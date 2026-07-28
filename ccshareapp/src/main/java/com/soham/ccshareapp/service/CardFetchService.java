package com.soham.ccshareapp.service;

import com.soham.ccshareapp.dto.FetchCardResponse;
import com.soham.ccshareapp.dto.FetchChallengeResponse;
import com.soham.ccshareapp.dto.FetchInitiateRequest;
import com.soham.ccshareapp.dto.FetchProofRequest;
import com.soham.ccshareapp.model.Card;
import com.soham.ccshareapp.repository.CardRepository;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import com.nimbusds.srp6.SRP6CryptoParams;
import com.nimbusds.srp6.SRP6Exception;
import com.nimbusds.srp6.SRP6ServerSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class CardFetchService {

    private static final Logger logger = LoggerFactory.getLogger(CardFetchService.class);
    private static final SRP6CryptoParams SRP_CRYPTO_PARAMS = SRP6CryptoParams.getInstance(2048, "SHA-256");
    private static final Duration CHALLENGE_TTL = Duration.ofMinutes(2);
    private static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final String DUMMY_CARD_LABEL = "Card";

    private final CardRepository cardRepository;
    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, PendingChallenge> challenges = new ConcurrentHashMap<>();

    public CardFetchService(CardRepository cardRepository) {
        this.cardRepository = cardRepository;
        logger.debug("CardFetchService initialized with SRP parameters: 2048-bit group, SHA-256");
    }

    public FetchChallengeResponse initiate(FetchInitiateRequest request) {
        logger.debug("Fetch initiate: validating card_identifier: {}", request.card_identifier());
        validateCardIdentifier(request.card_identifier());

        Card card = cardRepository.findById(request.card_identifier()).orElse(null);
        if (card != null && card.isLocked(Instant.now())) {
            logger.warn("Fetch initiate blocked: card locked due to failed attempts. card_id={}", request.card_identifier());
            throw forbidden();
        }

        boolean cardExists = card != null;
        if (cardExists) {
            logger.info("Fetch initiate: card found. card_id={}, label={}", request.card_identifier(), card.getCardLabel());
        } else {
            logger.debug("Fetch initiate: card not found (non-existent identifier). Generating dummy challenge for constant-time behavior.");
        }

        SRP6ServerSession session = new SRP6ServerSession(SRP_CRYPTO_PARAMS, (int) CHALLENGE_TTL.toSeconds());
        String salt;
        BigInteger verifier;
        String cardLabel;

        if (cardExists) {
            salt = card.getSrpSalt();
            verifier = parseHex(card.getSrpVerifier());
            cardLabel = card.getCardLabel();
            logger.debug("Fetch initiate: using real card credentials for SRP step 1. card_id={}", request.card_identifier());
        } else {
            byte[] dummySalt = new byte[16];
            secureRandom.nextBytes(dummySalt);
            salt = HexFormat.of().formatHex(dummySalt);
            verifier = new BigInteger(SRP_CRYPTO_PARAMS.N.bitLength() - 1, secureRandom);
            cardLabel = DUMMY_CARD_LABEL;
            logger.debug("Fetch initiate: using dummy credentials for constant-time behavior");
        }

        BigInteger serverPublicEphemeral = cardExists
                ? session.step1(request.card_identifier(), parseHex(salt), verifier)
                : session.mockStep1(request.card_identifier(), parseHex(salt), verifier);

        String challengeId = UUID.randomUUID().toString();
        challenges.put(challengeId, new PendingChallenge(request.card_identifier(), cardExists, session,
                Instant.now().plus(CHALLENGE_TTL)));
        logger.info("SRP challenge issued. challenge_id={}, card_exists={}, ttl={}s", challengeId, cardExists, CHALLENGE_TTL.toSeconds());
        logger.debug("Challenge stored in ephemeral map. Total active challenges: {}", challenges.size());

        return new FetchChallengeResponse(challengeId, salt, toHex(serverPublicEphemeral), cardLabel);
    }

    @Transactional(noRollbackFor = ResponseStatusException.class)
    public FetchCardResponse prove(FetchProofRequest request) {
        logger.debug("Fetch prove: validating proof request for challenge_id={}", request.challenge_id());
        validateProofRequest(request);

        PendingChallenge challenge = challenges.remove(request.challenge_id());
        if (challenge == null) {
            logger.warn("Fetch prove: challenge not found or already consumed. challenge_id={}", request.challenge_id());
            throw forbidden();
        }

        if (challenge.expiresAt().isBefore(Instant.now())) {
            logger.warn("Fetch prove: challenge expired. challenge_id={}", request.challenge_id());
            throw forbidden();
        }

        logger.debug("Fetch prove: challenge found and valid. card_id={}, challenge_id={}", challenge.cardIdentifier(), request.challenge_id());

        Card card = challenge.cardExists() ? cardRepository.findById(challenge.cardIdentifier()).orElse(null) : null;
        try {
            BigInteger serverProof = challenge.session().step2(
                    parseHex(request.client_public_ephemeral()),
                    parseHex(request.client_proof()));

            if (card == null || card.isLocked(Instant.now())) {
                logger.warn("Fetch prove failed: card not found or locked. card_id={}", challenge.cardIdentifier());
                throw forbidden();
            }

            logger.debug("SRP proof verification passed for card: {}", challenge.cardIdentifier());
            card.resetFailedAttempts();
            cardRepository.saveAndFlush(card);
            logger.info("Fetch prove successful: card credentials verified and retrieved. card_id={}", challenge.cardIdentifier());
            logger.debug("Failed attempt counter reset to 0 for card: {}", challenge.cardIdentifier());

            return new FetchCardResponse(Base64.getEncoder().encodeToString(card.getEncryptedCcBlob()), toHex(serverProof));
        } catch (SRP6Exception | IllegalArgumentException exception) {
            logger.debug("SRP proof verification failed or invalid argument: {}", exception.getMessage());
            if (card != null) {
                int failedCount = card.getFailedAttemptCount() + 1;
                card.recordFailedAttempt(Instant.now(), MAX_FAILED_ATTEMPTS, LOCKOUT_DURATION);
                logger.warn("Fetch prove failed: invalid proof. card_id={}, failed_attempts={}/{}", challenge.cardIdentifier(), failedCount, MAX_FAILED_ATTEMPTS);

                if (card.isLocked(Instant.now())) {
                    logger.warn("Card locked due to excessive failed attempts. card_id={}, locked_until={}", challenge.cardIdentifier(), card.getLockedUntil());
                }
                cardRepository.saveAndFlush(card);
            }
            throw forbidden();
        }
    }

    private void validateCardIdentifier(String cardIdentifier) {
        try {
            UUID identifier = UUID.fromString(cardIdentifier);
            if (identifier.version() != 4 || identifier.variant() != 2) {
                logger.warn("Invalid card identifier format (not UUIDv4): {}", cardIdentifier);
                throw badRequest();
            }
            logger.debug("Card identifier validation passed: {}", cardIdentifier);
        } catch (IllegalArgumentException exception) {
            logger.warn("Card identifier parsing failed: {}", cardIdentifier);
            throw badRequest();
        }
    }

    private void validateProofRequest(FetchProofRequest request) {
        try {
            UUID.fromString(request.challenge_id());
            logger.debug("Challenge ID validation passed: {}", request.challenge_id());

            if (!request.client_public_ephemeral().matches("^[0-9a-fA-F]{1,512}$")) {
                logger.warn("Invalid client public ephemeral format for challenge: {}", request.challenge_id());
                throw badRequest();
            }
            if (!request.client_proof().matches("^[0-9a-fA-F]{1,512}$")) {
                logger.warn("Invalid client proof format for challenge: {}", request.challenge_id());
                throw badRequest();
            }
            logger.debug("Proof request validation passed for challenge: {}", request.challenge_id());
        } catch (IllegalArgumentException exception) {
            logger.warn("Proof request validation failed: {}", exception.getMessage());
            throw badRequest();
        }
    }

    private BigInteger parseHex(String value) {
        String normalizedValue = value.length() % 2 == 0 ? value : "0" + value;
        return new BigInteger(1, HexFormat.of().parseHex(normalizedValue));
    }

    private String toHex(BigInteger value) {
        String hexValue = value.toString(16);
        return hexValue.length() % 2 == 0 ? hexValue : "0" + hexValue;
    }

    private ResponseStatusException badRequest() {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid fetch request");
    }

    private ResponseStatusException forbidden() {
        return new ResponseStatusException(HttpStatus.FORBIDDEN);
    }

    private record PendingChallenge(
            String cardIdentifier,
            boolean cardExists,
            SRP6ServerSession session,
            Instant expiresAt) {
    }
}
