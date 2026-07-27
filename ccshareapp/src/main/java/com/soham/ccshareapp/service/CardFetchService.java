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

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class CardFetchService {

    private static final SRP6CryptoParams SRP_CRYPTO_PARAMS = SRP6CryptoParams.getInstance(2048, "SHA-256");
    private static final Duration CHALLENGE_TTL = Duration.ofMinutes(2);
    private static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);
    private static final int MAX_FAILED_ATTEMPTS = 5;

    private final CardRepository cardRepository;
    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, PendingChallenge> challenges = new ConcurrentHashMap<>();

    public CardFetchService(CardRepository cardRepository) {
        this.cardRepository = cardRepository;
    }

    public FetchChallengeResponse initiate(FetchInitiateRequest request) {
        validateCardIdentifier(request.card_identifier());
        Card card = cardRepository.findById(request.card_identifier()).orElse(null);
        if (card != null && card.isLocked(Instant.now())) {
            throw forbidden();
        }

        SRP6ServerSession session = new SRP6ServerSession(SRP_CRYPTO_PARAMS, (int) CHALLENGE_TTL.toSeconds());
        String salt;
        BigInteger verifier;
        boolean cardExists = card != null;
        if (cardExists) {
            salt = card.getSrpSalt();
            verifier = parseHex(card.getSrpVerifier());
        } else {
            byte[] dummySalt = new byte[16];
            secureRandom.nextBytes(dummySalt);
            salt = HexFormat.of().formatHex(dummySalt);
            verifier = new BigInteger(SRP_CRYPTO_PARAMS.N.bitLength() - 1, secureRandom);
        }

        BigInteger serverPublicEphemeral = cardExists
                ? session.step1(request.card_identifier(), parseHex(salt), verifier)
                : session.mockStep1(request.card_identifier(), parseHex(salt), verifier);
        String challengeId = UUID.randomUUID().toString();
        challenges.put(challengeId, new PendingChallenge(request.card_identifier(), cardExists, session,
                Instant.now().plus(CHALLENGE_TTL)));
        return new FetchChallengeResponse(challengeId, salt, toHex(serverPublicEphemeral));
    }

    @Transactional
    public FetchCardResponse prove(FetchProofRequest request) {
        validateProofRequest(request);
        PendingChallenge challenge = challenges.remove(request.challenge_id());
        if (challenge == null || challenge.expiresAt().isBefore(Instant.now())) {
            throw forbidden();
        }

        Card card = challenge.cardExists() ? cardRepository.findById(challenge.cardIdentifier()).orElse(null) : null;
        try {
            BigInteger serverProof = challenge.session().step2(
                    parseHex(request.client_public_ephemeral()),
                    parseHex(request.client_proof()));
            if (card == null || card.isLocked(Instant.now())) {
                throw forbidden();
            }
            card.resetFailedAttempts();
            return new FetchCardResponse(Base64.getEncoder().encodeToString(card.getEncryptedCcBlob()), toHex(serverProof));
        } catch (SRP6Exception | IllegalArgumentException exception) {
            if (card != null) {
                card.recordFailedAttempt(Instant.now(), MAX_FAILED_ATTEMPTS, LOCKOUT_DURATION);
            }
            throw forbidden();
        }
    }

    private void validateCardIdentifier(String cardIdentifier) {
        try {
            UUID identifier = UUID.fromString(cardIdentifier);
            if (identifier.version() != 4 || identifier.variant() != 2) {
                throw badRequest();
            }
        } catch (IllegalArgumentException exception) {
            throw badRequest();
        }
    }

    private void validateProofRequest(FetchProofRequest request) {
        try {
            UUID.fromString(request.challenge_id());
            if (!request.client_public_ephemeral().matches("^[0-9a-fA-F]{1,512}$")
                    || !request.client_proof().matches("^[0-9a-fA-F]{1,512}$")) {
                throw badRequest();
            }
        } catch (IllegalArgumentException exception) {
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
