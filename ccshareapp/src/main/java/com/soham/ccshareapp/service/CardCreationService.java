package com.soham.ccshareapp.service;

import com.soham.ccshareapp.dto.CreateCardRequest;
import com.soham.ccshareapp.model.Card;
import com.soham.ccshareapp.repository.CardRepository;

import java.util.Base64;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class CardCreationService {

    private static final Logger logger = LoggerFactory.getLogger(CardCreationService.class);
    private static final int MAX_ENCRYPTED_BLOB_BYTES = 512;

    private final CardRepository cardRepository;

    public CardCreationService(CardRepository cardRepository) {
        this.cardRepository = cardRepository;
    }

    public void create(CreateCardRequest request) {
        logger.debug("Starting card creation for identifier: {}", request.card_identifier());
        validateIdentifier(request.card_identifier());
        logger.debug("Card identifier validation passed: {}", request.card_identifier());

        byte[] encryptedBlob = decodeEncryptedBlob(request.encrypted_cc_blob());
        logger.debug("Encrypted blob decoded successfully. Size: {} bytes", encryptedBlob.length);

        try {
            Card card = new Card(
                    request.card_identifier(),
                    encryptedBlob,
                    request.srp_verifier(),
                    request.srp_salt(),
                    request.card_label());
            cardRepository.saveAndFlush(card);
            logger.info("Card stored successfully. ID: {}, Label: {}", request.card_identifier(), request.card_label());
        } catch (DataIntegrityViolationException exception) {
            logger.warn("Card creation failed: duplicate card_identifier: {}", request.card_identifier());
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Card identifier already exists");
        }
    }

    private void validateIdentifier(String cardIdentifier) {
        try {
            UUID identifier = UUID.fromString(cardIdentifier);
            if (identifier.version() != 4 || identifier.variant() != 2) {
                logger.warn("Invalid card identifier format: {}", cardIdentifier);
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "card_identifier must be a UUIDv4");
            }
            logger.debug("Card identifier is valid UUIDv4: {}", cardIdentifier);
        } catch (IllegalArgumentException exception) {
            logger.warn("Card identifier parsing failed: {}", cardIdentifier);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "card_identifier must be a UUIDv4");
        }
    }

    private byte[] decodeEncryptedBlob(String encryptedBlob) {
        try {
            byte[] decodedBlob = Base64.getDecoder().decode(encryptedBlob);
            if (decodedBlob.length == 0 || decodedBlob.length > MAX_ENCRYPTED_BLOB_BYTES) {
                logger.warn("Encrypted blob size validation failed: {} bytes (max: {})", decodedBlob.length, MAX_ENCRYPTED_BLOB_BYTES);
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "encrypted_cc_blob is invalid");
            }
            logger.debug("Encrypted blob decoded and validated. Size: {} bytes", decodedBlob.length);
            return decodedBlob;
        } catch (IllegalArgumentException exception) {
            logger.warn("Encrypted blob Base64 decoding failed");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "encrypted_cc_blob is invalid");
        }
    }
}
