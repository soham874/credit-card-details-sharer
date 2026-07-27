package com.soham.ccshareapp.card;

import java.util.Base64;
import java.util.UUID;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class CardCreationService {

    private static final int MAX_ENCRYPTED_BLOB_BYTES = 512;

    private final CardRepository cardRepository;

    public CardCreationService(CardRepository cardRepository) {
        this.cardRepository = cardRepository;
    }

    public void create(CreateCardRequest request) {
        validateIdentifier(request.card_identifier());
        byte[] encryptedBlob = decodeEncryptedBlob(request.encrypted_cc_blob());

        try {
            cardRepository.saveAndFlush(new Card(
                    request.card_identifier(),
                    encryptedBlob,
                    request.srp_verifier(),
                    request.srp_salt()));
        } catch (DataIntegrityViolationException exception) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Card identifier already exists");
        }
    }

    private void validateIdentifier(String cardIdentifier) {
        try {
            UUID identifier = UUID.fromString(cardIdentifier);
            if (identifier.version() != 4 || identifier.variant() != 2) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "card_identifier must be a UUIDv4");
            }
        } catch (IllegalArgumentException exception) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "card_identifier must be a UUIDv4");
        }
    }

    private byte[] decodeEncryptedBlob(String encryptedBlob) {
        try {
            byte[] decodedBlob = Base64.getDecoder().decode(encryptedBlob);
            if (decodedBlob.length == 0 || decodedBlob.length > MAX_ENCRYPTED_BLOB_BYTES) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "encrypted_cc_blob is invalid");
            }
            return decodedBlob;
        } catch (IllegalArgumentException exception) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "encrypted_cc_blob is invalid");
        }
    }
}
