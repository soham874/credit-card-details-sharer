package com.soham.ccshareapp.controller;

import com.soham.ccshareapp.dto.CreateCardRequest;
import com.soham.ccshareapp.dto.FetchInitiateRequest;
import com.soham.ccshareapp.dto.FetchProofRequest;
import com.soham.ccshareapp.service.CardCreationService;
import com.soham.ccshareapp.service.CardFetchService;

import tools.jackson.databind.JsonNode;

import jakarta.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class CardController {

    private static final Logger logger = LoggerFactory.getLogger(CardController.class);

    private final CardCreationService cardCreationService;
    private final CardFetchService cardFetchService;

    public CardController(CardCreationService cardCreationService, CardFetchService cardFetchService) {
        this.cardCreationService = cardCreationService;
        this.cardFetchService = cardFetchService;
    }

    @PostMapping("/create")
    public ResponseEntity<Void> create(@Valid @RequestBody CreateCardRequest request) {
        logger.info("POST /create received for card: {}", request.card_identifier());
        logger.debug("Card label: {}", request.card_label());
        cardCreationService.create(request);
        logger.info("Card created successfully: {}", request.card_identifier());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/fetch")
    public Object fetch(@RequestBody JsonNode request) {
        logger.debug("POST /fetch received with payload size: {} bytes", request.toString().length());
        if (request.hasNonNull("card_identifier") && request.size() == 1) {
            String cardId = request.path("card_identifier").asString();
            logger.info("Fetch step 1 (initiate): card_identifier={}", cardId);
            logger.debug("Initiating SRP challenge for card: {}", cardId);
            return cardFetchService.initiate(new FetchInitiateRequest(cardId));
        }
        if (request.hasNonNull("challenge_id") && request.hasNonNull("client_public_ephemeral")
                && request.hasNonNull("client_proof") && request.size() == 3) {
            String challengeId = request.path("challenge_id").asString();
            logger.info("Fetch step 2 (prove): challenge_id={}", challengeId);
            logger.debug("Validating SRP proof for challenge: {}", challengeId);
            return cardFetchService.prove(new FetchProofRequest(
                    challengeId,
                    request.path("client_public_ephemeral").asString(),
                    request.path("client_proof").asString()));
        }
        logger.warn("Invalid fetch request received: {}", request.toString());
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid fetch request");
    }
}
