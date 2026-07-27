package com.soham.ccshareapp.controller;

import com.soham.ccshareapp.dto.CreateCardRequest;
import com.soham.ccshareapp.dto.FetchInitiateRequest;
import com.soham.ccshareapp.dto.FetchProofRequest;
import com.soham.ccshareapp.service.CardCreationService;
import com.soham.ccshareapp.service.CardFetchService;

import tools.jackson.databind.JsonNode;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class CardController {

    private final CardCreationService cardCreationService;
    private final CardFetchService cardFetchService;

    public CardController(CardCreationService cardCreationService, CardFetchService cardFetchService) {
        this.cardCreationService = cardCreationService;
        this.cardFetchService = cardFetchService;
    }

    @PostMapping("/create")
    public ResponseEntity<Void> create(@Valid @RequestBody CreateCardRequest request) {
        cardCreationService.create(request);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/fetch")
    public Object fetch(@RequestBody JsonNode request) {
        if (request.hasNonNull("card_identifier") && request.size() == 1) {
            return cardFetchService.initiate(new FetchInitiateRequest(request.path("card_identifier").asString()));
        }
        if (request.hasNonNull("challenge_id") && request.hasNonNull("client_public_ephemeral")
                && request.hasNonNull("client_proof") && request.size() == 3) {
            return cardFetchService.prove(new FetchProofRequest(
                    request.path("challenge_id").asString(),
                    request.path("client_public_ephemeral").asString(),
                    request.path("client_proof").asString()));
        }
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid fetch request");
    }
}
