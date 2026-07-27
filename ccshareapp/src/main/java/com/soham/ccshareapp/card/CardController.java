package com.soham.ccshareapp.card;

import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CardController {

    private final CardCreationService cardCreationService;

    public CardController(CardCreationService cardCreationService) {
        this.cardCreationService = cardCreationService;
    }

    @PostMapping("/create")
    public ResponseEntity<Void> create(@Valid @RequestBody CreateCardRequest request) {
        cardCreationService.create(request);
        return ResponseEntity.ok().build();
    }
}
