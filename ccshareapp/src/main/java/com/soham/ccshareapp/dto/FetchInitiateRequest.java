package com.soham.ccshareapp.card;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record FetchInitiateRequest(
        @NotBlank @Pattern(regexp = "^[0-9a-fA-F-]{36}$") String card_identifier) {
}
