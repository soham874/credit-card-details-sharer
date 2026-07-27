package com.soham.ccshareapp.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record FetchProofRequest(
        @NotBlank @Pattern(regexp = "^[0-9a-fA-F-]{36}$") String challenge_id,
        @NotBlank @Size(max = 512) @Pattern(regexp = "^[0-9a-fA-F]+$") String client_public_ephemeral,
        @NotBlank @Size(max = 512) @Pattern(regexp = "^[0-9a-fA-F]+$") String client_proof) {
}
