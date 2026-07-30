package com.soham.ccshareapp.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record CreateCardRequest(
        @NotBlank @Pattern(regexp = "^[0-9a-fA-F-]{36}$") String card_identifier,
        @NotBlank @Size(max = 684) String encrypted_cc_blob,
        @NotBlank @Size(max = 512) @Pattern(regexp = "^[0-9a-fA-F]+$") String srp_verifier,
        @NotBlank @Size(max = 64) @Pattern(regexp = "^[0-9a-fA-F]+$") String srp_salt) {
}
