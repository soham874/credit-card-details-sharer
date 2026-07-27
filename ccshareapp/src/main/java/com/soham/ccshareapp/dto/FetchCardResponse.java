package com.soham.ccshareapp.dto;

public record FetchCardResponse(
        String encrypted_cc_blob,
        String server_proof) {
}
