package com.soham.ccshareapp.card;

public record FetchCardResponse(
        String encrypted_cc_blob,
        String server_proof) {
}
