package com.soham.ccshareapp.card;

public record FetchChallengeResponse(
        String challenge_id,
        String srp_salt,
        String server_public_ephemeral) {
}
