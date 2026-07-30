package com.soham.ccshareapp.dto;

public record FetchChallengeResponse(
        String challenge_id,
        String srp_salt,
        String server_public_ephemeral) {
}
