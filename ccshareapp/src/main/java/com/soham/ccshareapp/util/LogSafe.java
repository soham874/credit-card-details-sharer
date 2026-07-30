package com.soham.ccshareapp.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Card identifiers are derived in the browser from the card name, its last four
 * digits, and the passkey. That makes a leaked identifier an offline oracle for
 * guessing the passkey: derive a candidate, compare, repeat, with no server and
 * no rate limit in the way.
 *
 * <p>Logs therefore carry a truncated digest rather than the identifier itself —
 * still stable enough to correlate requests for the attack detection LLD §6.7
 * asks for, useless for grinding.
 */
public final class LogSafe {

    private static final int DIGEST_CHARS = 12;

    private LogSafe() {
    }

    /** Truncated SHA-256 of a card identifier, safe to write to logs. */
    public static String identifier(String cardIdentifier) {
        if (cardIdentifier == null || cardIdentifier.isEmpty()) {
            return "none";
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(cardIdentifier.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest).substring(0, DIGEST_CHARS);
        } catch (NoSuchAlgorithmException exception) {
            // SHA-256 is mandated by every JDK; unreachable in practice.
            return "unavailable";
        }
    }
}
