/**
 * Versioned cryptographic constants (LLD §3.1, §3.2).
 *
 * These values MUST stay identical to the backend. Changing any of them is a
 * breaking change: cards created under the old values become undecryptable and
 * the SRP handshake stops interoperating. The interop test in
 * `src/crypto/srp.interop.test.ts` is what protects this file from a silent
 * dependency upgrade drifting either side.
 */

/** SRP-6a group, RFC 5054 2048-bit. Must match `SRP6CryptoParams.getInstance(2048, "SHA-256")`. */
export const SRP_GROUP_BITS = 2048;

/** SRP-6a hash. Must match the `"SHA-256"` passed to `SRP6CryptoParams` on the backend. */
export const SRP_HASH = "SHA-256" as const;

/** Per-record salt length in bytes. Hex-encoded on the wire, so 32 chars — within the backend's 64-char cap. */
export const SRP_SALT_BYTES = 16;

/**
 * Passkey -> AES key derivation.
 *
 * LLD §3.1 pins Argon2id (m=19MiB, t=2, p=1) with PBKDF2-SHA256 >=600k as the
 * sanctioned fallback (§3). We use the fallback: it is what the backend's own
 * `CardFlowIntegrationTests.encryptInBrowser`/`decryptInBrowser` models the
 * browser as doing, and it runs on native WebCrypto with no WASM dependency.
 * Moving to Argon2id requires changing the backend test in lockstep.
 */
export const PBKDF2_ITERATIONS = 600_000;
export const PBKDF2_HASH = "SHA-256" as const;

/**
 * Salt-space tag for the card-identifier derivation (`cardIdentifier.ts`).
 *
 * Two jobs. It separates that derivation from the AES one, which is salted with
 * the random per-record `srp_salt`, so the two can never collide. And it version
 * -stamps the normalization rules: if `normalizeCardName` ever has to change,
 * bumping this tag is what lets old and new identifiers coexist instead of every
 * stored card silently becoming unreachable.
 *
 * Do not change either the tag or the normalization without the other.
 */
export const ID_DERIVATION_VERSION = "ccshare-id-v1";

/** AES-256-GCM. IV is 12 bytes and never reused: a fresh one is drawn per encryption. */
export const AES_KEY_BITS = 256;
export const AES_GCM_IV_BYTES = 12;
export const AES_GCM_TAG_BITS = 128;

/**
 * Backend caps `encrypted_cc_blob` at 512 decoded bytes (`CardCreationService`).
 * Subtract the IV and the GCM tag to get the plaintext budget.
 */
export const MAX_ENCRYPTED_BLOB_BYTES = 512;
export const MAX_PLAINTEXT_BYTES =
  MAX_ENCRYPTED_BLOB_BYTES - AES_GCM_IV_BYTES - AES_GCM_TAG_BITS / 8;

/**
 * The card's name. No longer a backend concern — the `card_label` column was
 * dropped in V3 and the name now travels inside `encrypted_cc_blob` — so this
 * cap exists to keep the encrypted payload inside `MAX_PLAINTEXT_BYTES` and to
 * keep the name short enough to retype from memory.
 */
export const MAX_CARD_LABEL_LENGTH = 100;

/**
 * The server's 2-minute challenge TTL and its 5-attempt/15-minute lockout used
 * to be mirrored here so the unlock UI could count down and explain a lockout.
 * Neither is surfaced any more:
 *
 *  - The passkey is collected before the challenge is requested, so the two
 *    round trips complete in one go and the TTL cannot lapse mid-flow.
 *  - A wrong passkey now derives the identifier of a card that does not exist,
 *    so it never reaches the real card's counter. The lockout no longer bounds
 *    online guessing and there is nothing honest to tell the user about it.
 */

/** How long decrypted card data is allowed to sit in the DOM before it is wiped (LLD §8.2). */
export const PLAINTEXT_DWELL_SECONDS = 90;
