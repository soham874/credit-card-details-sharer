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

/** Backend caps `card_label` at 100 chars (`CreateCardRequest`, DB `VARCHAR(100)`). */
export const MAX_CARD_LABEL_LENGTH = 100;

/** Server-side challenge TTL (`CardFetchService.CHALLENGE_TTL`). Surfaced so the UI can warn before it lapses. */
export const CHALLENGE_TTL_SECONDS = 120;

/** Lockout policy mirrored from `CardFetchService`, for messaging only — the backend is the enforcer. */
export const MAX_FAILED_ATTEMPTS = 5;
export const LOCKOUT_MINUTES = 15;

/** How long decrypted card data is allowed to sit in the DOM before it is wiped (LLD §8.2). */
export const PLAINTEXT_DWELL_SECONDS = 90;
