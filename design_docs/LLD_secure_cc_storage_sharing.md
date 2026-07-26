# Low Level Design: Anonymous Secure Credit Card Storage & Sharing

**Version:** 1.0
**Status:** Design finalized, pending implementation
**Scope:** POC using Google Sheets as RDBMS substitute; production RDBMS swap is a drop-in replacement behind the same data-access interface.

---

## 1. Design Goals & Non-Goals

### 1.1 Goals
- Store credit card details without user signup/authentication accounts.
- Backend and its storage layer must **never** possess, even transiently, the plaintext card data or the passkey.
- Backend must **never** release encrypted card data to a requestor who has not proven possession of the correct passkey.
- Support secure, one-time, ephemeral sharing of a stored card with a third party (the "receiver") without either party needing an account.
- Resist offline brute-force attacks against stolen/leaked ciphertext.

### 1.2 Non-Goals
- Full PCI-DSS certification (flagged as a compliance question, addressed separately).
- Protection against a fully compromised end-user device (malware, physical access, OS-level keyloggers) — out of scope; assume the browser sandbox is intact.
- Protection against a malicious backend operator during the **Share** flow's public-key exchange (see §7.3, residual risk).

---

## 2. High-Level Component Map

| Component | Responsibility | Trust Level |
|---|---|---|
| **Frontend (SPA)** | Encryption/decryption, passkey handling, SRP client-side math, key generation | Holds all secrets transiently; must be isolated from Backend hosting (§8) |
| **Backend API** | Verifier storage/validation, ciphertext storage orchestration, one-time link/key lifecycle, rate limiting | Never sees plaintext or passkey |
| **RDBMS** (POC: Google Sheets) | Persists `{CardIdentifier, EncryptedCC, Verifier}` | Blind ciphertext store |
| **Ephemeral Storage** | Short-lived public keys, encrypted share payloads, auth-link state | Auto-expiring, delete-on-read |

**Hard architectural rule:** Frontend static assets MUST be served from a separate origin/host from the Backend API (see §8.1). This is a security boundary, not a deployment convenience.

---

## 3. Cryptographic Primitives

| Purpose | Primitive | Notes |
|---|---|---|
| Card data encryption at rest | AES-256-GCM | IV/nonce **must** be unique per encryption under a given key — never reused |
| Passkey → symmetric key derivation | Argon2id (fallback: PBKDF2-SHA256, ≥600k iterations) | Deliberately slow, to raise cost of any residual offline guessing |
| Passkey possession proof | SRP-6a (RFC 5054-style) | Zero-knowledge password proof; passkey never transmitted, verifier is one-way |
| Share-flow payload re-encryption | Ephemeral ECDH (X25519) + AES-256-GCM | Fresh keypair per share; private key never leaves receiver's browser memory |
| Verifier storage | `v = g^H(passkey) mod N` (SRP verifier) | `N` is a 2048-bit+ safe prime; stored alongside ciphertext, never the reverse |

**Prohibited:** storing `hash(passkey)` alone, using passkey directly as AES key without KDF, reusing IVs, custom/home-grown crypto formulas.

---

## 4. Data Model

### 4.1 `cards` table (RDBMS — MySQL)

**Design notes:**
- Records are immutable once created — no `updated_at`; nothing here is ever edited, only read or (implicitly) locked out.
- No secondary indexes beyond the primary key. There is no account/listing concept in this system, so no query pattern requires scanning or filtering `cards` by anything other than `card_identifier`. This is intentional — fewer indexes means less metadata leakage about usage patterns.
- `card_identifier` is always server-generated (§6.5) — never trust a client-supplied value as the primary key.

| Field | MySQL Type | Constraints | Notes |
|---|---|---|---|
| `card_identifier` | `CHAR(36)` | `PRIMARY KEY` | UUIDv4 (or 128-bit random token, hex/base32-encoded to fit). **Must not be sequential or guessable.** |
| `encrypted_cc_blob` | `VARBINARY(512)` | `NOT NULL` | IV \|\| ciphertext \|\| AEAD tag, bundled as raw bytes (not base64 — that's a POC/Sheets-only encoding; MySQL stores binary natively). Size generous for AES-256-GCM overhead on card-sized plaintext. |
| `srp_verifier` | `VARCHAR(512)` | `NOT NULL` | Hex string; sized for a 2048-bit+ SRP group. |
| `srp_salt` | `VARCHAR(64)` | `NOT NULL` | Hex, fixed-length per KDF config. |
| `created_at` | `TIMESTAMP` | `NOT NULL DEFAULT CURRENT_TIMESTAMP` | |
| `failed_attempt_count` | `SMALLINT UNSIGNED` | `NOT NULL DEFAULT 0` | Shared counter across `/fetch` and `/authLink` (§6.4). |
| `locked_until` | `TIMESTAMP` | `NULL DEFAULT NULL` | Lockout expiry, if triggered. `NULL` = not locked. |

**DDL:**
```sql
CREATE TABLE cards (
    card_identifier      CHAR(36)            NOT NULL,
    encrypted_cc_blob    VARBINARY(512)      NOT NULL,
    srp_verifier         VARCHAR(512)        NOT NULL,
    srp_salt             VARCHAR(64)         NOT NULL,
    created_at           TIMESTAMP           NOT NULL DEFAULT CURRENT_TIMESTAMP,
    failed_attempt_count SMALLINT UNSIGNED   NOT NULL DEFAULT 0,
    locked_until          TIMESTAMP           NULL DEFAULT NULL,
    PRIMARY KEY (card_identifier)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
```

> `utf8mb4_bin` collation chosen over the usual `utf8mb4_unicode_ci` since `card_identifier` and the hex/binary fields are compared for exact byte equality, not linguistic sorting — avoids case-insensitive collation quietly treating two distinct identifiers as equal.

**Deferred:** an append-only audit/event table for structured logging of failed attempts, lockouts, and per-`card_identifier` request volume (§6.7) is planned but out of scope for this schema pass — noted as a follow-up item.

### 4.2 `ephemeral_store` (Ephemeral Storage — separate from RDBMS)

| Key pattern | Value | TTL |
|---|---|---|
| `pubkey:{share_session_id}` | Receiver's public key (X25519) | 5 minutes, delete-on-consume |
| `payload:{share_session_id}` | Encrypted card payload for receiver | Delete-on-read (atomic) |
| `challenge:{card_identifier}:{attempt_id}` | SRP server ephemeral value `b`, `B` | 2 minutes, single-use |

---

## 5. API Contracts

### 5.1 `POST /create`
**Request:**
```json
{
  "card_identifier": "string (client-generated, high-entropy)",
  "encrypted_cc_blob": "base64 string (IV+ciphertext+tag)",
  "srp_verifier": "hex string",
  "srp_salt": "hex string"
}
```
**Response:** `200 OK` — no body needed beyond ack.

**Server behavior:**
- Validate `card_identifier` uniqueness and entropy (reject low-entropy/predictable identifiers if self-issued — recommend server-generated identifiers instead, returned in response, to remove client trust dependency).
- Persist all fields verbatim. Server performs **no decryption, no derivation** — it is a blind store at this step.
- Sanitize any string field before writing to Google Sheets (CSV/formula-injection guard — prefix-escape leading `=`, `+`, `-`, `@`).

---

### 5.2 `POST /fetch` — Step 1: Initiate

**Request:**
```json
{ "card_identifier": "string" }
```
**Response:**
```json
{
  "challenge_id": "string",
  "srp_salt": "hex",
  "server_public_ephemeral": "hex (B)"
}
```
**Server behavior:**
- Check `locked_until` — if in lockout window, return generic `403` (same shape as invalid-identifier response, see §6.5).
- Look up `srp_verifier` + `srp_salt` for `card_identifier`. If not found, still generate a plausible-looking dummy challenge (constant-time behavior — see §6.5) rather than short-circuiting.
- Generate SRP server ephemeral (`b`, `B`); store `b` against `challenge_id` in Ephemeral Storage with 2-minute TTL, single-use.
- **No card data touched yet.**

### 5.3 `POST /fetch` — Step 2: Prove & Retrieve

**Request:**
```json
{
  "challenge_id": "string",
  "client_public_ephemeral": "hex (A)",
  "client_proof": "hex (M1)"
}
```
**Response (success):**
```json
{ "encrypted_cc_blob": "base64 string" }
```
**Response (failure):** `403 Forbidden`, generic body, no distinguishing detail.

**Server behavior:**
1. Retrieve `b` via `challenge_id`; delete it immediately (single-use, prevents replay).
2. Compute session key `S` and expected proof using stored `verifier`, `A`, `b`, `B`.
3. Compare against `M1`. Constant-time comparison.
4. **On mismatch:** increment `failed_attempt_count`; if threshold exceeded, set `locked_until`; return generic `403`. Do not touch `encrypted_cc_blob`.
5. **On match:** reset `failed_attempt_count` to 0; return `encrypted_cc_blob`. Optionally return server proof `M2` so client can mutually authenticate the server (defends against a rogue backend impersonation — cheap to add, worth including).

**Client behavior (post-success):** derive AES key from passkey via Argon2id + `srp_salt`; decrypt blob locally; render; clear plaintext from memory/DOM on navigation away or after a timeout.

---

### 5.4 `POST /share/getCode`
**Request:**
```json
{ "receiver_public_key": "base64 (X25519 pubkey)" }
```
**Response:**
```json
{ "auth_link": "string (opaque, high-entropy)", "expires_at": "timestamp (+5 min)" }
```
**Server behavior:** store `receiver_public_key` in Ephemeral Storage keyed by `share_session_id` embedded in `auth_link`; 5-minute TTL.

---

### 5.5 `POST /share/authLink` — Step 1: Initiate (mirrors §5.2)
**Request:**
```json
{ "auth_link": "string", "card_identifier": "string" }
```
**Response:** same shape as §5.2 step 1 (`challenge_id`, `srp_salt`, `B`).

**Server behavior:** identical SRP challenge issuance as `/fetch`. Validates `auth_link` is unexpired but does **not yet** consume the receiver's public key.

### 5.6 `POST /share/authLink` — Step 2: Prove & Share
**Request:**
```json
{
  "challenge_id": "string",
  "client_public_ephemeral": "hex (A)",
  "client_proof": "hex (M1)",
  "encrypted_payload": "base64 (card data re-encrypted with receiver's pubkey, computed client-side)"
}
```
**Server behavior:**
1. Same SRP verification as §5.3, steps 1–4 (shared failure counter, see §6.4).
2. **Only on success:**
   - Fetch **and delete** receiver's public key from Ephemeral Storage (one-time use now correctly gated behind proof).
   - Persist `encrypted_payload` in Ephemeral Storage, keyed by `share_session_id`, delete-on-read.
   - Return `SUCCESS` to sender.
3. **On failure:** generic error, receiver's public key untouched, sender's `encrypted_payload` discarded, failure counted.

> Note: card decryption + re-encryption for the receiver happens **client-side, in the sender's browser**, after the proof succeeds and the backend hands back... nothing — the backend does not return `encrypted_cc_blob` in this flow at all. Instead, the sender's browser must already hold the decrypted card locally (e.g., from a prior successful `/fetch` in the same session) or the flow should be restructured so `/authLink` step 2's success response *does* return `encrypted_cc_blob` (symmetric to `/fetch`) so the sender's browser can decrypt-then-re-encrypt-for-receiver in one client-side operation. **Design decision needed** — recommend the latter for consistency; documented as open item in §10.

### 5.7 `POST /share/getApprovedDetails` (receiver polling)
**Request:**
```json
{ "share_session_id": "string (from auth_link session)" }
```
**Response:**
```json
{ "status": "pending" }
```
or
```json
{ "status": "ready", "encrypted_payload": "base64" }
```
**Server behavior:** atomic fetch-and-delete against Ephemeral Storage (see §6.6 — must be a single transactional operation, not fetch-then-delete as two steps, to avoid the double-read race).

**Client (receiver) behavior:** decrypt with private key (held only in memory), display, then explicitly destroy the private key variable.

---

## 6. Security Controls (Cross-Cutting)

### 6.1 Rate Limiting
- Per-IP rate limit on all endpoints (existing requirement, assumed infrastructure-level).
- **Per-`card_identifier` failed-attempt counter**, shared across `/fetch` and `/share/authLink` (§6.4) — this is the control that actually stops offline/online brute force of the passkey, independent of per-IP limits (which a distributed attacker can evade).

### 6.2 Lockout Policy
- Suggested: 5 failed proof attempts → 15-minute lockout on that `card_identifier`. Exponential backoff on repeated lockout cycles.
- Lockout state (`locked_until`) lives on the `cards` record itself (§4.1), not in a separate cache, to survive restarts of any rate-limiting middleware.

### 6.3 Constant-Time / Indistinguishable Responses
- `card_identifier` not found vs. `card_identifier` found but proof fails → **identical response shape, status code, and approximate timing.** Implement by always generating a real or dummy SRP challenge, never short-circuiting on lookup miss.

### 6.4 Shared Failure Budget
- `/fetch` and `/share/authLink` both decrement the same `failed_attempt_count` on a given `card_identifier`, preventing an attacker from splitting guess attempts across endpoints to double their effective attempt budget.

### 6.5 CardIdentifier Entropy
- Server-generated, ≥128-bit random token, returned to client at `/create` time. Client should not be trusted to self-generate this value (removes a class of weak-identifier risk from client bugs).

### 6.6 Atomicity in Ephemeral Storage
- `getApprovedDetails` fetch-and-delete, and public-key fetch-and-delete in `/share/authLink`, must be single atomic operations (conditional delete / transaction), not separate read-then-delete calls — closes the concurrent-poll race (§ threat model, TOCTOU).

### 6.7 Logging Hygiene
- Never log: passkeys, SRP proofs (`M1`/`M2`/session key `S`), `encrypted_cc_blob` contents, decrypted plaintext.
- Do log: failed-attempt counts, lockout triggers, request volumes per `card_identifier` — these are the actual attack-detection signals.

---

## 7. Threat Model Summary (Residual Risks After This Design)

| Threat | Mitigated? | Notes |
|---|---|---|
| Offline brute-force of stolen ciphertext | ✅ Yes | Ciphertext never released pre-proof; SRP makes the passkey never transmitted or reversible from verifier |
| Passkey enumeration via repeated online guesses | ✅ Yes | Shared failure counter + lockout across both endpoints |
| CardIdentifier enumeration/guessing | ✅ Mitigated | High-entropy, server-issued identifiers |
| Wrong-guess burning receiver's one-time public key | ✅ Fixed | Public key only consumed post-proof in `/share/authLink` |
| Concurrent double-read of share payload | ✅ Mitigated | Atomic fetch-and-delete required (§6.6) |
| XSS on frontend stealing passkey/plaintext at point of use | ⚠️ Partially — needs CSP, SRI, Worker isolation, minimal DOM dwell time | Frontend remains the true trust boundary; see §9 |
| Malicious backend substituting its own public key in Share flow (MITM) | ⚠️ Residual, not fully closed | Backend brokers the key exchange; consider out-of-band fingerprint verification between sender/receiver for high-assurance use cases |
| Compromised backend rewriting frontend code | ✅ Closed | Enforced via separate hosting origin (§8.1) |
| CSV/formula injection into Google Sheets (POC only) | ✅ Mitigated | Input sanitization/prefix-escaping on write |
| Weak passkey chosen by user | ⚠️ Partially | Argon2id raises cost per guess; UX should enforce minimum entropy at creation |

---

## 8. Deployment / Hosting Requirements

### 8.1 Origin Separation (Mandatory)
- Frontend SPA: static hosting (CDN / object storage), separate domain/subdomain from API.
- Backend API: separate service, JSON-only, no file-serving capability.
- Rationale: prevents backend compromise from escalating into frontend code tampering (§ prior discussion).

### 8.2 Frontend Hardening
- Strict CSP: no `unsafe-inline`, no `unsafe-eval`, explicit `script-src` allowlist.
- Subresource Integrity (SRI) on all third-party/CDN scripts (crypto libraries especially).
- Crypto operations (SRP math, AES encrypt/decrypt) isolated in a Web Worker where feasible, to narrow XSS blast radius.
- `autocomplete="off"` on passkey input; no persistence to localStorage/sessionStorage at any point.
- Explicit plaintext-clearing of card data and passkey variables after use/navigation.

### 8.3 Storage Layer (POC → Production)
- POC: Google Sheets as `cards` table backing store.
- Production: **MySQL**, per the schema in §4.1. Same `card_identifier` / `encrypted_cc_blob` / `srp_verifier` / `srp_salt` / `created_at` / `failed_attempt_count` / `locked_until` field set — no application-logic changes required if the data-access layer is abstracted correctly. Note the encoding difference: Sheets forces base64-text for the blob; MySQL stores it as native `VARBINARY`, so the data-access layer's (de)serialization step needs to branch on backend, not just the SQL dialect.

---

## 9. Open Items for Follow-Up Discussion

1. **§5.6 flow completion:** decide whether `/share/authLink` step 2 success response returns `encrypted_cc_blob` to the sender (for client-side decrypt-then-re-encrypt), or whether the sender is required to have already `/fetch`'d the card in-session beforehand. Needs to be pinned down before implementation.
2. **Mutual SRP authentication (`M2`):** recommend including server proof back to client, so a rogue/MITM backend can't trivially spoof a "success" response.
3. **Out-of-band public key verification** for the Share flow, to fully close the backend-MITM residual risk in §7 — e.g., a short verification code shown to both sender and receiver out-of-band (spoken, SMS) to confirm they're using the same session.
4. **PCI-DSS scope determination** — even with this architecture, legal/compliance review recommended given plaintext exists transiently in browser memory.
5. **Passkey strength enforcement** — minimum entropy requirements at `/create` time, communicated to the user.

---

## 10. Sequence Diagram Reference

This LLD implements the flows shown in the finalized architecture diagram (`cc_details.png`), specifically the challenge-response insertion into both **READ EXISTING CC DETAILS** and **SHARE EXISTING CC DETAILS** sections, replacing the prior client-side-only auth-tag comparison.
