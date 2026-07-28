# DB Design: Anonymous Secure Credit Card Storage & Sharing

**Version:** 1.0
**Database:** MySQL (InnoDB)
**Related doc:** `LLD_secure_cc_storage_sharing.md` (architecture, API contracts, crypto primitives, security controls)

**Scope of this document:** table-level schema design only — columns, types, constraints, indexes, and rationale. Security enforcement details (rate limiting implementation, lockout logic, sanitization) are covered in the LLD, §6.

---

## 1. Tables Overview

| Table | Purpose | Mutability |
|---|---|---|
| `cards` | Blind ciphertext store — one row per stored card | Immutable after insert (lockout fields excepted) |
| `card_auth_events` | Append-only audit log of auth attempts, lockouts, and share events | Insert-only, never updated or deleted by application logic |

The **ephemeral storage** (public keys, share payloads, SRP challenges) is intentionally **not** part of this relational schema — it's a separate short-TTL KV store (e.g. Redis), documented in LLD §4.2. It has no place in MySQL because every value in it is designed to be transient and auto-expiring, which a relational table would only approximate awkwardly.

---

## 2. `cards`

Primary record store. Backend never decrypts or derives anything from this table — it's a blind store keyed by a high-entropy, server-generated identifier.

| Field | MySQL Type | Constraints | Notes |
|---|---|---|---|
| `card_identifier` | `CHAR(36)` | `PRIMARY KEY` | UUIDv4 (or 128-bit random token). Server-generated only (LLD §6.5) — never accept a client-supplied value as PK. Must not be sequential or guessable. |
| `encrypted_cc_blob` | `VARBINARY(512)` | `NOT NULL` | IV \|\| ciphertext \|\| AEAD tag, raw bytes. Sized generously for AES-256-GCM overhead on card-sized plaintext. |
| `srp_verifier` | `VARCHAR(512)` | `NOT NULL` | Hex string; sized for a 2048-bit+ SRP group. |
| `srp_salt` | `VARCHAR(64)` | `NOT NULL` | Hex, fixed length per KDF config. |
| `card_label` | `VARCHAR(100)` | `NOT NULL` | Plaintext, user-chosen nickname (e.g. "HDFC Platinum"). Lets the frontend show which card is being unlocked before the passkey is entered — there's no account/listing concept to browse cards any other way. Safe to store unencrypted: it's a name the user typed, never derived from card data, and no more revealing than the fact that the row exists (LLD §4.3). |
| `created_at` | `TIMESTAMP` | `NOT NULL DEFAULT CURRENT_TIMESTAMP` | |
| `failed_attempt_count` | `SMALLINT UNSIGNED` | `NOT NULL DEFAULT 0` | Shared counter across `/fetch` and `/share/authLink` (LLD §6.4). Reset to 0 on successful proof. |
| `locked_until` | `TIMESTAMP` | `NULL DEFAULT NULL` | Lockout expiry. `NULL` = not locked. Lives on the record itself so lockout state survives restarts of any rate-limiting middleware. |

**Indexes:** primary key only. No account/listing concept exists in this system, so no query pattern needs to scan or filter `cards` by anything other than `card_identifier`. Fewer indexes here is a deliberate choice — it avoids creating any secondary structure that could leak usage-pattern metadata.

**Immutability:** rows are never updated except `failed_attempt_count` and `locked_until` (auth-attempt bookkeeping), and never deleted under normal operation — this system has no expressed card-deletion/expiry flow today.

```sql
CREATE TABLE cards (
    card_identifier      CHAR(36)            NOT NULL,
    encrypted_cc_blob    VARBINARY(512)      NOT NULL,
    srp_verifier         VARCHAR(512)        NOT NULL,
    srp_salt             VARCHAR(64)         NOT NULL,
    card_label           VARCHAR(100)        NOT NULL,
    created_at           TIMESTAMP           NOT NULL DEFAULT CURRENT_TIMESTAMP,
    failed_attempt_count SMALLINT UNSIGNED   NOT NULL DEFAULT 0,
    locked_until          TIMESTAMP           NULL DEFAULT NULL,
    PRIMARY KEY (card_identifier)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
```

**Migration note (`V2__add_card_label.sql`):** adds `card_label` to an existing `cards` table via `ALTER TABLE ... ADD COLUMN ... NOT NULL DEFAULT ''`, then drops the default. This is a POC-stage convenience — there is no production data to backfill — and lets the column land as `NOT NULL` without a separate backfill step.

> `utf8mb4_bin` over `utf8mb4_unicode_ci`: identifiers and hex/binary fields need exact byte-equality comparisons, not linguistic sorting. A case-insensitive collation could quietly treat two distinct identifiers as equal.

---

## 3. `card_auth_events` (audit table)

Append-only log satisfying LLD §6.7 ("do log: failed-attempt counts, lockout triggers, request volumes per `card_identifier`"). Never read by the hot-path auth logic — `cards.failed_attempt_count` and `cards.locked_until` remain the source of truth for enforcement. This table exists purely for detection, forensics, and monitoring, and is written to *in addition to*, not instead of, those two columns.

| Field | MySQL Type | Constraints | Notes |
|---|---|---|---|
| `event_id` | `BIGINT UNSIGNED` | `PRIMARY KEY AUTO_INCREMENT` | Monotonic, cheap, sufficient — no need for UUID here since this is an internal-only log, never exposed via API. |
| `card_identifier` | `CHAR(36)` | `NOT NULL` | Deliberately **no foreign key** to `cards.card_identifier`. Keeps this table writable/insertable even if it's later moved to a separate log store or physically different database; also means a lookup-miss event (LLD §6.3, an identifier that doesn't exist) can still be logged. |
| `event_type` | `ENUM('fetch_fail','fetch_success','authlink_fail','authlink_success','lockout_triggered')` | `NOT NULL` | Covers both `/fetch` and `/share/authLink` per the shared failure budget (LLD §6.4). Extend the enum as new flows are added rather than using a free-text column — keeps the event vocabulary closed and query-friendly. |
| `occurred_at` | `TIMESTAMP(3)` | `NOT NULL DEFAULT CURRENT_TIMESTAMP(3)` | Millisecond precision — useful for reconstructing rapid-fire brute-force attempt sequences. |
| `client_ip_hash` | `CHAR(64)` | `NULL` | SHA-256 hex digest of the client IP (+ salt), **not the raw IP**. Enables correlating repeated attempts from the same source without storing directly identifying network data at rest. Nullable in case IP isn't available in some deployment context (e.g. behind a proxy that strips it). |

**Explicitly never logged in this table** (per LLD §6.7): passkeys, SRP proofs (`M1`/`M2`/session key `S`), `encrypted_cc_blob` contents, decrypted plaintext.

**Indexes:**
- `PRIMARY KEY (event_id)` — insert-friendly monotonic key, avoids the page-fragmentation cost of a random PK on a high-write table.
- `INDEX idx_card_identifier_occurred_at (card_identifier, occurred_at)` — the actual query this table exists to serve: "show me the recent event history for this card_identifier" (attack investigation, lockout review).
- `INDEX idx_event_type_occurred_at (event_type, occurred_at)` — supports operational queries like "how many lockouts triggered system-wide in the last hour" without a full table scan.

```sql
CREATE TABLE card_auth_events (
    event_id        BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
    card_identifier CHAR(36)         NOT NULL,
    event_type      ENUM('fetch_fail','fetch_success','authlink_fail','authlink_success','lockout_triggered') NOT NULL,
    occurred_at      TIMESTAMP(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    client_ip_hash   CHAR(64)         NULL,
    PRIMARY KEY (event_id),
    INDEX idx_card_identifier_occurred_at (card_identifier, occurred_at),
    INDEX idx_event_type_occurred_at (event_type, occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
```

### 3.1 Open items on this table (for follow-up)

1. **Retention policy** — this table grows unbounded on a high-traffic system. Needs a purge/archive job (e.g. drop events older than N days) or a partition-by-date strategy (`PARTITION BY RANGE` on `occurred_at`) if it's expected to scale. Not addressed yet.
2. **Write path** — should this be a synchronous insert in the same transaction as the `cards.failed_attempt_count` update, or fire-and-forget/async (e.g. via a queue) so audit logging can never add latency or become a failure point on the auth hot path? Recommend async, but needs confirming against operational requirements.
3. **Where it lives** — same MySQL instance as `cards`, a separate schema, or shipped straight to a log aggregation system (e.g. ELK/CloudWatch) instead of a table at all? This document assumes same-instance MySQL for now since that's the simplest starting point, but it's a decision worth revisiting once traffic/retention requirements are clearer.

---

## 4. Entity Relationship Summary

```
cards (1) ── (0..N) card_auth_events
```

Logical relationship only — **no enforced FK**, by design (see §3, `card_identifier` rationale). This keeps the audit table decoupled enough to be relocated (different DB, different retention tier, external log system) without a schema migration on `cards`.
