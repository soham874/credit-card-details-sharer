# CC Share — Frontend

Single-page app for the anonymous encrypted card store. All cryptography happens
in the browser: the backend receives ciphertext and a one-way SRP verifier, and
never receives the passkey or the plaintext card.

Implements the **Create** and **Read** flows from `design_docs/cc_details.png`
and `LLD_secure_cc_storage_sharing.md` §5.1–5.3. The **Share** flow is not
implemented — see [Scope](#scope).

## Prerequisites

- Node.js 20.19+ (developed on 25.8)
- The backend running on `http://localhost:8080` (see `design_docs/README.MD`)

## Getting started

```bash
npm install --prefix frontend
```

```bash
npm run dev --prefix frontend
```

Open `http://localhost:5173`. The dev server proxies `/api/*` to the backend, so
no backend reconfiguration is needed for local work.

## Commands

| Command | What it does |
|---|---|
| `npm run dev` | Dev server on :5173 with the backend proxy |
| `npm run build` | Typecheck and produce `dist/` (injects the strict CSP) |
| `npm run preview` | Serve the production build |
| `npm test` | Offline crypto tests; the live handshake skips with a warning |
| `npm run test:interop` | Cross-language SRP validation; **requires** a running backend |
| `npm run lint` | oxlint |

Point the tests or the dev proxy elsewhere with `BACKEND_URL`:

```bash
BACKEND_URL=http://localhost:8081 npm run test:interop --prefix frontend
```

## How a card moves through the system

**Storing** (`POST /create`)

1. A UUIDv4 identifier and a 16-byte salt are generated in the browser.
2. The passkey is stretched with PBKDF2-SHA256 (600k iterations, salted) into an
   AES-256 key.
3. Card details are serialised to JSON and encrypted with AES-256-GCM. The blob
   is `IV(12) || ciphertext || tag(16)`.
4. The SRP-6a verifier `v = g^H(s | H(passkey)) mod N` is computed locally.
5. Only `{identifier, blob, verifier, salt, label}` is sent. The passkey is not.

**Retrieving** (`POST /fetch`, two steps)

1. Step 1 sends the identifier and gets back `{challenge_id, srp_salt, B, card_label}`.
   The label is rendered *before* the passkey prompt so the user knows which card
   they are unlocking (LLD §4.3).
2. Step 2 computes `A` and the proof `M1` from the passkey and sends those. The
   passkey never leaves the browser.
3. On success the server returns the blob plus its own proof `M2`. **`M2` is
   verified before the blob is decrypted**, so a backend that faked a success
   response is rejected (LLD §5.3, §10.2).
4. The blob is decrypted locally and wiped from the DOM after 90 seconds.

## Security properties

Implemented against LLD §8.2:

- **Crypto in a Web Worker.** All passkey handling, SRP math, key derivation, and
  encryption run in `src/crypto/crypto.worker.ts`. The passkey and derived key are
  never in the same heap as the DOM, which narrows the XSS blast radius. It also
  keeps the UI responsive through 600k PBKDF2 iterations and 2048-bit modexp.
- **No persistence.** Nothing is written to `localStorage`, `sessionStorage`,
  cookies, or IndexedDB at any point. Verified at runtime.
- **Strict CSP** on production builds — no `unsafe-inline`, no `unsafe-eval`. The
  app uses zero inline styles so `style-src 'self'` holds. A `<meta>` tag cannot
  carry `frame-ancestors`, so **the static host must also send the CSP as a
  response header**; `vite.config.ts` holds the authoritative policy string.
- **Bounded plaintext dwell time.** Decrypted data is masked by default, cleared
  after 90s, and dropped on navigation away.
- **No autofill/autocomplete** on the passkey and card fields, and password
  managers are told to ignore them.
- **Indistinguishable failures.** A wrong passkey, an unknown identifier, and a
  lockout all produce the same 403 and the same message (LLD §6.3). The UI does
  not invent a distinction the server refuses to make.
- **Passkey strength floor** at creation (LLD §7, §10.5): minimum 12 characters
  plus a character-class check, with a strength meter. This is a UX nudge, not an
  entropy proof — the real defences are the KDF cost and the server-side lockout.

## Cross-language SRP validation

LLD §3.2 requires that `tssrp6a` ↔ Nimbus SRP interoperability be *verified*,
permanently, rather than assumed from the library's compatibility claim.
`src/crypto/srp.interop.test.ts` is that test. It runs in two layers:

- **Offline** — pins the SRP group (a digest of `N`), the SHA-256 hash, the
  PBKDF2 iteration floor, and the salt size, so a dependency upgrade that
  silently changes any of them fails immediately without needing a server.
- **Live** — performs a real `create → challenge → proof → decrypt` round trip
  against the running backend. Any disagreement in `x`, `k`, `u`, `A`, `B`, `S`,
  or `M1` fails the handshake, and the `M2` assertion closes the loop in the
  server-to-client direction.

Both layers pass against the current backend. `npm test` alone does **not**
verify the live layer — it warns loudly and skips. Use `npm run test:interop` in
CI, which fails hard when the backend is unreachable.

## Deployment

LLD §8.1 makes origin separation mandatory: the SPA must be served from a
different origin than the API. Two things are required and are **not** handled by
this repo today:

1. **Build with the API's real origin.**

   ```bash
   VITE_API_BASE_URL=https://api.example.com npm run build --prefix frontend
   ```

   This also adds that origin to `connect-src` in the generated CSP.

2. **Add CORS to the backend.** `SecurityConfiguration` currently configures no
   CORS, so a cross-origin frontend will be blocked by the browser. It needs an
   allowlist containing exactly this frontend's origin — never `*` (LLD §9.1).
   The dev proxy sidesteps this locally, which is why the gap is easy to miss.

The app also requires HTTPS outside `localhost`, because `crypto.subtle` is
unavailable on insecure origins.

## Scope

**Implemented:** the Create and Read flows.

**Not implemented:** the Share flow (LLD §5.4–5.7 — `/share/getCode`,
`/share/authLink`, `/share/getApprovedDetails`). The backend does not expose
these endpoints; `CardController` handles only `/create` and `/fetch`, and
`SecurityConfiguration` denies everything else. The design also lists this flow
as having an open question (LLD §10.1) that must be settled before it can be
built.

## Known deviations from the LLD

| LLD | Design says | Implementation | Why |
|---|---|---|---|
| §3.1 | Argon2id (m=19MiB, t=2, p=1) for key derivation | PBKDF2-SHA256, 600k iterations | §3 sanctions PBKDF2-SHA256 ≥600k as the fallback, and it is what the backend's own `CardFlowIntegrationTests` models the browser as doing. Switching to Argon2id means changing that Java test in lockstep, or the two sides stop agreeing. |
| §6.5 | Identifiers should be server-generated | Client generates a UUIDv4 via `crypto.randomUUID()` | The deployed `/create` accepts a client-supplied UUIDv4 and validates its version and variant. Moving generation server-side is a backend change. Note a UUIDv4 carries 122 bits of randomness, just under the §6.5 "≥128-bit" target. |
| §8.1 | Separate origins | Dev proxy makes them same-origin locally | Local convenience only. Production requires the two steps under [Deployment](#deployment). |

## Layout

```
src/
  api/cardApi.ts            transport for /create and /fetch; ciphertext only
  crypto/
    constants.ts            versioned parameters shared with the backend
    cardCrypto.ts           PBKDF2 + AES-256-GCM, blob format
    srp.ts                  SRP-6a client, Nimbus-compatible routines
    crypto.worker.ts        every passkey-handling operation runs here
    cryptoClient.ts         promise-based handle on the worker
    nodeCryptoShim.ts       gives tssrp6a real WebCrypto inside a worker
    srp.interop.test.ts     LLD §3.2 validation
  components/               CreateCardFlow, UnlockCardFlow, CardPreview, PasskeyField
  cardUtils.ts              formatting, Luhn, brand detection, passkey rating
```
