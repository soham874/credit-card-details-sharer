/**
 * Cross-language interoperability validation (LLD §3.2).
 *
 * §3.2 is explicit that "tssrp6a documents itself as Nimbus-compatible" is a
 * signal, not a verification, and that the check must be a permanent test
 * rather than a one-time manual confirmation. This file is that test.
 *
 * Two layers:
 *  1. Offline — pins the SRP group, the hash, and the KDF parameters, so a
 *     dependency bump that silently changes the prime, the generator, or the
 *     digest fails here without needing a server.
 *  2. Live — runs the real `/create` + `/fetch` handshake against a running
 *     backend using the same modules the app ships. A disagreement in any of
 *     `x`, `k`, `u`, `A`, `B`, `S`, or `M1` makes the handshake fail, and the
 *     `M2` check closes the loop in the server-to-client direction.
 *
 * `npm test`          — offline layer only; live layer skips with a warning.
 * `npm run test:interop` — requires a reachable backend and fails if it is not.
 */
import { beforeAll, describe, expect, it } from "vitest";

import { decryptCard, encryptCard, type CardDetails } from "./cardCrypto";
import { PBKDF2_ITERATIONS, SRP_HASH, SRP_SALT_BYTES } from "./constants";
import { base64ToBytes, bigIntToHex, bytesToBase64, bytesToHex, hexToBigInt } from "./encoding";
import { computeProof, computeVerifier, generateSrpSalt, srpGroup, srpParameters } from "./srp";

const BACKEND_URL = process.env.BACKEND_URL ?? "http://localhost:8080";
const REQUIRE_BACKEND = process.env.REQUIRE_BACKEND === "1";

async function backendReachable(): Promise<boolean> {
  try {
    const response = await fetch(`${BACKEND_URL}/v3/api-docs`, {
      signal: AbortSignal.timeout(3000),
    });
    return response.ok;
  } catch {
    return false;
  }
}

const reachable = await backendReachable();

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource)));
}

describe("SRP parameters (offline)", () => {
  it("uses a 2048-bit group with generator 2", () => {
    expect(srpGroup.g).toBe(2n);
    expect(srpGroup.N.toString(2).length).toBe(2048);
  });

  /**
   * Regression pin on the exact prime. The digest was not transcribed from the
   * RFC by hand — it was captured from a run in which the live handshake below
   * passed against Nimbus, which is what actually proves the two sides share a
   * group. If a `tssrp6a` upgrade swaps the prime, this fails immediately
   * instead of waiting for a backend to be available.
   */
  it("pins the exact prime the backend's Nimbus group uses", async () => {
    const digest = await sha256Hex(new TextEncoder().encode(srpGroup.N.toString(16)));
    expect(digest).toBe("ef88b43c555c005c89f9c32dbd2ced49b0bb57e2cd1f2b5e9eca181afdf09c56");
  });

  it("hashes with SHA-256, not the library default of SHA-512", async () => {
    expect(SRP_HASH).toBe("SHA-256");
    // NIST's published SHA-256("abc"). If the configured hash silently changed,
    // every SRP intermediate would change with it.
    const digest = await srpParameters.H(new TextEncoder().encode("abc").buffer as ArrayBuffer);
    expect(bytesToHex(new Uint8Array(digest))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("keeps the derived-key parameters at the pinned values", () => {
    expect(PBKDF2_ITERATIONS).toBeGreaterThanOrEqual(600_000);
    expect(SRP_SALT_BYTES).toBe(16);
  });
});

describe("AES-GCM round trip (offline)", () => {
  it("recovers the card and rejects a wrong passkey via the GCM tag", async () => {
    const details: CardDetails = {
      cardNumber: "4111111111111111",
      expiry: "12/30",
      cvv: "123",
      pin: "1234",
      holder: "A CARDHOLDER",
      notes: "",
    };
    const salt = generateSrpSalt();
    const blob = await encryptCard(details, "correct-passkey", salt);

    // IV || ciphertext || tag, and inside the backend's 512-byte cap.
    expect(blob.length).toBeLessThanOrEqual(512);
    await expect(decryptCard(blob, "correct-passkey", salt)).resolves.toMatchObject(details);
    await expect(decryptCard(blob, "wrong-passkey", salt)).rejects.toThrow();
  }, 60_000);
});

describe("backend availability", () => {
  it("is reachable when the interop run demands it", () => {
    if (!REQUIRE_BACKEND) return;
    expect(reachable, `No backend at ${BACKEND_URL}. Start it, then re-run.`).toBe(true);
  });
});

/** Helper: store a card and return everything needed to unlock it. */
async function createCard(passkey: string, label: string, details: CardDetails) {
  const cardIdentifier = crypto.randomUUID();
  const salt = generateSrpSalt();
  const blob = await encryptCard(details, passkey, salt);
  const verifier = await computeVerifier(cardIdentifier, passkey, salt);
  const response = await fetch(`${BACKEND_URL}/create`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      card_identifier: cardIdentifier,
      encrypted_cc_blob: bytesToBase64(blob),
      srp_verifier: bigIntToHex(verifier),
      srp_salt: bytesToHex(salt),
      card_label: label,
    }),
  });
  return { cardIdentifier, salt, response };
}

async function requestChallenge(cardIdentifier: string) {
  const response = await fetch(`${BACKEND_URL}/fetch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ card_identifier: cardIdentifier }),
  });
  return { response, body: response.ok ? await response.json() : undefined };
}

async function submitProof(challengeId: string, A: string, M1: string) {
  return fetch(`${BACKEND_URL}/fetch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      challenge_id: challengeId,
      client_public_ephemeral: A,
      client_proof: M1,
    }),
  });
}

const liveDescribe = reachable ? describe : describe.skip;

if (!reachable) {
  // Loud on purpose: a silently-skipped interop test is the exact failure mode
  // §3.2 exists to prevent.
  console.warn(
    `\n  [interop] Backend not reachable at ${BACKEND_URL} — the cross-language ` +
      `handshake was NOT verified.\n  [interop] Start the backend, then run: npm run test:interop\n`,
  );
}

liveDescribe("live handshake against the Java backend", () => {
  const details: CardDetails = {
    cardNumber: "4111111111111111",
    expiry: "12/30",
    cvv: "123",
    pin: "1234",
    holder: "",
    notes: "",
  };

  beforeAll(() => {
    expect(reachable).toBe(true);
  });

  it(
    "completes create -> challenge -> proof -> decrypt and verifies the server proof",
    async () => {
      const passkey = "interop-test-passkey";
      const label = "Interop Test Card";
      const { cardIdentifier, salt, response: created } = await createCard(passkey, label, details);
      expect(created.status, await created.text()).toBe(200);

      const { response: challengeResponse, body: challenge } =
        await requestChallenge(cardIdentifier);
      expect(challengeResponse.status).toBe(200);
      expect(challenge.srp_salt).toBe(bytesToHex(salt));
      expect(challenge.card_label).toBe(label);

      // Our M1 has to satisfy Nimbus's own computation on the other side.
      const proof = await computeProof(
        cardIdentifier,
        passkey,
        challenge.srp_salt,
        challenge.server_public_ephemeral,
      );
      const proofResponse = await submitProof(
        challenge.challenge_id,
        proof.clientPublicEphemeral,
        proof.clientProof,
      );
      expect(
        proofResponse.status,
        "M1 was rejected — the client and server SRP routines disagree",
      ).toBe(200);

      const fetched = await proofResponse.json();

      // M2: the reverse direction. Throws if the server's evidence differs.
      await expect(
        proof.session.step3(hexToBigInt(fetched.server_proof)),
      ).resolves.not.toThrow();

      await expect(
        decryptCard(base64ToBytes(fetched.encrypted_cc_blob), passkey, salt),
      ).resolves.toMatchObject(details);
    },
    120_000,
  );

  it(
    "rejects a wrong passkey with 403 and returns no ciphertext",
    async () => {
      const { cardIdentifier } = await createCard("the-right-one", "Interop Negative", details);
      const { body: challenge } = await requestChallenge(cardIdentifier);

      const proof = await computeProof(
        cardIdentifier,
        "definitely-not-it",
        challenge.srp_salt,
        challenge.server_public_ephemeral,
      );
      const response = await submitProof(
        challenge.challenge_id,
        proof.clientPublicEphemeral,
        proof.clientProof,
      );

      expect(response.status).toBe(403);
      expect(await response.text()).not.toContain("encrypted_cc_blob");
    },
    120_000,
  );

  it(
    "returns an indistinguishable challenge for an identifier that does not exist (§6.3)",
    async () => {
      const { response, body } = await requestChallenge(crypto.randomUUID());
      expect(response.status).toBe(200);
      expect(body).toHaveProperty("challenge_id");
      expect(body).toHaveProperty("srp_salt");
      expect(body).toHaveProperty("server_public_ephemeral");
      // A fixed placeholder label, not an omitted field — same response shape.
      expect(typeof body.card_label).toBe("string");
      expect(body.card_label.length).toBeGreaterThan(0);
    },
    60_000,
  );
});
