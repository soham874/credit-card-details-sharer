/**
 * All passkey-handling crypto runs here, off the UI thread (LLD §8.2).
 *
 * Two reasons, in order of importance:
 *  1. It narrows the XSS blast radius — script injected into the page cannot
 *     read this worker's heap, so the passkey and the derived key are not
 *     sitting in the same scope as the DOM.
 *  2. PBKDF2 at 600k iterations plus 2048-bit modular exponentiation would
 *     otherwise freeze the page for seconds.
 *
 * The passkey enters on `create`/`prove` and is wiped on completion. It is
 * never returned to the UI thread and never persisted anywhere.
 */
import { encryptCard, decryptCard } from "./cardCrypto";
import { MAX_CARD_LABEL_LENGTH } from "./constants";
import { base64ToBytes, bigIntToHex, bytesToBase64, bytesToHex, hexToBytes } from "./encoding";
import { computeProof, computeVerifier, generateSrpSalt, verifyServerProof } from "./srp";
import type { SrpProof } from "./srp";
import type { WorkerRequest, WorkerResponse } from "./workerProtocol";

/**
 * SRP state held between the two `/fetch` round trips. Lives only for the
 * duration of one unlock; `unseal` and `discard` both clear it.
 */
type PendingUnlock = {
  passkey: string;
  saltHex: string;
  session: SrpProof["session"];
};

const pendingUnlocks = new Map<number, PendingUnlock>();

function forget(proveId: number): void {
  pendingUnlocks.delete(proveId);
}

async function handle(request: WorkerRequest): Promise<unknown> {
  switch (request.type) {
    case "create": {
      const cardLabel = request.cardLabel.trim();
      if (!cardLabel || cardLabel.length > MAX_CARD_LABEL_LENGTH) {
        throw new Error(`Card name must be 1-${MAX_CARD_LABEL_LENGTH} characters.`);
      }

      // LLD §6.5 wants a server-issued identifier; the deployed `/create` takes
      // a client-supplied UUIDv4 and validates its version/variant, so we mint
      // one from the platform CSPRNG (122 bits of randomness).
      const cardIdentifier = crypto.randomUUID();
      const salt = generateSrpSalt();

      // Same salt feeds both the AES key derivation and the SRP verifier, as in
      // the backend's own integration test.
      const blob = await encryptCard(request.details, request.passkey, salt);
      const verifier = await computeVerifier(cardIdentifier, request.passkey, salt);

      return {
        card_identifier: cardIdentifier,
        encrypted_cc_blob: bytesToBase64(blob),
        srp_verifier: bigIntToHex(verifier),
        srp_salt: bytesToHex(salt),
        card_label: cardLabel,
      };
    }

    case "prove": {
      const proof = await computeProof(
        request.cardIdentifier,
        request.passkey,
        request.saltHex,
        request.serverPublicEphemeralHex,
      );
      pendingUnlocks.set(request.id, {
        passkey: request.passkey,
        saltHex: request.saltHex,
        session: proof.session,
      });
      return {
        clientPublicEphemeral: proof.clientPublicEphemeral,
        clientProof: proof.clientProof,
      };
    }

    case "unseal": {
      const pending = pendingUnlocks.get(request.proveId);
      if (!pending) {
        throw new Error("This unlock session has expired. Start again.");
      }
      try {
        // Check the server proved possession of the verifier before trusting
        // anything it returned (LLD §5.3, §10.2). A rogue backend that faked a
        // success response fails here.
        await verifyServerProof(pending.session, request.serverProofHex);
        return await decryptCard(
          base64ToBytes(request.blobBase64),
          pending.passkey,
          hexToBytes(pending.saltHex),
        );
      } finally {
        forget(request.proveId);
      }
    }

    case "discard": {
      forget(request.proveId);
      return undefined;
    }
  }
}

self.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  const request = event.data;
  let response: WorkerResponse;
  try {
    response = { id: request.id, ok: true, result: await handle(request) };
  } catch (error) {
    response = {
      id: request.id,
      ok: false,
      error: error instanceof Error ? error.message : "Cryptographic operation failed.",
    };
  }
  self.postMessage(response);
};
