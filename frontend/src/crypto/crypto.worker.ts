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
 * The passkey enters on `create`/`beginUnlock` and is wiped on completion. It is
 * never returned to the UI thread and never persisted anywhere.
 */
import { deriveCardIdentifier, lastFourDigits } from "./cardIdentifier";
import { encryptCard, decryptCard } from "./cardCrypto";
import { MAX_CARD_LABEL_LENGTH } from "./constants";
import { base64ToBytes, bigIntToHex, bytesToBase64, bytesToHex, hexToBytes } from "./encoding";
import { computeProof, computeVerifier, generateSrpSalt, verifyServerProof } from "./srp";
import type { SrpProof } from "./srp";
import type { WorkerRequest, WorkerResponse } from "./workerProtocol";

/**
 * State for one unlock, from `beginUnlock` through `unseal`. The passkey is held
 * here rather than on the UI thread precisely because it is needed twice: once
 * to answer the server's challenge and once to decrypt what comes back.
 */
type PendingUnlock = {
  cardIdentifier: string;
  passkey: string;
  saltHex?: string;
  session?: SrpProof["session"];
};

const pendingUnlocks = new Map<number, PendingUnlock>();

function forget(unlockId: number): void {
  pendingUnlocks.delete(unlockId);
}

function requireUnlock(unlockId: number): PendingUnlock {
  const pending = pendingUnlocks.get(unlockId);
  if (!pending) {
    throw new Error("This unlock session has expired. Start again.");
  }
  return pending;
}

async function handle(request: WorkerRequest): Promise<unknown> {
  switch (request.type) {
    case "create": {
      const label = request.details.label.trim();
      if (!label || label.length > MAX_CARD_LABEL_LENGTH) {
        throw new Error(`Card name must be 1-${MAX_CARD_LABEL_LENGTH} characters.`);
      }

      const last4 = lastFourDigits(request.details.cardNumber);
      const details = { ...request.details, label };
      const salt = generateSrpSalt();

      // Independent derivations, so let the platform overlap them — this is the
      // slowest thing the app does and it now runs PBKDF2 twice.
      const [cardIdentifier, blob] = await Promise.all([
        deriveCardIdentifier(label, last4, request.passkey),
        // Same salt feeds both the AES key derivation and the SRP verifier, as
        // in the backend's own integration test.
        encryptCard(details, request.passkey, salt),
      ]);
      const verifier = await computeVerifier(cardIdentifier, request.passkey, salt);

      return {
        card_identifier: cardIdentifier,
        encrypted_cc_blob: bytesToBase64(blob),
        srp_verifier: bigIntToHex(verifier),
        srp_salt: bytesToHex(salt),
      };
    }

    case "beginUnlock": {
      const cardIdentifier = await deriveCardIdentifier(
        request.cardName,
        request.last4,
        request.passkey,
      );
      pendingUnlocks.set(request.id, { cardIdentifier, passkey: request.passkey });
      return { cardIdentifier };
    }

    case "prove": {
      const pending = requireUnlock(request.unlockId);
      const proof = await computeProof(
        pending.cardIdentifier,
        pending.passkey,
        request.saltHex,
        request.serverPublicEphemeralHex,
      );
      pending.saltHex = request.saltHex;
      pending.session = proof.session;
      return {
        clientPublicEphemeral: proof.clientPublicEphemeral,
        clientProof: proof.clientProof,
      };
    }

    case "unseal": {
      const pending = requireUnlock(request.unlockId);
      if (!pending.session || !pending.saltHex) {
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
        forget(request.unlockId);
      }
    }

    case "discard": {
      forget(request.unlockId);
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
