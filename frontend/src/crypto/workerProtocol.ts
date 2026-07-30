/** Message contract between the UI thread and the crypto worker. */
import type { CreateCardRequest } from "../api/cardApi";
import type { CardDetails } from "./cardCrypto";

export type CreateRequest = {
  id: number;
  type: "create";
  /** Includes the card's name, which is both encrypted and fed to the derivation. */
  details: CardDetails;
  passkey: string;
};

/**
 * Opens an unlock: derives the card identifier and keeps the passkey in the
 * worker for the two round trips that follow. The UI thread gets an identifier
 * back and nothing else, so it can drop the passkey before the first request
 * rather than holding it until the proof is computed.
 */
export type BeginUnlockRequest = {
  id: number;
  type: "beginUnlock";
  cardName: string;
  last4: string;
  passkey: string;
};

export type ProveRequest = {
  id: number;
  type: "prove";
  /** `id` of the `beginUnlock` call holding the passkey for this unlock. */
  unlockId: number;
  saltHex: string;
  serverPublicEphemeralHex: string;
};

export type UnsealRequest = {
  id: number;
  type: "unseal";
  unlockId: number;
  blobBase64: string;
  serverProofHex: string;
};

export type DiscardRequest = {
  id: number;
  type: "discard";
  unlockId: number;
};

export type WorkerRequest =
  | CreateRequest
  | BeginUnlockRequest
  | ProveRequest
  | UnsealRequest
  | DiscardRequest;

export type BeginUnlockResult = {
  cardIdentifier: string;
};

export type ProveResult = {
  clientPublicEphemeral: string;
  clientProof: string;
};

export type WorkerResultMap = {
  create: CreateCardRequest;
  beginUnlock: BeginUnlockResult;
  prove: ProveResult;
  unseal: CardDetails;
  discard: void;
};

export type WorkerResponse =
  | { id: number; ok: true; result: unknown }
  | { id: number; ok: false; error: string };
