/** Message contract between the UI thread and the crypto worker. */
import type { CreateCardRequest } from "../api/cardApi";
import type { CardDetails } from "./cardCrypto";

export type CreateRequest = {
  id: number;
  type: "create";
  details: CardDetails;
  cardLabel: string;
  passkey: string;
};

export type ProveRequest = {
  id: number;
  type: "prove";
  cardIdentifier: string;
  passkey: string;
  saltHex: string;
  serverPublicEphemeralHex: string;
};

export type UnsealRequest = {
  id: number;
  type: "unseal";
  /** `id` of the `prove` call whose retained session and passkey should be used. */
  proveId: number;
  blobBase64: string;
  serverProofHex: string;
};

export type DiscardRequest = {
  id: number;
  type: "discard";
  proveId: number;
};

export type WorkerRequest = CreateRequest | ProveRequest | UnsealRequest | DiscardRequest;

export type ProveResult = {
  clientPublicEphemeral: string;
  clientProof: string;
};

export type WorkerResultMap = {
  create: CreateCardRequest;
  prove: ProveResult;
  unseal: CardDetails;
  discard: void;
};

export type WorkerResponse =
  | { id: number; ok: true; result: unknown }
  | { id: number; ok: false; error: string };
