/**
 * UI-thread handle on the crypto worker. Turns the postMessage protocol into
 * promises and keeps the worker as the only place a passkey is held.
 */
import type { CreateCardRequest } from "../api/cardApi";
import type { CardDetails } from "./cardCrypto";
import type { ProveResult, WorkerRequest, WorkerResponse } from "./workerProtocol";

type Pending = {
  resolve: (value: unknown) => void;
  reject: (reason: Error) => void;
};

let worker: Worker | undefined;
let nextRequestId = 1;
const pending = new Map<number, Pending>();

function ensureWorker(): Worker {
  if (worker) return worker;

  worker = new Worker(new URL("./crypto.worker.ts", import.meta.url), { type: "module" });
  worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
    const response = event.data;
    const settle = pending.get(response.id);
    if (!settle) return;
    pending.delete(response.id);
    if (response.ok) {
      settle.resolve(response.result);
    } else {
      settle.reject(new Error(response.error));
    }
  };
  worker.onerror = () => {
    // A worker-level failure invalidates every in-flight request; fail them all
    // and drop the worker so the next call starts from a clean one.
    for (const [, settle] of pending) {
      settle.reject(new Error("The crypto worker failed. Reload the page and try again."));
    }
    pending.clear();
    worker?.terminate();
    worker = undefined;
  };
  return worker;
}

/**
 * Assigns the request id and hands it back alongside the promise, because the
 * unlock flow needs the id of its `prove` call to reach the retained session.
 */
function dispatch<T>(build: (id: number) => WorkerRequest): { id: number; result: Promise<T> } {
  const id = nextRequestId++;
  const result = new Promise<T>((resolve, reject) => {
    pending.set(id, { resolve: resolve as (value: unknown) => void, reject });
    ensureWorker().postMessage(build(id));
  });
  return { id, result };
}

/**
 * Encrypt the card and derive the verifier. Returns exactly the `/create` body;
 * neither the passkey nor the plaintext leaves the worker.
 */
export function prepareCard(
  details: CardDetails,
  cardLabel: string,
  passkey: string,
): Promise<CreateCardRequest> {
  return dispatch<CreateCardRequest>((id) => ({
    id,
    type: "create",
    details,
    cardLabel,
    passkey,
  })).result;
}

export type ProveHandle = ProveResult & {
  /** Pass to `unsealCard`/`discardUnlock` to reach this call's retained session. */
  proveId: number;
};

/** Answer the server's SRP challenge. The worker keeps the session for `unsealCard`. */
export async function proveUnlock(
  cardIdentifier: string,
  passkey: string,
  saltHex: string,
  serverPublicEphemeralHex: string,
): Promise<ProveHandle> {
  const { id, result } = dispatch<ProveResult>((requestId) => ({
    id: requestId,
    type: "prove",
    cardIdentifier,
    passkey,
    saltHex,
    serverPublicEphemeralHex,
  }));
  return { ...(await result), proveId: id };
}

/** Verify the server's `M2`, then decrypt. Clears the retained session either way. */
export function unsealCard(
  proveId: number,
  blobBase64: string,
  serverProofHex: string,
): Promise<CardDetails> {
  return dispatch<CardDetails>((id) => ({
    id,
    type: "unseal",
    proveId,
    blobBase64,
    serverProofHex,
  })).result;
}

/** Drop a retained session when an unlock is abandoned or the server refuses the proof. */
export function discardUnlock(proveId: number): void {
  void dispatch<void>((id) => ({ id, type: "discard", proveId })).result.catch(() => {
    // Nothing to recover: the state we wanted gone is gone either way.
  });
}
