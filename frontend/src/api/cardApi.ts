/**
 * Thin transport over the two backend endpoints. No crypto happens here — this
 * module only ever handles ciphertext, the one-way verifier, and public SRP
 * values.
 *
 * In dev, `VITE_API_BASE_URL` is unset and requests go to `/api`, which Vite
 * proxies to the backend. In any real deployment it must be set to the API's
 * own origin, which is separate from the frontend's by design (LLD §8.1).
 */
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api";

export type CreateCardRequest = {
  card_identifier: string;
  encrypted_cc_blob: string;
  srp_verifier: string;
  srp_salt: string;
  card_label: string;
};

export type FetchChallengeResponse = {
  challenge_id: string;
  srp_salt: string;
  server_public_ephemeral: string;
  card_label: string;
};

export type FetchCardResponse = {
  encrypted_cc_blob: string;
  server_proof: string;
};

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      // No cookies are involved: the backend is stateless and CSRF is disabled
      // deliberately (LLD §9.2).
      credentials: "omit",
    });
  } catch {
    throw new ApiError(0, "Could not reach the server. Check your connection and try again.");
  }

  if (!response.ok) {
    throw new ApiError(response.status, await describeFailure(response));
  }
  if (response.status === 204 || response.headers.get("content-length") === "0") {
    return undefined as T;
  }
  const text = await response.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

/**
 * Deliberately coarse. Per LLD §6.3 the backend returns an identical 403 for
 * "no such card", "wrong passkey", and "locked out", and the UI must not invent
 * a distinction the server refuses to make.
 */
async function describeFailure(response: Response): Promise<string> {
  switch (response.status) {
    case 400:
      return "The request was rejected as malformed.";
    case 403:
      return "Access denied.";
    case 409:
      return "That card identifier is already in use.";
    case 429:
      return "Too many requests. Wait a moment and try again.";
    default:
      return `Unexpected server response (${response.status}).`;
  }
}

/** `POST /create` — stores ciphertext and verifier material. Returns 200 with no body. */
export async function createCard(request: CreateCardRequest): Promise<void> {
  await postJson<void>("/create", request);
}

/** `POST /fetch` step 1 — asks for an SRP challenge and the card's label. */
export async function initiateFetch(cardIdentifier: string): Promise<FetchChallengeResponse> {
  return postJson<FetchChallengeResponse>("/fetch", { card_identifier: cardIdentifier });
}

/** `POST /fetch` step 2 — submits `A` and `M1`; on success returns the blob and `M2`. */
export async function proveFetch(
  challengeId: string,
  clientPublicEphemeral: string,
  clientProof: string,
): Promise<FetchCardResponse> {
  return postJson<FetchCardResponse>("/fetch", {
    challenge_id: challengeId,
    client_public_ephemeral: clientPublicEphemeral,
    client_proof: clientProof,
  });
}
