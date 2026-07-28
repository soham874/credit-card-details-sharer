/**
 * SRP-6a client side (LLD §3.1).
 *
 * `tssrp6a`'s default routines are ports of Nimbus SRP's `SRP6Routines`, which
 * is what the backend runs. The pairings that have to hold:
 *
 *   x  = H(s | H(P))          — identity is deliberately excluded on both sides
 *   k  = H(pad(N) | pad(g))
 *   u  = H(pad(A) | pad(B))
 *   M1 = H(A | B | S)         — unpadded
 *   M2 = H(A | M1 | S)        — unpadded
 *
 * The passkey is never sent anywhere: it only ever feeds `x`, which stays in
 * this module's caller (the crypto worker).
 */
import {
  SRPClientSession,
  SRPParameters,
  SRPRoutines,
  type SRPClientSessionStep2,
} from "tssrp6a";

import { SRP_GROUP_BITS, SRP_SALT_BYTES } from "./constants";
import { bytesToHex, hexToBigInt } from "./encoding";

/**
 * `SRPParameters` defaults to SHA-512; the backend uses SHA-256, so the hash is
 * passed explicitly. Never rely on the library default here.
 */
const parameters = new SRPParameters(
  SRPParameters.PrimeGroup[SRP_GROUP_BITS],
  SRPParameters.H.SHA256,
);
const routines = new SRPRoutines(parameters);

export const srpParameters = parameters;

/** RFC 5054 2048-bit group, as asserted by the interop test. */
export const srpGroup = parameters.primeGroup;

export type SrpProof = {
  /** Client public ephemeral `A`, hex. */
  clientPublicEphemeral: string;
  /** Client evidence `M1`, hex. */
  clientProof: string;
  /** Live session, retained so the server's `M2` can be checked in step 3. */
  session: SRPClientSessionStep2;
};

/** Fresh per-record salt. 16 bytes, matching the backend's own test fixture. */
export function generateSrpSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(SRP_SALT_BYTES));
}

/**
 * `v = g^H(s | H(passkey)) mod N`, computed here so the backend only ever
 * receives the one-way verifier.
 *
 * Driven off `routines` rather than the package's `createVerifierAndSalt`,
 * because the salt is ours: the same bytes have to feed both the verifier and
 * the PBKDF2 key derivation.
 */
export async function computeVerifier(
  cardIdentifier: string,
  passkey: string,
  salt: Uint8Array,
): Promise<bigint> {
  const x = await routines.computeX(cardIdentifier, hexToBigInt(bytesToHex(salt)), passkey);
  return routines.computeVerifier(x);
}

/**
 * Answer the server challenge: derive `A` and `M1` from the passkey and the
 * server's `B`. Throws if `B` is invalid (`B mod N == 0`), which is a rogue or
 * broken server rather than a wrong passkey.
 */
export async function computeProof(
  cardIdentifier: string,
  passkey: string,
  saltHex: string,
  serverPublicEphemeralHex: string,
): Promise<SrpProof> {
  const step1 = await new SRPClientSession(routines).step1(cardIdentifier, passkey);
  const step2 = await step1.step2(
    hexToBigInt(saltHex),
    hexToBigInt(serverPublicEphemeralHex),
  );
  return {
    clientPublicEphemeral: step2.A.toString(16),
    clientProof: step2.M1.toString(16),
    session: step2,
  };
}

/**
 * Mutual authentication (LLD §5.3, §10.2): confirm the server proved it holds
 * the verifier before we trust the blob it handed back. Throws on mismatch.
 */
export async function verifyServerProof(
  session: SRPClientSessionStep2,
  serverProofHex: string,
): Promise<void> {
  await session.step3(hexToBigInt(serverProofHex));
}
