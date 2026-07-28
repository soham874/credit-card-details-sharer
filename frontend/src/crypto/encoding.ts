/** Byte/hex/base64 conversions shared by the SRP and AES paths. */

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("Malformed hex string");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Hex for the wire. The backend validates `^[0-9a-fA-F]+$` and normalises odd
 * lengths itself, but we pad to an even length so what we send round-trips
 * byte-for-byte through `HexFormat.parseHex`.
 */
export function bigIntToHex(value: bigint): string {
  if (value < 0n) {
    throw new Error("Cannot hex-encode a negative BigInt");
  }
  const hex = value.toString(16);
  return hex.length % 2 === 0 ? hex : `0${hex}`;
}

export function hexToBigInt(hex: string): bigint {
  if (hex.length === 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error("Malformed hex string");
  }
  return BigInt(`0x${hex}`);
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Best-effort scrub of a buffer that held key material or plaintext (LLD §8.2). */
export function wipe(bytes: Uint8Array | undefined): void {
  bytes?.fill(0);
}
