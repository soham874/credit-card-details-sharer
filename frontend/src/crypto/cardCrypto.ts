/**
 * Card payload encryption (LLD §3, §5.3).
 *
 * Blob layout is `IV(12) || ciphertext || GCM tag(16)`, byte-for-byte what
 * `CardFlowIntegrationTests.encryptInBrowser` produces on the Java side. The
 * key comes from the passkey via PBKDF2-SHA256 at 600k iterations, salted with
 * the same per-record salt the SRP verifier uses.
 */
import {
  AES_GCM_IV_BYTES,
  AES_GCM_TAG_BITS,
  AES_KEY_BITS,
  MAX_PLAINTEXT_BYTES,
  PBKDF2_HASH,
  PBKDF2_ITERATIONS,
} from "./constants";
import { wipe } from "./encoding";

export type CardDetails = {
  cardNumber: string;
  expiry: string;
  cvv: string;
  pin: string;
  holder: string;
  notes: string;
};

/**
 * Key names are part of the stored ciphertext format — renaming one makes every
 * previously stored card unreadable. Empty optional fields are dropped to stay
 * inside the backend's 512-byte blob cap.
 */
function serialize(details: CardDetails): Uint8Array {
  const payload: Record<string, string> = {
    cardNumber: details.cardNumber,
    expiry: details.expiry,
    cvv: details.cvv,
  };
  if (details.pin) payload.pin = details.pin;
  if (details.holder) payload.holder = details.holder;
  if (details.notes) payload.notes = details.notes;
  return new TextEncoder().encode(JSON.stringify(payload));
}

function deserialize(bytes: Uint8Array): CardDetails {
  const parsed = JSON.parse(new TextDecoder().decode(bytes)) as Partial<CardDetails>;
  return {
    cardNumber: parsed.cardNumber ?? "",
    expiry: parsed.expiry ?? "",
    cvv: parsed.cvv ?? "",
    pin: parsed.pin ?? "",
    holder: parsed.holder ?? "",
    notes: parsed.notes ?? "",
  };
}

async function deriveAesKey(passkey: string, salt: Uint8Array): Promise<CryptoKey> {
  const passkeyBytes = new TextEncoder().encode(passkey);
  try {
    const baseKey = await crypto.subtle.importKey("raw", passkeyBytes, "PBKDF2", false, [
      "deriveKey",
    ]);
    return await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt as BufferSource,
        iterations: PBKDF2_ITERATIONS,
        hash: PBKDF2_HASH,
      },
      baseKey,
      { name: "AES-GCM", length: AES_KEY_BITS },
      // Non-extractable: the derived key cannot be read back out of WebCrypto.
      false,
      ["encrypt", "decrypt"],
    );
  } finally {
    wipe(passkeyBytes);
  }
}

/** Returns `IV || ciphertext || tag`. A fresh IV is drawn per call — never reused under a key. */
export async function encryptCard(
  details: CardDetails,
  passkey: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const plaintext = serialize(details);
  if (plaintext.byteLength > MAX_PLAINTEXT_BYTES) {
    wipe(plaintext);
    throw new Error(
      `Card details are ${plaintext.byteLength} bytes; the maximum is ${MAX_PLAINTEXT_BYTES}. Shorten the notes or cardholder name.`,
    );
  }

  const key = await deriveAesKey(passkey, salt);
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  try {
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv as BufferSource, tagLength: AES_GCM_TAG_BITS },
        key,
        plaintext as BufferSource,
      ),
    );
    const blob = new Uint8Array(iv.length + ciphertext.length);
    blob.set(iv, 0);
    blob.set(ciphertext, iv.length);
    return blob;
  } finally {
    wipe(plaintext);
  }
}

/**
 * Reverses `encryptCard`. A wrong passkey fails the GCM tag check and surfaces
 * as an `OperationError` from WebCrypto rather than as garbage plaintext.
 */
export async function decryptCard(
  blob: Uint8Array,
  passkey: string,
  salt: Uint8Array,
): Promise<CardDetails> {
  if (blob.length <= AES_GCM_IV_BYTES + AES_GCM_TAG_BITS / 8) {
    throw new Error("Encrypted card data is malformed");
  }
  const key = await deriveAesKey(passkey, salt);
  const iv = blob.subarray(0, AES_GCM_IV_BYTES);
  const ciphertext = blob.subarray(AES_GCM_IV_BYTES);

  let plaintext: Uint8Array | undefined;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv as BufferSource, tagLength: AES_GCM_TAG_BITS },
        key,
        ciphertext as BufferSource,
      ),
    );
    return deserialize(plaintext);
  } finally {
    wipe(plaintext);
  }
}
