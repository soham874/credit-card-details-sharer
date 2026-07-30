/**
 * Card identifier derivation.
 *
 * The identifier used to be a random UUID the user had to keep somewhere and
 * paste back. It is now derived from three things the user either knows or is
 * holding — the card's name, its last four digits, and the passkey:
 *
 *     identifier = uuidV4Shape(PBKDF2(passkey, "ccshare-id-v1|<name>|<last4>"))
 *
 * Two properties matter, and they pull in opposite directions from the old design:
 *
 *  - It must be *unguessable*, because a guessable identifier hands an attacker
 *    a target list and, via the lockout, a way to grief every card at once. All
 *    of its entropy comes from the passkey, which is why this derivation is as
 *    deliberately slow as the AES one — a fast hash here would let anyone
 *    holding the identifier filter passkey candidates cheaply before paying for
 *    the expensive check.
 *  - It must be *reproducible*, because nothing stores it. That is what
 *    `normalizeCardName` is for, and why changing that function is a breaking
 *    change on the same footing as changing the KDF parameters: every existing
 *    card would become unreachable, with no error message that could explain it.
 *
 * The identifier is therefore secret-adjacent. Leaking one gives an attacker an
 * offline oracle for grinding the passkey behind it, with no server and no rate
 * limit in the way — so it is never put in a URL, never logged in the clear, and
 * never shown to the user.
 */
import { ID_DERIVATION_VERSION, PBKDF2_HASH, PBKDF2_ITERATIONS } from "./constants";
import { bytesToHex, wipe } from "./encoding";

/**
 * Folds away every difference a user is likely to introduce when retyping a
 * card's name months later: case, spacing, and punctuation. "HDFC Platinum",
 * "hdfc-platinum" and " HDFC_Platinum " all become `hdfcplatinum`.
 *
 * What it deliberately cannot rescue is a different *word* — "HDFC Plat" is a
 * different card as far as this function is concerned. The create flow shows the
 * normalized form as the user types so that what must be reproduced is visible
 * at the moment it is chosen.
 *
 * NFKC runs first so that visually identical characters that differ in encoding
 * (composed vs. decomposed accents, full-width Latin) collapse together before
 * anything else is stripped.
 */
export function normalizeCardName(cardName: string): string {
  return cardName.normalize("NFKC").toLowerCase().replace(/[^a-z0-9]/g, "");
}

/** The four digits are read off the card, never typed at creation time. */
export function lastFourDigits(cardNumber: string): string {
  return cardNumber.replace(/\D/g, "").slice(-4);
}

/**
 * Stamps 16 derived bytes into the UUIDv4 shape both sides validate
 * (`CardCreationService.validateIdentifier`, `isUuidV4`). This spends 6 of the
 * 128 bits on the version and variant markers, which costs nothing real: the
 * ceiling here is the passkey's own entropy, far below either number.
 */
function toUuidV4Shape(bytes: Uint8Array): string {
  const shaped = bytes.slice(0, 16);
  shaped[6] = (shaped[6] & 0x0f) | 0x40;
  shaped[8] = (shaped[8] & 0x3f) | 0x80;

  const hex = bytesToHex(shaped);
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join("-");
}

/**
 * Same passkey, same card name, same last four digits — same identifier, on any
 * device, forever. A wrong passkey does not produce a failed lookup of the right
 * card; it produces the identifier of a card that does not exist, which the
 * server answers with an indistinguishable dummy challenge (LLD §6.3).
 */
export async function deriveCardIdentifier(
  cardName: string,
  last4: string,
  passkey: string,
): Promise<string> {
  const normalizedName = normalizeCardName(cardName);
  if (!normalizedName) {
    throw new Error("Card name must contain at least one letter or digit.");
  }
  if (!/^\d{4}$/.test(last4)) {
    throw new Error("Last four digits must be exactly four digits.");
  }

  // Version-tagged so a future change to the normalization rules can be rolled
  // forward deliberately instead of silently orphaning every stored card. The
  // tag also keeps this derivation in a different salt space from the AES key,
  // which is salted with the random per-record `srp_salt`.
  const salt = new TextEncoder().encode(
    `${ID_DERIVATION_VERSION}|${normalizedName}|${last4}`,
  );
  const passkeyBytes = new TextEncoder().encode(passkey);

  try {
    const baseKey = await crypto.subtle.importKey("raw", passkeyBytes, "PBKDF2", false, [
      "deriveBits",
    ]);
    const derived = new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: salt as BufferSource,
          iterations: PBKDF2_ITERATIONS,
          hash: PBKDF2_HASH,
        },
        baseKey,
        128,
      ),
    );
    try {
      return toUuidV4Shape(derived);
    } finally {
      wipe(derived);
    }
  } finally {
    wipe(passkeyBytes);
  }
}
