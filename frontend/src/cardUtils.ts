/**
 * Presentation-layer helpers for card input: formatting, brand detection, and
 * validation. Nothing here is security-relevant — it exists so the user catches
 * a typo before the details are encrypted, since a mistyped card can only be
 * discovered by unlocking it again.
 */

export type CardBrand = {
  id: string;
  label: string;
  /** Digit-group layout used for display, e.g. 4-4-4-4. */
  groups: number[];
  cvvLength: number;
};

const BRANDS: Array<CardBrand & { pattern: RegExp }> = [
  { id: "amex", label: "American Express", pattern: /^3[47]/, groups: [4, 6, 5], cvvLength: 4 },
  { id: "visa", label: "Visa", pattern: /^4/, groups: [4, 4, 4, 4], cvvLength: 3 },
  {
    id: "mastercard",
    label: "Mastercard",
    pattern: /^(5[1-5]|2[2-7])/,
    groups: [4, 4, 4, 4],
    cvvLength: 3,
  },
  { id: "rupay", label: "RuPay", pattern: /^(60|65|81|82|508)/, groups: [4, 4, 4, 4], cvvLength: 3 },
  { id: "discover", label: "Discover", pattern: /^(6011|64[4-9]|65)/, groups: [4, 4, 4, 4], cvvLength: 3 },
  { id: "diners", label: "Diners Club", pattern: /^3(0[0-5]|[68])/, groups: [4, 6, 4], cvvLength: 3 },
  { id: "jcb", label: "JCB", pattern: /^35/, groups: [4, 4, 4, 4], cvvLength: 3 },
];

const UNKNOWN_BRAND: CardBrand = {
  id: "unknown",
  label: "Card",
  groups: [4, 4, 4, 4],
  cvvLength: 3,
};

export function digitsOnly(value: string): string {
  return value.replace(/\D/g, "");
}

export function detectBrand(cardNumber: string): CardBrand {
  const digits = digitsOnly(cardNumber);
  // Discover's 65 prefix overlaps RuPay's, so the first match in list order
  // wins; RuPay is listed first because this is an India-first tool.
  const match = BRANDS.find((brand) => brand.pattern.test(digits));
  return match ?? UNKNOWN_BRAND;
}

/** Groups digits per the detected brand's layout, for display only. */
export function formatCardNumber(value: string): string {
  const digits = digitsOnly(value);
  const { groups } = detectBrand(digits);

  const parts: string[] = [];
  let offset = 0;
  for (const size of groups) {
    if (offset >= digits.length) break;
    parts.push(digits.slice(offset, offset + size));
    offset += size;
  }
  // Anything past the expected length still gets shown rather than silently
  // dropped, so an over-long number is visible to the user.
  if (offset < digits.length) parts.push(digits.slice(offset));
  return parts.join(" ");
}

export function maxCardDigits(brand: CardBrand): number {
  return brand.groups.reduce((total, size) => total + size, 0);
}

/** Luhn checksum. Catches transposed and mistyped digits. */
export function passesLuhn(cardNumber: string): boolean {
  const digits = digitsOnly(cardNumber);
  if (digits.length < 12) return false;

  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = digits.charCodeAt(i) - 48;
    if (double) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    double = !double;
  }
  return sum % 10 === 0;
}

/** Accepts `MM/YY`, inserting the slash as the user types. */
export function formatExpiry(value: string): string {
  const digits = digitsOnly(value).slice(0, 4);
  if (digits.length === 0) return "";
  // A leading digit above 1 can only be a single-digit month, so pad it.
  if (digits.length === 1) return digits > "1" ? `0${digits}/` : digits;
  const month = digits.slice(0, 2);
  const year = digits.slice(2);
  return year ? `${month}/${year}` : month;
}

export function isExpiryValid(expiry: string): boolean {
  const match = /^(\d{2})\/(\d{2})$/.exec(expiry);
  if (!match) return false;
  const month = Number(match[1]);
  if (month < 1 || month > 12) return false;

  // Two-digit years are read as 20xx; a card expiring in the past is a typo.
  const now = new Date();
  const expiryYear = 2000 + Number(match[2]);
  const currentYear = now.getFullYear();
  const currentMonth = now.getMonth() + 1;
  if (expiryYear < currentYear) return false;
  if (expiryYear === currentYear && month < currentMonth) return false;
  return expiryYear <= currentYear + 25;
}

export function maskCardNumber(cardNumber: string): string {
  const digits = digitsOnly(cardNumber);
  if (digits.length <= 4) return digits;
  return `•••• ${digits.slice(-4)}`;
}

/**
 * Rough passkey strength, used to enforce a floor at creation time
 * (LLD §7, §10.5). This is a heuristic for UX nudging, not an entropy proof —
 * the real defence is Argon2id/PBKDF2 cost plus the server-side lockout.
 */
export type PasskeyStrength = {
  score: 0 | 1 | 2 | 3 | 4;
  label: string;
  acceptable: boolean;
  hint: string;
};

const MIN_PASSKEY_LENGTH = 12;

export function ratePasskey(passkey: string): PasskeyStrength {
  if (!passkey) {
    return { score: 0, label: "Empty", acceptable: false, hint: "" };
  }

  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((pattern) =>
    pattern.test(passkey),
  ).length;
  const unique = new Set(passkey).size;

  let score = 0;
  if (passkey.length >= 8) score++;
  if (passkey.length >= MIN_PASSKEY_LENGTH) score++;
  if (classes >= 3) score++;
  if (passkey.length >= 16 && unique >= 10) score++;

  // A long string of one repeated character passes the length checks but is
  // trivially guessable, so cap it.
  if (unique <= 4) score = Math.min(score, 1);

  const tooShort = passkey.length < MIN_PASSKEY_LENGTH;
  const acceptable = !tooShort && score >= 2;

  const hint = tooShort
    ? `Use at least ${MIN_PASSKEY_LENGTH} characters.`
    : acceptable
      ? ""
      : "Mix upper case, lower case, digits, and symbols.";

  return {
    score: Math.min(score, 4) as PasskeyStrength["score"],
    label: ["Very weak", "Weak", "Fair", "Strong", "Very strong"][Math.min(score, 4)],
    acceptable,
    hint,
  };
}

export const PASSKEY_MIN_LENGTH = MIN_PASSKEY_LENGTH;

/** Backend requires a UUIDv4 for both `card_identifier` and `challenge_id`. */
export function isUuidV4(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value.trim());
}
