/**
 * Guards the card-identifier derivation (`cardIdentifier.ts`).
 *
 * Nothing stores a card identifier — it is recomputed from the card's name, its
 * last four digits, and the passkey every time. That makes this derivation a
 * versioned constant in the same sense as the SRP group and the KDF parameters
 * (LLD §3.2): if it ever changes, every stored card becomes unreachable, and the
 * failure looks to the user exactly like a wrong passkey. The golden vector
 * below is what makes such a change fail here first.
 */
import { describe, expect, it } from "vitest";

import { isUuidV4 } from "../cardUtils";
import { deriveCardIdentifier, lastFourDigits, normalizeCardName } from "./cardIdentifier";

const PASSKEY = "interop-vector-passkey";

describe("normalizeCardName", () => {
  it.each([
    ["HDFC Platinum", "hdfcplatinum"],
    ["hdfc platinum", "hdfcplatinum"],
    ["  HDFC  Platinum  ", "hdfcplatinum"],
    ["HDFC-Platinum", "hdfcplatinum"],
    ["HDFC_Platinum!", "hdfcplatinum"],
    ["hdfc.platinum", "hdfcplatinum"],
    ["Amex Gold 2", "amexgold2"],
  ])("folds %o to %o", (input, expected) => {
    expect(normalizeCardName(input)).toBe(expected);
  });

  it("collapses composed and decomposed forms of the same name", () => {
    // Written as escapes on purpose: a precomposed e-acute (U+00E9) and
    // e + combining acute (U+0301) are different bytes that render identically,
    // so spelling them literally would make this test silently vacuous.
    const precomposed = "Café Card";
    const decomposed = "Café Card";
    expect(precomposed).not.toBe(decomposed);
    expect(normalizeCardName(decomposed)).toBe(normalizeCardName(precomposed));
  });

  it("keeps genuinely different names apart", () => {
    expect(normalizeCardName("HDFC Platinum")).not.toBe(normalizeCardName("HDFC Plat"));
  });

  it("returns an empty string when nothing survives normalization", () => {
    expect(normalizeCardName("---")).toBe("");
    expect(normalizeCardName("   ")).toBe("");
  });
});

describe("lastFourDigits", () => {
  it("reads the last four digits through display formatting", () => {
    expect(lastFourDigits("4111 1111 1111 4242")).toBe("4242");
    expect(lastFourDigits("4111111111114242")).toBe("4242");
  });
});

describe("deriveCardIdentifier", () => {
  it(
    "matches the pinned vector",
    async () => {
      // Independently reproducible:
      //   node -e 'const c=require("node:crypto");
      //     const b=c.pbkdf2Sync("interop-vector-passkey",
      //       "ccshare-id-v1|hdfcplatinum|4242", 600000, 16, "sha256");
      //     b[6]=(b[6]&0x0f)|0x40; b[8]=(b[8]&0x3f)|0x80;
      //     console.log(b.toString("hex"));'
      await expect(deriveCardIdentifier("HDFC Platinum", "4242", PASSKEY)).resolves.toBe(
        "36f310aa-83f0-43a7-b782-b3481a8d3e67",
      );
    },
    60_000,
  );

  it(
    "produces a well-formed UUIDv4 that both sides will accept",
    async () => {
      const identifier = await deriveCardIdentifier("HDFC Platinum", "4242", PASSKEY);
      // The backend checks version 4 and variant 2 explicitly
      // (`CardCreationService.validateIdentifier`).
      expect(isUuidV4(identifier)).toBe(true);
      expect(identifier[14]).toBe("4");
      expect(["8", "9", "a", "b"]).toContain(identifier[19]);
    },
    60_000,
  );

  it(
    "is stable across calls — nothing is stored, so it has to be",
    async () => {
      const [first, second] = await Promise.all([
        deriveCardIdentifier("HDFC Platinum", "4242", PASSKEY),
        deriveCardIdentifier("HDFC Platinum", "4242", PASSKEY),
      ]);
      expect(first).toBe(second);
    },
    60_000,
  );

  it(
    "ignores case, spacing, and punctuation in the card name",
    async () => {
      const [canonical, messy] = await Promise.all([
        deriveCardIdentifier("HDFC Platinum", "4242", PASSKEY),
        deriveCardIdentifier("  hdfc-PLATINUM ", "4242", PASSKEY),
      ]);
      expect(messy).toBe(canonical);
    },
    60_000,
  );

  it(
    "changes completely when any one input changes",
    async () => {
      const [base, otherName, otherDigits, otherPasskey] = await Promise.all([
        deriveCardIdentifier("HDFC Platinum", "4242", PASSKEY),
        deriveCardIdentifier("HDFC Platinum Plus", "4242", PASSKEY),
        deriveCardIdentifier("HDFC Platinum", "4243", PASSKEY),
        deriveCardIdentifier("HDFC Platinum", "4242", `${PASSKEY}!`),
      ]);
      expect(new Set([base, otherName, otherDigits, otherPasskey]).size).toBe(4);
    },
    120_000,
  );

  it("rejects inputs it cannot derive from", async () => {
    await expect(deriveCardIdentifier("---", "4242", PASSKEY)).rejects.toThrow(
      /at least one letter or digit/,
    );
    await expect(deriveCardIdentifier("HDFC Platinum", "424", PASSKEY)).rejects.toThrow(
      /exactly four digits/,
    );
    await expect(deriveCardIdentifier("HDFC Platinum", "42x2", PASSKEY)).rejects.toThrow(
      /exactly four digits/,
    );
  });
});
