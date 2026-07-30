import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";

import { ApiError, initiateFetch, proveFetch } from "../api/cardApi";
import { digitsOnly, maskCardNumber } from "../cardUtils";
import type { CardDetails } from "../crypto/cardCrypto";
import { normalizeCardName } from "../crypto/cardIdentifier";
import { MAX_CARD_LABEL_LENGTH, PLAINTEXT_DWELL_SECONDS } from "../crypto/constants";
import { beginUnlock, discardUnlock, proveUnlock, unsealCard } from "../crypto/cryptoClient";
import { CardPreview } from "./CardPreview";
import { PasskeyField } from "./PasskeyField";

type Stage = "form" | "working" | "revealed";

type Props = {
  /** Pre-filled when arriving straight from the create flow. */
  initialHandle?: { cardName: string; last4: string };
};

/**
 * The `/fetch` flow (LLD §5.2, §5.3), as one shot.
 *
 * The card identifier is derived in the worker from the name, the last four
 * digits, and the passkey, so all three are collected up front and the two
 * server round trips happen without further input:
 *
 *   derive -> challenge -> A, M1 -> ciphertext + M2 -> decrypt locally
 *
 * A wrong input of any kind produces the identifier of a card that does not
 * exist, which the server answers exactly as it answers a wrong passkey against
 * a real card (LLD §6.3). The UI must not pretend to know which it was.
 */
export function UnlockCardFlow({ initialHandle }: Props) {
  const [cardName, setCardName] = useState(initialHandle?.cardName ?? "");
  const [last4, setLast4] = useState(initialHandle?.last4 ?? "");
  const [passkey, setPasskey] = useState("");
  const [stage, setStage] = useState<Stage>("form");
  const [progress, setProgress] = useState("");
  const [card, setCard] = useState<CardDetails | undefined>();
  const [error, setError] = useState<string | undefined>();
  const [dwellSecondsLeft, setDwellSecondsLeft] = useState(PLAINTEXT_DWELL_SECONDS);
  const [revealNumber, setRevealNumber] = useState(false);

  /** Worker-side session holding the passkey for this unlock, if one is open. */
  const openUnlockId = useRef<number | undefined>(undefined);

  const releaseUnlockSession = useCallback(() => {
    if (openUnlockId.current !== undefined) {
      discardUnlock(openUnlockId.current);
      openUnlockId.current = undefined;
    }
  }, []);

  // Wipe anything sensitive if this component goes away (LLD §8.2).
  useEffect(() => releaseUnlockSession, [releaseUnlockSession]);

  useEffect(() => {
    if (initialHandle) {
      setCardName(initialHandle.cardName);
      setLast4(initialHandle.last4);
      setStage("form");
    }
  }, [initialHandle]);

  // Bound how long plaintext sits in the DOM.
  useEffect(() => {
    if (stage !== "revealed") return;
    setDwellSecondsLeft(PLAINTEXT_DWELL_SECONDS);
    const timer = setInterval(() => {
      setDwellSecondsLeft((seconds) => {
        if (seconds <= 1) {
          clearInterval(timer);
          setCard(undefined);
          setRevealNumber(false);
          setStage("form");
          return 0;
        }
        return seconds - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [stage]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!normalizeCardName(cardName)) {
      setError("Enter the card's name — the one you chose when you stored it.");
      return;
    }
    if (!/^\d{4}$/.test(last4)) {
      setError("Enter the last 4 digits of the card number.");
      return;
    }
    if (!passkey) return;

    setError(undefined);
    setStage("working");
    setProgress("Deriving this card's identifier…");

    try {
      // The worker derives the identifier and keeps the passkey; this thread
      // never needs it again, so it goes immediately.
      const handle = await beginUnlock(cardName, last4, passkey);
      openUnlockId.current = handle.unlockId;
      setPasskey("");

      setProgress("Asking the server for a challenge…");
      const challenge = await initiateFetch(handle.cardIdentifier);

      setProgress("Proving you know the passkey…");
      const proof = await proveUnlock(
        handle.unlockId,
        challenge.srp_salt,
        challenge.server_public_ephemeral,
      );
      const result = await proveFetch(
        challenge.challenge_id,
        proof.clientPublicEphemeral,
        proof.clientProof,
      );

      // Verifies the server's M2 before decrypting, then wipes the session.
      setProgress("Decrypting…");
      const details = await unsealCard(
        handle.unlockId,
        result.encrypted_cc_blob,
        result.server_proof,
      );
      openUnlockId.current = undefined;

      setCard(details);
      setStage("revealed");
    } catch (caught) {
      releaseUnlockSession();
      setPasskey("");
      setStage("form");
      setError(
        caught instanceof ApiError && caught.status === 403
          ? // §6.3: the server cannot tell a wrong passkey from a card that was
            // never stored, and neither can we. Do not invent a distinction.
            "Could not unlock. The card name, last 4 digits, or passkey does not match anything stored — all three have to be exactly right."
          : caught instanceof Error
            ? caught.message
            : "Could not unlock the card.",
      );
    } finally {
      setProgress("");
    }
  }

  function hideNow() {
    setCard(undefined);
    setRevealNumber(false);
    setStage("form");
    setError(undefined);
  }

  if (stage === "revealed" && card) {
    return (
      <section className="panel">
        <h2>
          Unlocked <span className="card-name">{card.label}</span>
        </h2>
        <p className="lede">
          Decrypted in this browser. Nothing is stored locally — this disappears in{" "}
          <strong>{dwellSecondsLeft}s</strong>.
        </p>

        <CardPreview
          cardNumber={card.cardNumber}
          holder={card.holder}
          expiry={card.expiry}
          cvv={card.cvv}
          label={card.label}
          revealed={revealNumber}
        />

        <div className="revealed-fields">
          <RevealedField
            title="Card number"
            value={revealNumber ? card.cardNumber : maskCardNumber(card.cardNumber)}
          />
          <RevealedField title="Expiry" value={card.expiry} />
          <RevealedField title="CVV" value={revealNumber ? card.cvv : "•••"} />
          {card.pin && <RevealedField title="PIN" value={revealNumber ? card.pin : "••••"} />}
          {card.holder && <RevealedField title="Cardholder" value={card.holder} />}
          {card.notes && <RevealedField title="Notes" value={card.notes} />}
        </div>

        <div className="button-row">
          <button
            type="button"
            className="button secondary"
            onClick={() => setRevealNumber((current) => !current)}
          >
            {revealNumber ? "Mask details" : "Reveal details"}
          </button>
          <button type="button" className="button" onClick={hideNow}>
            Clear now
          </button>
        </div>
      </section>
    );
  }

  const working = stage === "working";
  const normalizedName = normalizeCardName(cardName);

  return (
    <section className="panel">
      <h2>Unlock a card</h2>
      <p className="lede">
        Nothing about your cards is stored on this device or listed by the server. A card is found by
        recomputing its address from what you know about it.
      </p>

      <form onSubmit={handleSubmit} noValidate>
        <div className="field">
          <label className="field-label" htmlFor="unlock-card-name">
            Card name
          </label>
          <input
            id="unlock-card-name"
            className="input"
            value={cardName}
            onChange={(event) => setCardName(event.target.value.slice(0, MAX_CARD_LABEL_LENGTH))}
            placeholder="HDFC Platinum"
            autoComplete="off"
            spellCheck={false}
            disabled={working}
          />
          {normalizedName && (
            <p className="field-hint">
              Looking for <code>{normalizedName}</code>. Spacing, capitals, and punctuation do not
              matter.
            </p>
          )}
        </div>

        <div className="field">
          <label className="field-label" htmlFor="unlock-last4">
            Last 4 digits
          </label>
          <input
            id="unlock-last4"
            className="input mono"
            value={last4}
            onChange={(event) => setLast4(digitsOnly(event.target.value).slice(0, 4))}
            placeholder="1234"
            inputMode="numeric"
            autoComplete="off"
            spellCheck={false}
            disabled={working}
          />
        </div>

        <PasskeyField
          label="Passkey"
          value={passkey}
          onChange={setPasskey}
          autoFocus={Boolean(initialHandle)}
          disabled={working}
        />

        {error && <p className="error-text">{error}</p>}

        <button type="submit" className="button full" disabled={working || !passkey}>
          {working ? "Working…" : "Unlock card"}
        </button>

        {working && progress && <p className="field-hint center">{progress}</p>}
      </form>
    </section>
  );
}

function RevealedField({ title, value }: { title: string; value: string }) {
  return (
    <div className="revealed-field">
      <span className="revealed-field-title">{title}</span>
      <span className="revealed-field-value mono">{value}</span>
    </div>
  );
}
