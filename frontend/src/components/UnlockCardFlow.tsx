import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";

import { ApiError, initiateFetch, proveFetch, type FetchChallengeResponse } from "../api/cardApi";
import { isUuidV4, maskCardNumber } from "../cardUtils";
import type { CardDetails } from "../crypto/cardCrypto";
import {
  CHALLENGE_TTL_SECONDS,
  LOCKOUT_MINUTES,
  MAX_FAILED_ATTEMPTS,
  PLAINTEXT_DWELL_SECONDS,
} from "../crypto/constants";
import { discardUnlock, proveUnlock, unsealCard } from "../crypto/cryptoClient";
import { CardPreview } from "./CardPreview";
import { PasskeyField } from "./PasskeyField";

type Stage = "identifier" | "requesting" | "passkey" | "proving" | "revealed";

type Props = {
  /** Pre-filled when arriving from the create flow or a deep link. */
  initialIdentifier?: string;
};

/**
 * The `/fetch` flow (LLD §5.2, §5.3):
 *   step 1  identifier -> challenge + card label
 *   step 2  passkey    -> A, M1 -> ciphertext + M2 -> decrypt locally
 *
 * The passkey is used inside the crypto worker and is never sent anywhere. The
 * decrypted card is held in state only, wiped on a timer and on unmount.
 */
export function UnlockCardFlow({ initialIdentifier }: Props) {
  const [cardIdentifier, setCardIdentifier] = useState(initialIdentifier ?? "");
  const [stage, setStage] = useState<Stage>("identifier");
  const [challenge, setChallenge] = useState<FetchChallengeResponse | undefined>();
  const [passkey, setPasskey] = useState("");
  const [card, setCard] = useState<CardDetails | undefined>();
  /** Kept separately from `challenge`, which is cleared as soon as it is spent. */
  const [unlockedLabel, setUnlockedLabel] = useState("");
  const [error, setError] = useState<string | undefined>();
  const [challengeSecondsLeft, setChallengeSecondsLeft] = useState(CHALLENGE_TTL_SECONDS);
  const [dwellSecondsLeft, setDwellSecondsLeft] = useState(PLAINTEXT_DWELL_SECONDS);
  const [revealNumber, setRevealNumber] = useState(false);

  /** Worker-side SRP session awaiting the server's response, if any. */
  const openProveId = useRef<number | undefined>(undefined);

  const releaseProveSession = useCallback(() => {
    if (openProveId.current !== undefined) {
      discardUnlock(openProveId.current);
      openProveId.current = undefined;
    }
  }, []);

  const reset = useCallback(
    (nextStage: Stage) => {
      releaseProveSession();
      setChallenge(undefined);
      setPasskey("");
      setCard(undefined);
      setUnlockedLabel("");
      setRevealNumber(false);
      setStage(nextStage);
    },
    [releaseProveSession],
  );

  // Wipe anything sensitive if this component goes away (LLD §8.2).
  useEffect(() => releaseProveSession, [releaseProveSession]);

  useEffect(() => {
    if (initialIdentifier) {
      setCardIdentifier(initialIdentifier);
      setStage("identifier");
    }
  }, [initialIdentifier]);

  // The server drops the challenge after 2 minutes; count down so an expired
  // submission is explained rather than looking like a wrong passkey.
  useEffect(() => {
    if (stage !== "passkey") return;
    setChallengeSecondsLeft(CHALLENGE_TTL_SECONDS);
    const timer = setInterval(() => {
      setChallengeSecondsLeft((seconds) => Math.max(0, seconds - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, [stage, challenge]);

  // Bound how long plaintext sits in the DOM.
  useEffect(() => {
    if (stage !== "revealed") return;
    setDwellSecondsLeft(PLAINTEXT_DWELL_SECONDS);
    const timer = setInterval(() => {
      setDwellSecondsLeft((seconds) => {
        if (seconds <= 1) {
          clearInterval(timer);
          setCard(undefined);
          setUnlockedLabel("");
          setRevealNumber(false);
          setStage("identifier");
          return 0;
        }
        return seconds - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [stage]);

  async function requestChallenge(identifier: string) {
    setError(undefined);
    setStage("requesting");
    try {
      const received = await initiateFetch(identifier.trim());
      setChallenge(received);
      setPasskey("");
      setStage("passkey");
    } catch (caught) {
      setStage("identifier");
      setError(
        caught instanceof ApiError && caught.status === 403
          ? `This card is unavailable. After ${MAX_FAILED_ATTEMPTS} failed attempts a card locks for ${LOCKOUT_MINUTES} minutes — if that just happened, wait and try again.`
          : caught instanceof Error
            ? caught.message
            : "Could not start the unlock.",
      );
    }
  }

  function handleIdentifierSubmit(event: FormEvent) {
    event.preventDefault();
    if (!isUuidV4(cardIdentifier)) {
      setError("That does not look like a card identifier. Paste the full UUID you were given.");
      return;
    }
    void requestChallenge(cardIdentifier);
  }

  async function handlePasskeySubmit(event: FormEvent) {
    event.preventDefault();
    if (!challenge || !passkey) return;

    setError(undefined);
    setStage("proving");
    try {
      // Worker computes A and M1 and holds the session; the passkey stays there.
      const proof = await proveUnlock(
        cardIdentifier.trim(),
        passkey,
        challenge.srp_salt,
        challenge.server_public_ephemeral,
      );
      openProveId.current = proof.proveId;
      // The passkey is no longer needed on this thread.
      setPasskey("");

      const result = await proveFetch(
        challenge.challenge_id,
        proof.clientPublicEphemeral,
        proof.clientProof,
      );

      // Verifies the server's M2 before decrypting, then wipes the session.
      const details = await unsealCard(
        proof.proveId,
        result.encrypted_cc_blob,
        result.server_proof,
      );
      openProveId.current = undefined;

      setCard(details);
      setUnlockedLabel(challenge.card_label);
      setChallenge(undefined);
      setStage("revealed");
    } catch (caught) {
      releaseProveSession();
      setChallenge(undefined);
      setStage("identifier");
      setError(
        caught instanceof ApiError && caught.status === 403
          ? // §6.3: the server returns the same 403 for a wrong passkey, an
            // unknown identifier, and a lockout. Do not invent a distinction.
            `Could not unlock. The identifier or passkey is wrong, or the card is locked. Cards lock for ${LOCKOUT_MINUTES} minutes after ${MAX_FAILED_ATTEMPTS} failed attempts.`
          : caught instanceof Error
            ? caught.message
            : "Could not unlock the card.",
      );
    }
  }

  function hideNow() {
    setCard(undefined);
    setUnlockedLabel("");
    setRevealNumber(false);
    setStage("identifier");
    setError(undefined);
  }

  if (stage === "revealed" && card) {
    return (
      <section className="panel">
        <h2>Unlocked</h2>
        <p className="lede">
          Decrypted in this browser. Nothing is stored locally — this disappears in{" "}
          <strong>{dwellSecondsLeft}s</strong>.
        </p>

        <CardPreview
          cardNumber={card.cardNumber}
          holder={card.holder}
          expiry={card.expiry}
          cvv={card.cvv}
          label={unlockedLabel}
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

  if ((stage === "passkey" || stage === "proving") && challenge) {
    const expired = challengeSecondsLeft === 0;
    return (
      <section className="panel">
        <h2>
          Enter passkey for <span className="card-name">{challenge.card_label}</span>
        </h2>
        <p className="lede">
          The server sent a challenge. Your passkey answers it without ever being transmitted.
        </p>

        <form onSubmit={handlePasskeySubmit} noValidate>
          <PasskeyField
            label="Passkey"
            value={passkey}
            onChange={setPasskey}
            autoFocus
            disabled={stage === "proving" || expired}
          />

          <p className={`field-hint ${expired ? "warn" : ""}`}>
            {expired
              ? "This challenge expired. Request a new one to try again."
              : `Challenge expires in ${challengeSecondsLeft}s.`}
          </p>

          {error && <p className="error-text">{error}</p>}

          <button
            type="submit"
            className="button full"
            disabled={stage === "proving" || expired || !passkey}
          >
            {stage === "proving" ? "Proving and decrypting…" : "Unlock card"}
          </button>
        </form>

        <button
          type="button"
          className="button link"
          onClick={() => {
            reset("identifier");
            setError(undefined);
          }}
          disabled={stage === "proving"}
        >
          Use a different card
        </button>
      </section>
    );
  }

  return (
    <section className="panel">
      <h2>Unlock a card</h2>
      <p className="lede">
        Paste the identifier you were given when the card was stored. There is no account and no
        card list by design — the identifier is the only handle on the record.
      </p>

      <form onSubmit={handleIdentifierSubmit} noValidate>
        <div className="field">
          <label className="field-label" htmlFor="unlock-identifier">
            Card identifier
          </label>
          <input
            id="unlock-identifier"
            className="input mono"
            value={cardIdentifier}
            onChange={(event) => setCardIdentifier(event.target.value)}
            placeholder="550e8400-e29b-41d4-a716-446655440000"
            autoComplete="off"
            spellCheck={false}
            disabled={stage === "requesting"}
          />
        </div>

        {error && <p className="error-text">{error}</p>}

        <button type="submit" className="button full" disabled={stage === "requesting"}>
          {stage === "requesting" ? "Requesting challenge…" : "Continue"}
        </button>
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
