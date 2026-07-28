import { useState, type FormEvent } from "react";

import { ApiError, createCard } from "../api/cardApi";
import {
  detectBrand,
  digitsOnly,
  formatCardNumber,
  formatExpiry,
  isExpiryValid,
  maxCardDigits,
  passesLuhn,
  ratePasskey,
} from "../cardUtils";
import { MAX_CARD_LABEL_LENGTH } from "../crypto/constants";
import { prepareCard } from "../crypto/cryptoClient";
import type { CardDetails } from "../crypto/cardCrypto";
import { CardPreview } from "./CardPreview";
import { PasskeyField } from "./PasskeyField";

const EMPTY_DETAILS: CardDetails = {
  cardNumber: "",
  expiry: "",
  cvv: "",
  pin: "",
  holder: "",
  notes: "",
};

type Stage = "form" | "encrypting" | "saving" | "done";

type Props = {
  /** Hands the new identifier to the unlock flow so the user can test it immediately. */
  onUnlockCard: (cardIdentifier: string) => void;
};

export function CreateCardFlow({ onUnlockCard }: Props) {
  const [details, setDetails] = useState<CardDetails>(EMPTY_DETAILS);
  const [cardLabel, setCardLabel] = useState("");
  const [passkey, setPasskey] = useState("");
  const [confirmPasskey, setConfirmPasskey] = useState("");
  const [stage, setStage] = useState<Stage>("form");
  const [error, setError] = useState<string | undefined>();
  const [savedIdentifier, setSavedIdentifier] = useState<string | undefined>();
  const [copied, setCopied] = useState(false);

  const brand = detectBrand(details.cardNumber);
  const busy = stage === "encrypting" || stage === "saving";

  function update<K extends keyof CardDetails>(key: K, value: CardDetails[K]) {
    setDetails((current) => ({ ...current, [key]: value }));
  }

  function validate(): string | undefined {
    if (!cardLabel.trim()) return "Give the card a name so you can recognise it later.";
    if (cardLabel.length > MAX_CARD_LABEL_LENGTH) {
      return `Card name must be ${MAX_CARD_LABEL_LENGTH} characters or fewer.`;
    }
    if (!passesLuhn(details.cardNumber)) return "That card number does not look valid.";
    if (!isExpiryValid(details.expiry)) return "Enter a valid, unexpired expiry date as MM/YY.";
    if (details.cvv.length !== brand.cvvLength) {
      return `CVV must be ${brand.cvvLength} digits for ${brand.label}.`;
    }
    if (!ratePasskey(passkey).acceptable) {
      return "Choose a stronger passkey — it is the only thing protecting this card.";
    }
    if (passkey !== confirmPasskey) {
      return "The two passkeys do not match.";
    }
    return undefined;
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    const validationError = validate();
    if (validationError) {
      setError(validationError);
      return;
    }

    setError(undefined);
    setStage("encrypting");
    try {
      // Everything secret happens inside the worker: it returns only ciphertext,
      // the one-way verifier, and the salt.
      const request = await prepareCard(details, cardLabel.trim(), passkey);

      setStage("saving");
      await createCard(request);

      setSavedIdentifier(request.card_identifier);
      // Drop the plaintext and the passkey the moment they are no longer needed
      // (LLD §8.2).
      setDetails(EMPTY_DETAILS);
      setPasskey("");
      setConfirmPasskey("");
      setStage("done");
    } catch (caught) {
      setStage("form");
      setError(
        caught instanceof ApiError || caught instanceof Error
          ? caught.message
          : "Something went wrong while saving the card.",
      );
    }
  }

  async function copyIdentifier() {
    if (!savedIdentifier) return;
    try {
      await navigator.clipboard.writeText(savedIdentifier);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setError("Could not copy automatically — select the identifier and copy it manually.");
    }
  }

  function startAnother() {
    setSavedIdentifier(undefined);
    setCardLabel("");
    setStage("form");
    setError(undefined);
  }

  if (stage === "done" && savedIdentifier) {
    return (
      <section className="panel">
        <div className="success-mark" aria-hidden="true">
          ✓
        </div>
        <h2>Card stored</h2>
        <p className="lede">
          The card was encrypted in this browser before it was sent. The server holds ciphertext and
          a one-way verifier — it cannot read the card, and it never received your passkey.
        </p>

        <div className="callout danger">
          <strong>Save this identifier now.</strong> There is no account and no card list — this
          identifier plus your passkey is the only way to get the card back. If you lose either, the
          data is unrecoverable.
        </div>

        <div className="identifier-block">
          <code className="identifier">{savedIdentifier}</code>
          <button type="button" className="button secondary" onClick={copyIdentifier}>
            {copied ? "Copied" : "Copy"}
          </button>
        </div>

        {error && <p className="error-text">{error}</p>}

        <div className="button-row">
          <button
            type="button"
            className="button"
            onClick={() => onUnlockCard(savedIdentifier)}
          >
            Unlock it now
          </button>
          <button type="button" className="button secondary" onClick={startAnother}>
            Store another card
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="panel">
      <h2>Store a card</h2>
      <p className="lede">
        Details are encrypted here, in your browser, with a key derived from your passkey. Only the
        ciphertext leaves this page.
      </p>

      <CardPreview
        cardNumber={details.cardNumber}
        holder={details.holder}
        expiry={details.expiry}
        cvv={details.cvv}
        label={cardLabel}
      />

      <form onSubmit={handleSubmit} noValidate>
        <div className="field">
          <label className="field-label" htmlFor="card-label">
            Card name
          </label>
          <input
            id="card-label"
            className="input"
            value={cardLabel}
            onChange={(event) => setCardLabel(event.target.value.slice(0, MAX_CARD_LABEL_LENGTH))}
            placeholder="HDFC Platinum"
            autoComplete="off"
            disabled={busy}
          />
          <p className="field-hint">
            Stored unencrypted so you can tell which card you are unlocking before you type the
            passkey. Never put card data in here.
          </p>
        </div>

        <div className="field">
          <label className="field-label" htmlFor="card-number">
            Card number
          </label>
          <input
            id="card-number"
            className="input mono"
            value={formatCardNumber(details.cardNumber)}
            onChange={(event) =>
              update("cardNumber", digitsOnly(event.target.value).slice(0, maxCardDigits(brand)))
            }
            placeholder="4111 1111 1111 1111"
            inputMode="numeric"
            autoComplete="off"
            spellCheck={false}
            disabled={busy}
          />
        </div>

        <div className="field-row">
          <div className="field">
            <label className="field-label" htmlFor="card-expiry">
              Expiry
            </label>
            <input
              id="card-expiry"
              className="input mono"
              value={details.expiry}
              onChange={(event) => update("expiry", formatExpiry(event.target.value))}
              placeholder="MM/YY"
              inputMode="numeric"
              autoComplete="off"
              disabled={busy}
            />
          </div>
          <div className="field">
            <label className="field-label" htmlFor="card-cvv">
              CVV
            </label>
            <input
              id="card-cvv"
              className="input mono"
              type="password"
              value={details.cvv}
              onChange={(event) =>
                update("cvv", digitsOnly(event.target.value).slice(0, brand.cvvLength))
              }
              placeholder={"•".repeat(brand.cvvLength)}
              inputMode="numeric"
              autoComplete="off"
              disabled={busy}
            />
          </div>
          <div className="field">
            <label className="field-label" htmlFor="card-pin">
              PIN <span className="optional">optional</span>
            </label>
            <input
              id="card-pin"
              className="input mono"
              type="password"
              value={details.pin}
              onChange={(event) => update("pin", digitsOnly(event.target.value).slice(0, 6))}
              placeholder="••••"
              inputMode="numeric"
              autoComplete="off"
              disabled={busy}
            />
          </div>
        </div>

        <div className="field">
          <label className="field-label" htmlFor="card-holder">
            Cardholder name <span className="optional">optional</span>
          </label>
          <input
            id="card-holder"
            className="input"
            value={details.holder}
            onChange={(event) => update("holder", event.target.value.slice(0, 26))}
            placeholder="As embossed on the card"
            autoComplete="off"
            disabled={busy}
          />
        </div>

        <div className="field">
          <label className="field-label" htmlFor="card-notes">
            Notes <span className="optional">optional</span>
          </label>
          <input
            id="card-notes"
            className="input"
            value={details.notes}
            onChange={(event) => update("notes", event.target.value.slice(0, 120))}
            placeholder="Billing address zip, issuing bank, anything else"
            autoComplete="off"
            disabled={busy}
          />
        </div>

        <hr className="divider" />

        <PasskeyField
          label="Passkey"
          value={passkey}
          onChange={setPasskey}
          showStrength
          disabled={busy}
          hint="Never sent to the server. Never recoverable. Write it down somewhere safe."
        />
        <PasskeyField
          label="Confirm passkey"
          value={confirmPasskey}
          onChange={setConfirmPasskey}
          disabled={busy}
        />

        {error && <p className="error-text">{error}</p>}

        <button type="submit" className="button full" disabled={busy}>
          {stage === "encrypting"
            ? "Encrypting in your browser…"
            : stage === "saving"
              ? "Storing ciphertext…"
              : "Encrypt and store"}
        </button>
        {busy && (
          <p className="field-hint center">
            Key derivation is deliberately slow — this takes a moment by design.
          </p>
        )}
      </form>
    </section>
  );
}
