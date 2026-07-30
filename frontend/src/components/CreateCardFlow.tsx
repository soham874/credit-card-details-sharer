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
import { lastFourDigits, normalizeCardName } from "../crypto/cardIdentifier";
import { MAX_CARD_LABEL_LENGTH } from "../crypto/constants";
import { prepareCard } from "../crypto/cryptoClient";
import type { CardDetails } from "../crypto/cardCrypto";
import { CardPreview } from "./CardPreview";
import { PasskeyField } from "./PasskeyField";

const EMPTY_DETAILS: CardDetails = {
  label: "",
  cardNumber: "",
  expiry: "",
  cvv: "",
  pin: "",
  holder: "",
  notes: "",
};

type Stage = "form" | "confirm" | "encrypting" | "saving" | "done";

/** What the user has to be able to reproduce later. Nothing else can find the card. */
type CardHandle = { cardName: string; last4: string };

type Props = {
  /** Hands the name and last four to the unlock flow so the user can test them immediately. */
  onUnlockCard: (handle: CardHandle) => void;
};

export function CreateCardFlow({ onUnlockCard }: Props) {
  const [details, setDetails] = useState<CardDetails>(EMPTY_DETAILS);
  const [passkey, setPasskey] = useState("");
  const [confirmPasskey, setConfirmPasskey] = useState("");
  const [stage, setStage] = useState<Stage>("form");
  const [error, setError] = useState<string | undefined>();
  const [savedHandle, setSavedHandle] = useState<CardHandle | undefined>();

  const brand = detectBrand(details.cardNumber);
  const busy = stage === "encrypting" || stage === "saving";
  const normalizedName = normalizeCardName(details.label);
  const last4 = lastFourDigits(details.cardNumber);

  function update<K extends keyof CardDetails>(key: K, value: CardDetails[K]) {
    setDetails((current) => ({ ...current, [key]: value }));
  }

  function validate(): string | undefined {
    if (!details.label.trim()) return "Give the card a name so you can find it later.";
    if (details.label.length > MAX_CARD_LABEL_LENGTH) {
      return `Card name must be ${MAX_CARD_LABEL_LENGTH} characters or fewer.`;
    }
    // Punctuation and spacing are stripped before the name is used, so a name
    // made only of them would leave nothing to derive from.
    if (!normalizedName) return "Card name must contain at least one letter or digit.";
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

  function handleReview(event: FormEvent) {
    event.preventDefault();
    const validationError = validate();
    if (validationError) {
      setError(validationError);
      return;
    }
    setError(undefined);
    setStage("confirm");
  }

  async function handleConfirmedSave() {
    setError(undefined);
    setStage("encrypting");
    try {
      // Everything secret happens inside the worker: it returns only the derived
      // identifier, ciphertext, the one-way verifier, and the salt.
      const request = await prepareCard(details, passkey);

      setStage("saving");
      await createCard(request);

      // The name and last four are kept for the hand-off to the unlock flow.
      // Everything genuinely sensitive — the full number, CVV, PIN, passkey —
      // goes now (LLD §8.2).
      setSavedHandle({ cardName: details.label.trim(), last4 });
      setDetails(EMPTY_DETAILS);
      setPasskey("");
      setConfirmPasskey("");
      setStage("done");
    } catch (caught) {
      setStage("form");
      setError(
        caught instanceof ApiError && caught.status === 409
          ? "A card with this name, last four digits, and passkey is already stored. Unlock it instead, or use a different name."
          : caught instanceof ApiError || caught instanceof Error
            ? caught.message
            : "Something went wrong while saving the card.",
      );
    }
  }

  function startAnother() {
    setSavedHandle(undefined);
    setStage("form");
    setError(undefined);
  }

  if (stage === "done" && savedHandle) {
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
          <strong>Remember these three things.</strong> They are not stored anywhere and they cannot
          be recovered. Together they are the only way back to this card — nothing else, including
          us, can find it.
        </div>

        <dl className="recall-list">
          <div className="recall-item">
            <dt>Card name</dt>
            <dd>{savedHandle.cardName}</dd>
          </div>
          <div className="recall-item">
            <dt>Last 4 digits</dt>
            <dd className="mono">{savedHandle.last4}</dd>
          </div>
          <div className="recall-item">
            <dt>Passkey</dt>
            <dd className="muted">The one you just chose</dd>
          </div>
        </dl>

        {error && <p className="error-text">{error}</p>}

        <div className="button-row">
          <button type="button" className="button" onClick={() => onUnlockCard(savedHandle)}>
            Unlock it now
          </button>
          <button type="button" className="button secondary" onClick={startAnother}>
            Store another card
          </button>
        </div>
      </section>
    );
  }

  if (stage === "confirm" || busy) {
    return (
      <section className="panel">
        <h2>Check this before it is encrypted</h2>
        <p className="lede">
          Stored cards cannot be edited or deleted. If anything here is wrong, go back now — after
          this, the only fix is storing the card again under a different name.
        </p>

        <div className="callout danger">
          <strong>You will need all three of these to get this card back.</strong> Nothing is written
          down for you, and there is no reset. Get one of them wrong later and the card is simply not
          found.
        </div>

        <dl className="recall-list">
          <div className="recall-item">
            <dt>Card name</dt>
            <dd>
              {details.label.trim()}{" "}
              <span className="muted">
                (matched as <code>{normalizedName}</code>)
              </span>
            </dd>
          </div>
          <div className="recall-item">
            <dt>Last 4 digits</dt>
            <dd className="mono">{last4}</dd>
          </div>
          <div className="recall-item">
            <dt>Passkey</dt>
            <dd className="muted">The one you just chose</dd>
          </div>
        </dl>

        <p className="field-hint">
          Spacing, capitals, and punctuation in the name do not matter — <code>{normalizedName}</code>{" "}
          is what has to match. The words themselves do.
        </p>

        {error && <p className="error-text">{error}</p>}

        <div className="button-row">
          <button
            type="button"
            className="button"
            onClick={() => void handleConfirmedSave()}
            disabled={busy}
          >
            {stage === "encrypting"
              ? "Encrypting in your browser…"
              : stage === "saving"
                ? "Storing ciphertext…"
                : "Encrypt and store"}
          </button>
          <button
            type="button"
            className="button secondary"
            onClick={() => setStage("form")}
            disabled={busy}
          >
            Back to edit
          </button>
        </div>
        {busy && (
          <p className="field-hint center">
            Key derivation is deliberately slow, and this runs it twice — once for the card's
            identifier and once for its encryption key. It takes a moment by design.
          </p>
        )}
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
        label={details.label}
      />

      <form onSubmit={handleReview} noValidate>
        <div className="field">
          <label className="field-label" htmlFor="card-label">
            Card name
          </label>
          <input
            id="card-label"
            className="input"
            value={details.label}
            onChange={(event) => update("label", event.target.value.slice(0, MAX_CARD_LABEL_LENGTH))}
            placeholder="HDFC Platinum"
            autoComplete="off"
            disabled={busy}
          />
          <p className="field-hint">
            {normalizedName ? (
              <>
                You will find this card again by its name, its last 4 digits, and your passkey. This
                one will be matched as <code>{normalizedName}</code>.
              </>
            ) : (
              "You will find this card again by its name, its last 4 digits, and your passkey — so pick something you will still say the same way in a year."
            )}
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
          hint="Never sent to the server. Never recoverable. It is what keeps this card unreachable, so make it a real one."
        />
        <PasskeyField
          label="Confirm passkey"
          value={confirmPasskey}
          onChange={setConfirmPasskey}
          disabled={busy}
        />

        {error && <p className="error-text">{error}</p>}

        <button type="submit" className="button full" disabled={busy}>
          Review and store
        </button>
      </form>
    </section>
  );
}
