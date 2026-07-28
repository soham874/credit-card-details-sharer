import { useId, useState } from "react";

import { ratePasskey } from "../cardUtils";

type Props = {
  label: string;
  value: string;
  onChange: (value: string) => void;
  /** Renders the strength meter and enforcement hint. Creation only. */
  showStrength?: boolean;
  autoFocus?: boolean;
  disabled?: boolean;
  hint?: string;
};

/**
 * Passkey input. Per LLD §8.2 it must never be autofilled, autocompleted, spell
 * checked, or persisted — the value lives in React state only until it is
 * handed to the crypto worker, then it is cleared.
 */
export function PasskeyField({
  label,
  value,
  onChange,
  showStrength = false,
  autoFocus = false,
  disabled = false,
  hint,
}: Props) {
  const inputId = useId();
  const [revealed, setRevealed] = useState(false);
  const strength = showStrength ? ratePasskey(value) : undefined;

  return (
    <div className="field">
      <label className="field-label" htmlFor={inputId}>
        {label}
      </label>
      <div className="passkey-input">
        <input
          id={inputId}
          className="input"
          type={revealed ? "text" : "password"}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="off"
          spellCheck={false}
          autoFocus={autoFocus}
          disabled={disabled}
          // Keeps password managers from offering to save it (LLD §8.2).
          data-lpignore="true"
          data-1p-ignore="true"
        />
        <button
          type="button"
          className="reveal-button"
          onClick={() => setRevealed((current) => !current)}
          aria-label={revealed ? "Hide passkey" : "Show passkey"}
          disabled={disabled}
        >
          {revealed ? "Hide" : "Show"}
        </button>
      </div>

      {strength && value.length > 0 && (
        <div className="strength">
          {/* Discrete classes rather than an inline width, so the production CSP
              can forbid inline styles outright. */}
          <div className={`strength-meter strength-${strength.score}`} aria-hidden="true">
            <span />
            <span />
            <span />
            <span />
          </div>
          <span className="strength-label">{strength.label}</span>
        </div>
      )}
      {strength?.hint && <p className="field-hint warn">{strength.hint}</p>}
      {hint && <p className="field-hint">{hint}</p>}
    </div>
  );
}
