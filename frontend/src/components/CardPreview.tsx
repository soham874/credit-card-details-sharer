import { detectBrand, formatCardNumber } from "../cardUtils";

type Props = {
  cardNumber: string;
  holder: string;
  expiry: string;
  cvv: string;
  label: string;
  /** When false, the number and CVV are masked. */
  revealed?: boolean;
};

const PLACEHOLDER_NUMBER = "•••• •••• •••• ••••";

/**
 * Visual echo of what is being encrypted (or what was just decrypted). Purely a
 * rendering surface — it holds no state and keeps no copy of the values.
 */
export function CardPreview({ cardNumber, holder, expiry, cvv, label, revealed = true }: Props) {
  const brand = detectBrand(cardNumber);
  const formatted = formatCardNumber(cardNumber);

  return (
    <div className={`card-preview brand-${brand.id}`}>
      <div className="card-preview-top">
        {/* React escapes this; the label is untrusted user input (LLD §4.3). */}
        <span className="card-preview-label">{label || "Unnamed card"}</span>
        <span className="card-preview-brand">{brand.label}</span>
      </div>

      <div className="card-preview-chip" aria-hidden="true" />

      <div className="card-preview-number">
        {revealed ? formatted || PLACEHOLDER_NUMBER : PLACEHOLDER_NUMBER}
      </div>

      <div className="card-preview-bottom">
        <div>
          <span className="card-preview-caption">Cardholder</span>
          <span className="card-preview-value">{holder || "—"}</span>
        </div>
        <div>
          <span className="card-preview-caption">Expires</span>
          <span className="card-preview-value">{expiry || "••/••"}</span>
        </div>
        <div>
          <span className="card-preview-caption">CVV</span>
          <span className="card-preview-value">{revealed ? cvv || "•••" : "•••"}</span>
        </div>
      </div>
    </div>
  );
}
