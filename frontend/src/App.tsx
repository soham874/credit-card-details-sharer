import { useState } from "react";

import { CreateCardFlow } from "./components/CreateCardFlow";
import { UnlockCardFlow } from "./components/UnlockCardFlow";

type Tab = "create" | "unlock";

type CardHandle = { cardName: string; last4: string };

/**
 * There is deliberately no `#/unlock/<identifier>` deep link any more.
 *
 * Identifiers are derived from the passkey now, which makes a leaked one an
 * offline oracle for guessing that passkey — no server, no rate limit, unlimited
 * attempts. A link would put exactly that into browser history and into whatever
 * the link was pasted into. It would also be pointless: the identifier is
 * recomputed from what the user knows, so there is nothing to link to.
 */
export function App() {
  const [tab, setTab] = useState<Tab>("create");
  const [handleToUnlock, setHandleToUnlock] = useState<CardHandle | undefined>();

  function openUnlock(handle: CardHandle) {
    setHandleToUnlock(handle);
    setTab("unlock");
  }

  function switchTab(next: Tab) {
    setTab(next);
    if (next === "create") setHandleToUnlock(undefined);
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            🔐
          </span>
          <div>
            <h1>Card Vault</h1>
            <p className="tagline">Encrypted in your browser. The server never sees the card.</p>
          </div>
        </div>

        <nav className="tabs" aria-label="Flows">
          <button
            type="button"
            className={`tab ${tab === "create" ? "active" : ""}`}
            onClick={() => switchTab("create")}
            aria-current={tab === "create"}
          >
            Store a card
          </button>
          <button
            type="button"
            className={`tab ${tab === "unlock" ? "active" : ""}`}
            onClick={() => switchTab("unlock")}
            aria-current={tab === "unlock"}
          >
            Unlock a card
          </button>
        </nav>
      </header>

      <main>
        {tab === "create" ? (
          <CreateCardFlow onUnlockCard={openUnlock} />
        ) : (
          <UnlockCardFlow initialHandle={handleToUnlock} />
        )}
      </main>

      <footer className="app-footer">
        <p>
          Card data is encrypted with AES-256-GCM under a key derived from your passkey. Possession
          of the passkey is proved to the server with SRP-6a, so the passkey itself is never
          transmitted and the server cannot derive it.
        </p>
        <p className="muted">
          Sharing a card with a third party is specified in the design docs but not yet available —
          the backend does not implement those endpoints.
        </p>
      </footer>
    </div>
  );
}
