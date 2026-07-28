import { useEffect, useState } from "react";

import { CreateCardFlow } from "./components/CreateCardFlow";
import { UnlockCardFlow } from "./components/UnlockCardFlow";
import { isUuidV4 } from "./cardUtils";

type Tab = "create" | "unlock";

/**
 * Reads `#/unlock/<card-identifier>` so a stored card can be reached by link.
 * The identifier is not a secret on its own — the passkey is what protects the
 * data (LLD §4.3) — but it is still only ever put in the fragment, which
 * browsers do not send to the server.
 */
function readIdentifierFromHash(): string | undefined {
  const match = /^#\/unlock\/([0-9a-fA-F-]{36})$/.exec(window.location.hash);
  return match && isUuidV4(match[1]) ? match[1] : undefined;
}

export function App() {
  const [tab, setTab] = useState<Tab>(() => (readIdentifierFromHash() ? "unlock" : "create"));
  const [identifierToUnlock, setIdentifierToUnlock] = useState<string | undefined>(
    readIdentifierFromHash,
  );

  useEffect(() => {
    function onHashChange() {
      const identifier = readIdentifierFromHash();
      if (identifier) {
        setIdentifierToUnlock(identifier);
        setTab("unlock");
      }
    }
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  function openUnlock(cardIdentifier: string) {
    setIdentifierToUnlock(cardIdentifier);
    setTab("unlock");
  }

  function switchTab(next: Tab) {
    setTab(next);
    if (next === "create") setIdentifierToUnlock(undefined);
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
          <UnlockCardFlow initialIdentifier={identifierToUnlock} />
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
