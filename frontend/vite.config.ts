/// <reference types="vitest/config" />
import { fileURLToPath } from "node:url";

import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

/**
 * `tssrp6a` probes for `window.crypto` and falls back to `require("crypto")`.
 * Web Workers have no `window`, so the SRP code takes the Node branch and hits
 * Vite's externalized stub. The shim hands it real WebCrypto instead — see
 * src/crypto/nodeCryptoShim.ts.
 */
const nodeCryptoShim = fileURLToPath(new URL("./src/crypto/nodeCryptoShim.ts", import.meta.url));

/**
 * Strict CSP for production builds (LLD §8.2): no `unsafe-inline`, no
 * `unsafe-eval`, no wildcard `script-src`. It is injected only on `vite build`
 * because the dev server relies on inline scripts for HMR — shipping a CSP that
 * had to be loosened for dev would defeat the point.
 *
 * A `<meta>` tag cannot express `frame-ancestors`, so the static host must also
 * send this as a response header. Treat what follows as the source of truth for
 * that header.
 */
function strictCsp(apiOrigin: string): Plugin {
  const policy = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    `connect-src 'self' ${apiOrigin}`.trim(),
    "worker-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests",
  ].join("; ");

  return {
    name: "inject-strict-csp",
    apply: "build",
    transformIndexHtml(html) {
      return html.replace(
        "</head>",
        `  <meta http-equiv="Content-Security-Policy" content="${policy}" />\n  </head>`,
      );
    },
  };
}

/**
 * LLD §8.1 requires the SPA and the API to live on separate origins in any real
 * deployment. That is a security boundary, so it is not something to "fix" by
 * relaxing it — instead, set `VITE_API_BASE_URL` to the API's own origin at
 * build time and give the backend a CORS allowlist containing exactly this
 * frontend's origin.
 *
 * The dev proxy below exists only so local work does not need the backend
 * reconfigured; it is not the deployment model.
 */
export default defineConfig(({ command }) => {
  const backendUrl = process.env.BACKEND_URL ?? "http://localhost:8080";
  // Same-origin ('/api') needs nothing extra in connect-src beyond 'self'.
  const apiBaseUrl = process.env.VITE_API_BASE_URL ?? "";
  const apiOrigin = apiBaseUrl.startsWith("http") ? new URL(apiBaseUrl).origin : "";

  /**
   * An unset `VITE_API_BASE_URL` does not fail anything on its own — it ships a
   * bundle that is broken in two ways at once, both silent:
   *
   *   1. `cardApi.ts` reads `import.meta.env.VITE_API_BASE_URL ?? "/api"`, and
   *      GitHub Actions substitutes the empty string for an unset repository
   *      variable. `"" ?? "/api"` is `""`, not `"/api"`, so `??` never catches
   *      the one case it exists for. Requests become relative and resolve
   *      against the Pages origin — `POST https://<user>.github.io/create`,
   *      which a static host answers with 405.
   *   2. `apiOrigin` is empty, so the CSP above collapses to
   *      `connect-src 'self'` and would block the API even at the right URL.
   *
   * Both only surface in a browser, in production. LLD §8.1 makes the separate
   * API origin a requirement rather than a preference, so a build without one
   * is broken by construction — fail here instead of shipping it.
   */
  if (command === "build" && !apiOrigin) {
    throw new Error(
      "VITE_API_BASE_URL must be an absolute http(s) origin for a production build " +
        `(got ${JSON.stringify(apiBaseUrl)}). Set the repository variable under ` +
        "Settings -> Secrets and variables -> Actions -> Variables.",
    );
  }

  /**
   * A GitHub Pages *project* site is served from `/<repo>/`, not from the domain
   * root, so every asset URL has to carry that prefix. Kept as an env var rather
   * than hardcoded so local dev, `vite preview`, and a future custom domain all
   * keep the default `/`.
   */
  const base = process.env.BASE_PATH ?? "/";

  return {
    base,
    plugins: [react(), strictCsp(apiOrigin)],
    resolve: {
      alias: { crypto: nodeCryptoShim },
    },
    server: {
      port: 5173,
      proxy: {
        "/api": {
          target: backendUrl,
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api/, ""),
        },
      },
    },
    test: {
      environment: "node",
      include: ["src/**/*.test.ts"],
    },
  };
});
