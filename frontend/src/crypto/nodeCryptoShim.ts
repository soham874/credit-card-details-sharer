/**
 * Stands in for Node's `crypto` module inside the bundle.
 *
 * `tssrp6a`'s environment probe is `(typeof window !== "undefined" && window.crypto)`
 * and it falls back to `require("crypto").webcrypto` otherwise. That probe is
 * wrong for Web Workers: a worker has `self.crypto` but no `window`, so the
 * library takes the Node branch, gets Vite's "externalized for browser
 * compatibility" stub, and dies on `nodeCrypto.createHash is not a function`.
 *
 * Since all our SRP work runs in a worker (LLD §8.2), that is the only path
 * that matters. Aliasing `crypto` to this module hands the library the real
 * WebCrypto implementation in every environment — worker, main thread, and Node
 * under Vitest.
 */
const webcrypto: Crypto = globalThis.crypto;

if (!webcrypto?.subtle) {
  // Surfaces as a clear error rather than a confusing failure deep inside the
  // SRP routines. `crypto.subtle` is unavailable on insecure origins, which is
  // also why this app requires HTTPS outside localhost.
  throw new Error(
    "WebCrypto is unavailable. This app must be served over HTTPS (or localhost).",
  );
}

export { webcrypto };
export default { webcrypto };
