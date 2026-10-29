// The Content-Security-Policy of the web build (SPEC §9). It is injected into
// the built index.html only; the dev server needs inline HMR and websockets.
//
// - script-src: our own origin only. 'wasm-unsafe-eval' lets the page compile
//   the tokenator-wasm module; it does not allow eval() of JavaScript.
// - connect-src: any https URL, because key URLs (kid, jwt-vc-issuer
//   metadata) are arbitrary. Every fetch is user-confirmed (app/ARCHITECTURE.md).
// - style-src 'unsafe-inline': CodeMirror injects its theme styles.
// frame-ancestors and sandbox are ignored in a <meta> CSP; GitHub Pages cannot
// send headers, and the Tauri CSP lives in src-tauri/tauri.conf.json.
export const CSP_DIRECTIVES: Readonly<Record<string, readonly string[]>> = {
  'default-src': ["'self'"],
  'script-src': ["'self'", "'wasm-unsafe-eval'"],
  'style-src': ["'self'", "'unsafe-inline'"],
  'img-src': ["'self'", 'data:'],
  'font-src': ["'self'"],
  'connect-src': ["'self'", 'https:'],
  'worker-src': ["'self'"],
  'object-src': ["'none'"],
  'base-uri': ["'none'"],
  'form-action': ["'none'"],
};

export function cspString(directives = CSP_DIRECTIVES): string {
  return Object.entries(directives)
    .map(([name, values]) => `${name} ${values.join(' ')}`)
    .join('; ');
}
