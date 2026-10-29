# WASM ↔ native parity corpus

Generated; do not edit by hand. `tools/parity` builds every case from
`testdata/tokens/` and `testdata/keys/` (plus `testdata/rfc/rfc7515-jws.json`
and `testdata/iana/cwt.xml`) with fixed seeds and clocks, and writes the
native engine's output as the golden:

- `cases/<method>--<name>.json`: one Engine call, `{ method, source, stack?, args }`.
  Each arg is `{"bytes": <unpadded base64url>}` (a `Uint8Array` at the wasm
  boundary) or `{"json": <request DTO>}` (passed as JSON text).
- `expected/<id>.json`: the exact response envelope, `{"ok":…}` or `{"err":…}`.
- `expected/<id>.sha256`: `<sha256 hex> <length>` of the envelope, for
  goldens over 32 KiB.

Cases with `"stack": true` are the WASM stack audit (#27).

Regenerate after a deliberate core change with `pnpm parity:regen` in `app/`
(`cargo run --release -p parity -- regen`). Checks: `cargo test -p parity`
(native) and `pnpm test:parity` (the release wasm build). See
`crates/tokenator-wasm/TEST-PLAN.md` §3–4.
