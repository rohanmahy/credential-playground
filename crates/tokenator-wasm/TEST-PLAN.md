# Web wiring test plan (tokenator-wasm, WasmEngine, parity, e2e)

This plan covers everything between `tokenator-core` and the browser:
the `tokenator-wasm` bindings, the real `WasmEngine` in `app/`, the
WASM ↔ native parity suite (SPEC §11), the stack audit (#27), and the
Playwright specs against the production web build, including the CSP
(SPEC §9). The Engine contract itself (DTOs, NodeIds, wire conventions)
is `crates/tokenator-core/TEST-PLAN.md`; the UI contract is
`app/TEST-PLAN.md`.

## Commands

| Command (in `app/`) | What |
|---|---|
| `pnpm build:wasm` | `wasm-pack build ../crates/tokenator-wasm --target web --profile wasm-release --no-opt --no-pack` → `crates/tokenator-wasm/pkg/` (gitignored) |
| `pnpm build:wasm:debug` | the same as a debug build (panic messages on the console; not size- or stack-audited) |
| `pnpm build`, `pnpm dev` | run `build:wasm` first, then Vite |
| `pnpm test:wasm` | `build:wasm`, then Vitest in Node on `src/test/wasm/` (`vitest.wasm.config.ts`) |
| `pnpm test:parity` | `build:wasm`, then only `src/test/wasm/parity.test.ts` |
| `pnpm parity:regen` | `cargo run --release -p parity -- regen`: rebuilds `testdata/parity/` from the native engine |
| `pnpm parity:check` | the same check natively, without writing |
| `pnpm test:e2e` | Playwright against `vite preview` of `pnpm build` (no longer gated by `TOKENATOR_E2E`) |
| `cargo test -p parity` | native half of parity |
| `cargo test -p tokenator-wasm` | the binding layer compiled natively, replaying the corpus |

`pnpm test` (the unit suite) does not need the Rust toolchain: when
`pkg/` is missing, Vite resolves `tokenator-wasm` to
`src/lib/engine/wasm-missing.ts`, whose `init()` fails. Outside Vitest a
missing `pkg/` is a build error, so a production bundle can never ship
the stand-in (`vite.config.ts`).

## 1. tokenator-wasm

**Surface.** One class, `TokenatorEngine`, with one method per Engine
method under the core's snake_case name (`info`, `detect`, `open`,
`render`, `parse_edit`, …, `registry_merge`: 27), plus the hidden test hook
`panic_for_tests(message)`. `app/src/lib/engine/tokenator-wasm.d.ts`
declares the same surface for type-checking without the build.

- Requests cross as **JSON text** in the core wire format; raw
  `detect`/`open` input crosses as a **`Uint8Array`** (#34 item 2).
- Every method returns a **JSON envelope string** and never throws for an
  engine error: `{"ok":<DTO>}` or `{"err":{"code","message","node_id"}}`,
  compact `serde_json` output. A request that does not deserialize is
  `{"err":{"code":"invalid_input",…}}`.
- `new TokenatorEngine(snapshot?)`: `Engine::new()`, or
  `Engine::with_registry_snapshot(snapshot)`; an unreadable snapshot
  throws the `{"err":…}` envelope text (a JS string, code `registry`).
  `TokenatorEngine::create(Option<&[u8]>) -> Result<_, String>` is the
  same, callable natively.
- No logic beyond (de)serialization and error mapping. Runtime
  dependencies: `wasm-bindgen`, `serde_json`, `console_error_panic_hook`.
  No `getrandom`, no `js-sys`: randomness and time arrive in requests.

**Why JSON text, not serde-wasm-bindgen.** Parity compares serialized
output byte for byte. With JSON text both targets run the same
`serde_json` serializer and the wasm output *is* the comparable string.
serde-wasm-bindgen would build JS objects whose `i64`/`u64` handling
(BigInt vs number), map types, and key order depend on its settings, so
the check would compare a JS re-serialization instead. `JSON.parse` on
the JS side is native and fast at token sizes.

**Panics** never cross silently. The release profile has
`panic = "abort"`: a panic is a wasm trap, thrown in JS as
`WebAssembly.RuntimeError`, which `WasmEngine` maps to an
`EngineFailure` with code `internal`. Debug builds also install
`console_error_panic_hook` (in the `#[wasm_bindgen(start)]` function).
After a trap the same `TokenatorEngine` keeps answering (shared borrows
are not poisoned); the shadow-stack space of the trapped frames is not
reclaimed, which the "repeated panics" test bounds.

**Stack (#27).** `build.rs` passes `-zstack-size=2097152` (2 MiB, twice
the rustc default) to the cdylib link on wasm32 only. The binary test
reads `__stack_pointer`'s initial value back from the module (rustc puts
the stack first, so it equals the stack size) and compares it with
`STACK_SIZE` in `build.rs`.

**Size.** Profile `wasm-release` (root `Cargo.toml`): `opt-level = "s"`,
`lto = true`, `codegen-units = 1`, `panic = "abort"`, debuginfo
stripped. `wasm-opt` is off: wasm-pack would download binaryen during the
build, and parity checks the artifact rustc and wasm-bindgen produce. A
probe build of the full binding measured **2.90 MB raw, 0.89 MB gzip**
(`opt-level = "z"`: 2.81 MB / 0.84 MB, slower; `3`: 4.01 MB / 1.17 MB).
Budget, enforced by `binary.test.ts` (which prints the size): ≤ 3.5 MiB
raw, ≤ 1.1 MiB gzip.

| Test | File | Count |
|---|---|---|
| Every parity case through the binding (native build) matches its golden; envelope shape; `invalid_input` for malformed requests (bad JSON, wrong shape/type, unknown tag, bad base64url, bad candidate/view); `parse_edit`/lookups answer `ok`; bad snapshot → `registry`; a merged snapshot is used | `crates/tokenator-wasm/tests/native.rs` | 6 |
| Stack size from `build.rs`; imports only from the wasm-bindgen glue, none for randomness, clock, or network; size budget; exported methods = Engine methods + hook = `.d.ts`; envelope strings; constructor throws the envelope; a panic throws `RuntimeError` and the object keeps working | `app/src/test/wasm/binary.test.ts` | 7 |
| `vite build` emits the release `.wasm` byte for byte as a same-origin asset, does not bundle the stand-in, and keeps `'wasm-unsafe-eval'` without `'unsafe-eval'` | `app/src/test/wasm/build.test.ts` | 3 |

## 2. WasmEngine

`app/src/lib/engine/WasmEngine.ts`; tests in
`app/src/test/wasm/engine.test.ts` run the real release module in Node,
passing its bytes as `WasmEngine.load(snapshot, { wasm })`.

- `load(snapshot = null, options = {})` resolves at once. The module
  (`import('tokenator-wasm')`, then `init({ module_or_path: options.wasm })`)
  is instantiated lazily on the first call, once, shared by concurrent
  calls; then `new TokenatorEngine(snapshot)` (so
  `Engine::with_registry_snapshot` when a snapshot is given).
- Each method calls the binding of the same snake_case name with
  `JSON.stringify(req)` (raw input as the `Uint8Array` itself, honouring
  `byteOffset`) and parses the envelope: `ok` resolves (`keyToJwk`
  resolves the JWK *text*), `err` rejects with `new EngineFailure(err)`.
- Every other failure rejects with an `EngineFailure` too: module load
  failure and traps get code `internal` (message mentions the panic or
  trap); the constructor's envelope keeps its code (`registry`).
- `panicForTests(message)` calls the hook (test-only).

| Area | Tests |
|---|---|
| Loading: lazy (bad bytes → `load()` resolves, first call `internal`); concurrent first calls; `info()` | 3 |
| Every parity case through the TS method (camelCase of the core name): `ok` deep-equals the golden DTO, `err` rejects with `EngineFailure` whose `error` deep-equals the golden; digest goldens resolve | 476 |
| Raw input views (`subarray`); omitted defaulted fields; malformed request → `invalid_input`; fresh result objects; `keyToJwk` returns text | 5 |
| Snapshot: `load(snapshot)` from `registryMerge` (patched `<updated>` date shows in `info()`); all four IANA registries merged in turn; unreadable snapshot → `registry` | 3 |
| Panics: `internal`, engine keeps answering; 20 panics then a max-depth render still succeeds | 2 |

## 3. Parity suite (SPEC §11)

**Corpus.** `tools/parity` builds it from `testdata/tokens/` and
`testdata/keys/` (plus `testdata/rfc/rfc7515-jws.json` keys and
`testdata/iana/cwt.xml`): **476 cases covering all 27 methods**, 38 of them
error envelopes. Seeds are `[n; 32]` and clocks are constants. Requests
that need an earlier result (a `Candidate`, an issued document) are
computed natively when the corpus is built, so each stored case is
self-contained:

- `testdata/parity/cases/<method>--<name>.json`:
  `{ method, source, stack?, args }`, each arg `{"bytes": <base64url>}`
  (a `Uint8Array` at the boundary) or `{"json": <request DTO>}` (passed as
  `JSON.stringify`). The builder refuses numbers JavaScript cannot
  represent exactly.
- `testdata/parity/expected/<id>.json`: the exact envelope text from the
  native engine. Goldens over 32 KiB (max-depth documents, the registry
  snapshot; 37 cases) are `expected/<id>.sha256` holding
  `<sha256 hex> <length>` instead.

| Methods | Cases |
|---|---|
| `detect` | every token and key fixture, plus wrapped inputs (Bearer, Authorization header, quotes, JSON container, URL-encoded, base64url, hex with colons, empty, garbage) |
| `open` | the top candidate of every token fixture that detects, the wrapped inputs, a mismatched candidate |
| `render`, `parse_edit` | view options (compact, indent, no decoded views, no annotations, base64 bytes, `dt''` + `now`, hide/manual decode, pretty JSON); claim sets; edits that keep, change, re-indicate, or break the text |
| `issue`, `redact`, `disclose`, `present` | JWT ES256/RS256/PS256, SD-JWT (cnf, decoys, compact/flattened/general, SHA-512), CWT ES256/EdDSA with tag 61, SD-CWT from Figure 4 and from tags 58; SD-JWT+KB, SD-KBT, plain CWT in an SD-KBT; randomness/alg/cnf/nothing-to-redact/already-presented errors |
| `validate`, `lint` | every family with and without keys, expired, wrong aud, HS256, `alg: none`, decoys, recursive disclosures, nested SD-KBT; lint on fixtures and on non-preferred CBOR, indefinite lengths, NaN, duplicate JSON keys |
| `resign`, `tamper`, `reencode`, `edit_disclosures`, `decode_embedded` | edited JWT/CWT; every tamper op; layers, tags, preferred-plus, deterministic `deep`, JOSE serializations; every disclosure op (and COSE `add_decoy` → `unsupported`); manual decode ok/not CBOR/not bytes/not found |
| `key_*` | import of every key fixture (unsupported ones are error goldens) and EDN COSE_Key; generate every spec seeded, well-known, entropy, kid sources; export in every format; public; thumbprints; kid; JWK/CWK conversions |
| `datetime`, `registry_lookup`, `registry_merge`, `info` | every input form; lookups by name/label/prefix/kind; merging `cwt.xml`; bad XML |

**Checks.**

- Native (`cargo test -p parity`, 5 tests; pass now): the committed cases
  are exactly what the builder makes; the native engine reproduces every
  golden; every method has a successful case and ≥ 20 errors exist; every
  token fixture is detected and opened; the stack audit is complete.
- WASM (`src/test/wasm/parity.test.ts`, 477 tests): every case through
  the release module's bindings returns the golden text byte for byte (or
  its SHA-256 and length); the corpus covers every method.
- `pnpm parity:regen` rewrites `cases/` and `expected/` from scratch
  after a deliberate core change; review the diff like any golden update.

## 4. Stack audit (#27)

Corpus cases tagged `"stack": true` (22; the 16 core ones are required by
`the_stack_audit_covers_issue_27`) run in the release wasm build under
the 2 MiB stack and must neither trap nor differ from native:

- CBOR at `MAX_DEPTH` (512): nested maps and arrays through `detect`,
  `render`, and `lint`; one level deeper is a `parse` error, not a trap.
- EDN at `MAX_DEPTH`: `detect` (EDN confirmation), `render`,
  `parse_edit`; a CWT issued with a payload nested to `MAX_DEPTH - 8`,
  then validated (signature passes).
- A chain of 120 nested SD-JWT disclosures (every level of a 120-deep
  object marked; tokenator-json's claim-set depth limit is 128): `issue`,
  `validate`, `disclose`.
- ML-DSA-87: seeded `key_generate`, `issue` (JOSE and COSE), `validate`
  (signature passes).

## 5. End-to-end (Playwright)

Against `vite preview --host 127.0.0.1 --port 4173` of `pnpm build`
(real `WasmEngine`), Chromium. Binary fixtures are pasted as hex.

| Spec | Tests |
|---|---|
| `paste-validate`: 11 families (JWT, JWS JSON, SD-JWT, SD-JWT+KB, SD-JWT+KB JSON, CWT hex, tag 61, COSE_Sign1, SD-CWT, SD-KBT, nested SD-KBT) → detected type, main and raw pane, report; Authorization header layers; JWT and SD-JWT+KB with their published keys (signature passes); no key → `skip`; JSON/EDN/CBOR claim sets open with Validate disabled; a pasted key goes to the panel | 19 |
| `issue-present`: SD-JWT issue → present → validate; SD-CWT redact → SD-KBT → validate; plain JWT; CWT from EDN → SD-KBT; ML-DSA-87 JWT | 5 |
| `keys`: create → convert → export private (confirmation); nothing stored; import JWK → derive public → kid = JWK thumbprint; every Create key algorithm (incl. RSA 2048, ML-DSA-87) generates; public JWK export without confirmation | 5 |
| `tree-sync`: COSE collapse main → raw, expand raw → main, keyboard folding in the raw pane, selection both ways, fold state survives a re-render; JOSE collapse part → segment, claim selection marks base64url characters that decode to the claim | 8 |
| `network`: the full flows request nothing outside the app origin (route guard aborts and records anything else; the `.wasm` is loaded from the origin); a key URL is not fetched before confirmation; Update registries fetches exactly the four `www.iana.org` URLs, only after confirmation (fulfilled from `testdata/iana`) | 3 |
| `csp`: the served meta CSP has `script-src 'self' 'wasm-unsafe-eval'`, no `'unsafe-eval'`, `connect-src 'self' https:`; the engine runs without violations; inline script and string eval are blocked (checked with code the page compiles, since `page.evaluate` is exempt); `http:` and `ws:` connections are refused by the CSP | 4 |

**CSP decisions.** `connect-src 'self' https:` is exactly what
user-confirmed fetches need: `https:` covers `https://www.iana.org`
(Update registries) and arbitrary key URLs (`kid`, jwt-vc-issuer
metadata), the SPEC §9 tradeoff. Nothing else is allowed (no `http:`,
`ws:`, `data:`, `blob:`); `src/test/scaffold/csp.test.ts` pins the
directive at build time, `e2e/csp.spec.ts` in the browser.

## Status

Native parity (5) passes; the unit suite (165) passes. Against the stubs,
`cargo test -p tokenator-wasm` fails 6/6; `pnpm test:wasm` fails 969 of
976 (the 7 passing check the corpus, the binary's stack size, imports,
size, and surface, and two build properties that also hold for the stub);
`pnpm test:e2e` fails 40 of 44 (the 4 passing need no engine: the served
CSP, inline/eval blocking, refused connections, the key URL
confirmation). Every failure is a stub: `unimplemented!()` traps in the
bindings, or `NotImplemented` from `WasmEngine`.

## Decisions (issues filed)

- #37: the binding and build choices: JSON text with an `ok`/`err`
  envelope (not serde-wasm-bindgen), `Uint8Array` raw input (#34 item 2),
  `internal` for traps and load failures, panics as traps with the
  instance kept, the 2 MiB stack, `opt-level = "s"` without wasm-opt and
  the size budget, digest goldens over 32 KiB, `pkg/` behind a Vite alias
  with a unit-test stand-in, e2e no longer gated, and
  `connect-src 'self' https:`.
- #38: `ErrorCode` has no code for binding-level failures; the app uses
  `'internal'` with a cast until core adds one.
