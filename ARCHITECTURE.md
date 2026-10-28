# The Tokenator — Architecture

## Overview

```
┌──────────────────────── app/ (Svelte + TypeScript) ────────────────────────┐
│  UI components ── stores (workspace, keys, tabs) ── Engine + Platform (TS)  │
│                                        │                 │                 │
│                     ┌──────────────────┴───┐   ┌─────────┴──────────┐      │
│                     │ WasmEngine / WebPlat │   │ TauriEngine / Plat │      │
└─────────────────────┼──────────────────────┼───┼────────────────────┼──────┘
                      │ wasm-bindgen          │   │ tauri invoke()     │
               tokenator-wasm                 │   app/src-tauri (commands,
                      │                       │   fs, clipboard, reqwest)
                      └───────────┬───────────┘           │
                                  ▼                       ▼
                        tokenator-core (Engine facade, DTOs, no I/O)
        ┌──────────┬──────────┬───────┴──┬───────────┬───────────┬──────────┐
     detect     tokens      keys      registry      edn        json-span
                  │  └─ jose, cose ─┐    │            │
                  └──────── crypto ─┴────┘           cbor
```

The design splits along two seams:

1. **Engine (pure) vs Platform (I/O).** The Rust core never does I/O: no
   network, no files, no clock, no RNG source it picks itself. Time and
   randomness come in as parameters (with a seed option for deterministic keys
   and salts). Fetching, files, and the clipboard belong to the TS `Platform`
   interface, implemented by browser APIs on the web and by Tauri commands on
   the desktop.
2. **WASM vs native.** The same `tokenator-core` API is exposed twice, by
   `tokenator-wasm` (wasm-bindgen) and by the Tauri commands. Both are thin
   serde wrappers. TS types are generated once from the core DTOs with `ts-rs`,
   so both TS implementations share the same types, and a parity test suite
   keeps their behavior identical.

## Repository layout

```
Cargo.toml                 workspace
crates/
  tokenator-cbor/          span-preserving, zero-copy CBOR decode/encode
  tokenator-edn/           EDN parser + printer (with span maps)
  tokenator-json/          span-preserving JSON parse (order and bytes kept)
  tokenator-crypto/        Signer/Verifier over RustCrypto; alg registry
  tokenator-keys/          key model; PEM/JWK/COSE_Key; thumbprints; keygen
  tokenator-jose/          JWS compact/JSON, SD-JWT, KB-JWT
  tokenator-cose/          COSE_Sign1, CWT, SD-CWT, SD-KBT (behind trait)
  tokenator-registry/      claim/header DB; build-time snapshot; IANA parser
  tokenator-detect/        unwrapping chain + classification
  tokenator-core/          Engine facade, DTOs, document model, actions
  tokenator-wasm/          wasm-bindgen bindings
  (tokenator-cli/)         future
app/
  src/                     Svelte UI
  src/lib/engine/          Engine interface, WasmEngine, TauriEngine
  src/lib/platform/        Platform interface, WebPlatform, TauriPlatform
  src-tauri/               Tauri shell + commands
tools/registry-gen/        build-time IANA → snapshot generator
testdata/                  vectors (RFCs, drafts, cbor-test-vectors), parity corpus
fuzz/                      cargo-fuzz targets
```

## Components

### tokenator-cbor
A zero-copy decoder that produces `Item<'a>` trees borrowing from the input,
where every item carries `Span { start, end, head_len }`. It records the
encoding details needed for an exact round trip: argument width, indefinite
length, and the chunks of an indefinite-length string. The encoder preserves
those details by default. It can also emit preferred-plus or deterministic
serialization (draft-ietf-cbor-serialization-11 §4 and §5), and it checks
whether an item conforms to either. Nesting is limited to `MAX_DEPTH = 512`.

```rust
pub fn decode(bytes: &[u8]) -> Result<Item<'_>, DecodeError>;      // single item; trailing bytes are an error
pub fn decode_seq(bytes: &[u8]) -> Result<Vec<Item<'_>>, DecodeError>;
pub fn encode(item: &Item, mode: EncodeMode) -> Result<Vec<u8>, EncodeError>; // Preserve | PreferredPlus | Deterministic; Err on invalid simple values
pub fn duplicate_keys(item: &Item) -> Vec<DuplicateKey>;          // detection only; the linter warns
pub enum Value<'a> { Uint(u64), Nint(u64), Bytes(Cow<'a,[u8]>), Text(Cow<'a,str>),
                     Array(Vec<Item<'a>>), Map(Vec<(Item<'a>, Item<'a>)>),
                     Tag(u64, Box<Item<'a>>), Simple(u8), Float(f64, FloatWidth), ... }
```
Maps are kept as ordered vectors **in arrival order**, so duplicate keys are
preserved and linted rather than rejected. `EncodeMode::Preserve`,
`PreferredPlus`, and the EDN printer emit map entries in that order. Only
`Deterministic` re-sorts.
Unknown simple values and tags are kept as-is, which covers SD-CWT's custom
simple value.

```rust
pub fn preferred_findings(item: &Item) -> Vec<EncodingFinding>; // non-preferred args/floats/indefinite, with span + preferred bytes
pub fn deterministic_findings(item: &Item) -> Vec<EncodingFinding>; // adds map key order
```

### tokenator-edn
`parse(&str) -> Result<Item<'static>, EdnError>` and
`print(&Item, &PrintOptions) -> Rendered`. `Rendered` contains the text plus a
`SpanMap` (NodeId → text range and line range). The printer takes a
`&dyn Annotator` (the registry) for `/ comment /` annotations.
Application-extensions are a trait with built-ins for h, b64, dt, ip, and hash.

### tokenator-json
A small JSON parser that keeps member order as it arrived, duplicate keys,
number lexemes, and the byte range of every node. The printer never sorts. It's needed because the JOSE raw pane and the
tree must point into the exact decoded JSON bytes, which serde_json's `Value`
can't do. Printing reuses the original bytes when a node is unedited.

### tokenator-crypto
```rust
pub enum Alg { ES256, ES384, ES512, EdDSA, Ed25519, RS256, RS384, RS512,
               PS256, PS384, PS512, MlDsa44, MlDsa65, MlDsa87 }
pub fn sign(alg: Alg, key: &PrivateKey, msg: &[u8], rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, CryptoError>;
pub fn verify(alg: Alg, key: &PublicKey, msg: &[u8], sig: &[u8]) -> Result<(), CryptoError>;
pub fn digest(h: HashAlg, data: &[u8]) -> Vec<u8>;

// Key requirements, consumed by the linter and by keys/validation
pub struct KeyRequirements { jwk_kty: &'static str, cose_kty: i64,
                             crv: Option<Curve>,           // JWK name + COSE label
                             akp_param_set: Option<MlDsaParams>,
                             min_rsa_bits: Option<u32> }
pub fn requirements(alg: Alg) -> KeyRequirements;
pub fn algs_for_key(params: &KeyParams) -> Vec<Alg>;      // which algs this key may use
pub fn check_key(alg: Alg, params: &KeyParams) -> Vec<KeyMismatch>; // kty/crv/size/alg-field mismatches
pub fn alg_from_jose(name: &str) -> Option<Alg>;  pub fn alg_from_cose(label: i64) -> Option<Alg>;
```
`KeyParams` is a format-neutral description of a key (kty, crv, RSA bits,
ML-DSA set, and an optional declared `alg`). `tokenator-keys` produces one from
a JWK or CWK without needing key material. That's how the linter checks `cnf`
keys and key cards.
Backends: `p256`/`p384`/`p521`/`ecdsa`, `ed25519-dalek`, `rsa`, `ml-dsa`, and
`sha2`, all pure Rust. These are the only crates that touch key material.

### tokenator-keys
A `Key` model (private or public, by key type) with a role and metadata, kept
separate from the formats.
```rust
pub fn import(input: &[u8], hint: Option<KeyFormat>) -> Result<Vec<Key>, KeyError>; // sets → many
pub fn export(key: &Key, fmt: KeyFormat, visibility: Visibility) -> Result<Vec<u8>, KeyError>;
pub fn to_public(key: &Key) -> Key;
pub fn to_jwk(key: &Key, visibility: Visibility) -> Result<Jwk, KeyError>;   // structured; serialize separately
pub fn to_cwk(key: &Key, visibility: Visibility) -> Result<CoseKey, KeyError>; // COSE_Key as cbor Item
pub fn from_jwk(jwk: &Jwk) -> Result<Key, KeyError>;  pub fn from_cwk(cwk: &CoseKey) -> Result<Key, KeyError>;
pub fn params(key: &Key) -> KeyParams;               // for tokenator-crypto::check_key
pub fn generate(spec: KeySpec, seed: Option<&[u8]>) -> Result<Key, KeyError>;
pub fn thumbprint(key: &Key, kind: ThumbprintKind, h: HashAlg) -> Vec<u8>;    // Jwk | Cose
```

### tokenator-jose / tokenator-cose
Format logic for parse, build, sign, verify, SD digest computation, and
disclosure matching. Each returns a structured model **plus** references to the
original byte ranges.

`tokenator-cose` puts its COSE_Sign1 handling behind a `Sign1Backend` trait
(`parse`, `sig_structure`, `build`). The span-preserving implementation built on
`tokenator-cbor` is the default. Because of this seam, a `coset`/`esdicawt`
backend could be swapped in for signing and validation without touching the
display model. Displays always come from `tokenator-cbor`.

### tokenator-registry
A `Registry` with lookups by JOSE name, COSE label, and CWT claim key, holding
the description, spec reference, and value type. The bundled snapshot is
generated by `tools/registry-gen` from the IANA XML and embedded with
`include_bytes!`. `Registry::merge_iana(xml: &[u8], which: RegistryId)` parses
a refreshed fetch, which `Platform` performs and caches.

### tokenator-detect
`detect(input: &[u8]) -> Vec<Candidate>`, where each candidate has
`{ layers: Vec<Layer>, kind, confidence, payload_range }`. A `Layer` records
each unwrapping step (`BearerPrefix`, `JsonField(path)`, `Base64Url`, `Hex`,
`CborTag(61)`, …), so the UI can show the breadcrumb and Re-encode can rebuild
any of the outer layers.

### tokenator-core: the Engine facade
**Stateless.** The UI holds the bytes, and each call re-parses them. Tokens are
small, so this is cheap. It also avoids leaking wasm-bindgen handles and makes
parity trivial to test. Keys cross the boundary as serialized key bytes
(JWK/COSE_Key) inside DTOs.

```rust
// all args/returns are serde DTOs exported to TS via ts-rs
fn detect(input: Bytes) -> Vec<Candidate>;
fn open(input: Bytes, choice: CandidateRef, opts: ViewOptions) -> Document;
fn render(doc_bytes: Bytes, kind: Kind, opts: ViewOptions) -> Document;     // re-render
fn parse_edit(kind: Kind, text: String) -> EditResult;                      // live edit → bytes + diagnostics
fn issue(req: IssueRequest) -> Document;           // claims text, header opts, issuer key, sd marks, decoys, salts seed?
fn redact(req: RedactRequest) -> Document;         // tagged EDN / marked JSON → SD form
fn disclose(doc: Bytes, kind: Kind, keep: Vec<DisclosureId>) -> Document;
fn present(req: PresentRequest) -> Document;       // keep, holder key, aud, nonce, iat
fn validate(req: ValidateRequest) -> ValidationReport; // keys, now, skew, expectations
fn resign(doc: Bytes, kind: Kind, key: KeyBytes, rng_seed: Option<Bytes>) -> Document;
fn tamper(doc: Bytes, kind: Kind, op: TamperOp) -> Document;
fn reencode(doc: Bytes, layers: Vec<Layer>) -> Bytes;
fn edit_disclosures(doc: Bytes, kind: Kind, ops: Vec<DisclosureOp>) -> Document;
fn key_import / key_export / key_public / key_generate / key_thumbprint (...);
fn key_to_jwk(key: KeyBytes, vis: Visibility) -> String;          // JSON text
fn key_to_cwk(key: KeyBytes, vis: Visibility) -> Document;        // EDN + hex views
fn datetime(input: DateTimeInput) -> DateTimeForms;  // epoch/RFC3339/tag 0,1,100,1004 ↔ all forms (EDN + hex)
fn lint(doc: Bytes, kind: Kind) -> Vec<Finding>;     // also folded into validate()
fn registry_lookup(q: RegistryQuery) -> Vec<RegistryEntry>;
fn registry_merge(xml: Bytes, which: RegistryId) -> RegistryStats;
```

`Document` = `{ kind, layers, bytes, tree: Node, main: Rendered, raw: RawView,
disclosures, diagnostics }`. A `Node` has a **path-based `NodeId`** (e.g.
`payload/2/cnf/1`, or `disclosure/3/value`), its own children, and references
to its main-pane range and its raw-pane range. Both panes key their
expand/collapse state on `NodeId`, which keeps the trees in sync and lets
collapse state survive re-renders.

### app/ (Svelte + TS)
- `Engine` (TS interface, generated types): `WasmEngine` loads `tokenator-wasm`,
  and `TauriEngine` calls `invoke("engine_*")`. The engine is chosen at startup
  according to whether `window.__TAURI__` is present.
- `Platform`: `fetchUrl`, `openFile`, `saveFile`, `readClipboard`,
  `writeClipboard`, `registryCache`, `now`, and `randomBytes`. The web
  implementation uses `fetch`, the File System Access API with fallbacks, and
  the Clipboard API. The Tauri implementation uses Rust commands, with
  `reqwest` for network access (so no CORS), dialog-scoped fs, and the
  clipboard plugin.
- Stores: `keys` (in-memory key cards), `tabs` (documents and provenance
  graph), `settings` (clock override, skew, view toggles). Nothing is written
  to storage except `registryCache`.
- Code editor: CodeMirror 6 with JSON and custom EDN language modes. Hex/segment
  views are custom virtualized components that render from `RawView` rows.

## Data flow example: paste → validate → present

1. The paste goes to `Platform.readClipboard`, then `engine.detect(bytes)`, then
   `engine.open(bytes, top)`, and a new tab opens with provenance `clipboard`.
2. On Validate, the UI gathers the panel keys and settings, calls
   `engine.validate(...)`, and gets back a report whose items link to `NodeId`s.
   If the report says a key is fetchable, the UI asks the user, calls
   `Platform.fetchUrl`, imports the key, and validates again.
3. On Present, the UI collects disclosure checkboxes, the holder key, aud, and
   nonce, plus `Platform.now()` and `randomBytes`. It calls
   `engine.present(...)`, and a new tab opens, derived from the original.

## Non-obvious consequences

- **Copies at the boundary.** Inside Rust, everything borrows (`&[u8]`, `Cow`).
  But each Engine call copies the input in and the `Document` out, because the
  WASM boundary and Tauri IPC both serialize. That's acceptable at token sizes.
  It's also why the engine is stateless, rather than handing out handles that
  hold memory in WASM.
- **Private keys travel on every signing call** (JS → WASM, or JS → IPC → Rust).
  They are never persisted. On the desktop they pass through Tauri IPC in
  memory only.
- **Randomness and time are injected.** That makes deterministic test
  fixtures possible (seeded salts, keys, and ECDSA nonces via RFC 6979), but
  callers must remember to pass fresh randomness in normal use. The Platform
  supplies it by default.
- **Editing changes bytes only where you edit.** Unedited regions are copied
  verbatim, so a "harmless" edit to one claim does not reformat the others.
  Re-signing still produces new signature bytes (ECDSA and ML-DSA are
  randomized unless seeded).
- **Arrival order is semantic for display, not for crypto.** Maps and objects
  render in input order. Deterministic order is computed only when the linter
  checks it or an encoder is explicitly asked for it. Sorting in the display is
  a tracked issue, and has to be a view option that never touches the bytes.
- **Registry cache is the single persisted artifact.** A stale or poisoned
  cache affects only annotations, never validation results.
- **Native vs WASM parity is a test obligation, not a guarantee.** Any
  target-specific dependency (e.g. a `getrandom` backend) is confined to
  `tokenator-wasm` and `src-tauri`.
- **Web fetches are subject to CORS** and the CSP's `connect-src`. Keeping
  `connect-src` broad enough for arbitrary `kid` URLs while blocking everything
  else is a deliberate tradeoff, documented in the About box.

## Build and CI (once the bulk exists)

Build: `cargo` workspace, `wasm-pack build crates/tokenator-wasm`, `pnpm`
with Vite for `app/`, and `cargo tauri build` for the `.app`.

CI runs `cargo fmt --check`, `clippy -D warnings` (honoring `.clippy.toml`),
unit tests and vectors, the parity suite, Playwright (web), and short fuzz
smoke runs. It deploys Pages from `main` and attaches the `.app` to tagged
releases.
