# The Tokenator — Specification (v1)

A credential playground for issuing, presenting, validating, viewing, and
manipulating JWT, SD-JWT, CWT, and SD-CWT credentials and their keys. It ships
as a static web app and a macOS desktop app (Tauri).

See `PRODUCT-REQUIREMENTS.md` for the original brief and `ARCHITECTURE.md` for
components and interfaces.

## 1. Principles

- **Local only.** The web server delivers the app and nothing else. Credentials,
  keys, and claims are never sent to any server. The only network traffic is
  user-confirmed fetches (key URLs, issuer metadata, IANA registries) made
  directly from the browser or app.
- **Never persist user data.** Keys, credentials, and workspace state live in
  memory and are lost when the tab or app closes. Users export explicitly
  (file or clipboard). *Exception:* refreshed IANA registry data, which is
  public, may be cached (IndexedDB on web, app data dir on desktop).
- **Original bytes are authoritative.** Decoding never re-serializes silently.
  Signatures, digests, and the hex/segment views always reflect the exact input
  bytes until the user edits something.
- **It's a playground.** Generating broken, insecure, or non-conformant
  artifacts is a feature. Insecure states are labeled, never blocked.

## 2. Supported formats

| Family | Formats | Serializations |
|---|---|---|
| JOSE | JWT (JWS), SD-JWT (RFC 9901) with KB-JWT | compact; SD-JWT JWS JSON (flattened and general) |
| COSE | CWT (RFC 8392, COSE_Sign1), SD-CWT (draft-ietf-spice-sd-cwt) with SD-KBT | binary CBOR, tagged or untagged (tags 61, 18) |

The SD-CWT implementation targets one specific draft revision, recorded in the
registry snapshot and shown in the About box. Codepoints (tags, header labels,
simple values) come from that revision.

**Algorithms (sign and verify):** ES256, ES384, ES512 (P-256/384/521); EdDSA/Ed25519
(both the polymorphic `EdDSA` and the fully-specified `Ed25519` identifiers);
RS256, RS384, RS512; PS256, PS384, PS512; ML-DSA-44, ML-DSA-65, ML-DSA-87
(AKP key type). Hash algorithms for SD: SHA-256 (default), SHA-384, SHA-512.

## 3. Input and detection

Inputs: paste, drag-and-drop, file open, clipboard read, and URL fetch.

Detection runs a chain of *unwrapping layers*. Each layer it peels off is
recorded and shown as a breadcrumb (e.g. `Authorization header › base64url ›
CWT tag 61 › COSE_Sign1`):

1. Text cleanup: trim, strip quotes, the `Bearer ` prefix, `Authorization:`
   headers, and URL encoding.
2. Container: a JSON object holding a token string (e.g. `{"credential": "…"}`).
   Every string field that looks like a token is offered as a candidate.
3. Encoding: base64url, base64 classic (padded or not), hex (with or without
   whitespace or colons), or raw binary.
4. Classification:
   - `ey…` with two dots → JWS compact / JWT.
   - Compact with `~` separators → SD-JWT (with KB-JWT if the last part is non-empty).
   - JSON containing `payload` + `signature(s)` → JWS JSON / SD-JWT JSON.
   - CBOR tag 61 / tag 18 / a 4-element array with a bstr protected header →
     COSE_Sign1 → CWT. SD-CWT if SD headers are present. SD-KBT if the
     key-binding header is present.
   - Valid EDN or JSON text that isn't a token → **unsigned claim set**
     (a draft, ready for Issue/Redact).
   - JWK / JWK Set / COSE_Key / COSE_KeySet / PEM → routed to the Key panel.

Detection returns ranked candidates with confidence. The UI opens the top one
and lets the user pick another through a "Detected as…" menu.

## 4. Workspace UI

- **Layout:** a key panel docked on the left and credential **tabs** on the
  right. Any two tabs can be split side by side.
- **Provenance:** every key and credential shows where it came from: file name,
  clipboard, URL, pasted, generated, or *derived from tab N via action X*.
  Derived tabs show a breadcrumb back to their parent.
- **Light/dark theme,** following the OS by default.
- **Map order:** maps and objects are always displayed in the order their items
  arrived in the input, never re-sorted, in both the main and raw panes. Sorting
  is a future option (#1).
- **Tool chits:** small floating utilities you can open from the toolbar or from
  a node's context menu (§4.3).

### 4.1 Credential tab

- **Header bar:** detected type, unwrapping breadcrumb, provenance, validation
  badge, a **Read-only / Live edit** toggle, and action buttons (§5). Each
  action is enabled only when the required keys or inputs are available, and a
  tooltip explains what's missing.
- **Main pane** (collapsible): JSON for JOSE, EDN for COSE. Claim and header
  names are annotated from the registry (e.g. `/ iss / 1: "…"`, hover for the
  description and spec link).
- **Raw pane** (optional, toggleable):
  - COSE: annotated hex, with one row per CBOR data item, lined up row for row
    with the EDN pane.
  - JOSE: the encoded segments (header, payload, signature, each disclosure, and
    the KB-JWT), each highlighted when its node is selected.
- **Tree sync:** expanding or collapsing a node in either pane does the same in
  the other. Selecting a node highlights its counterpart. Collapse state
  survives re-renders and edits, because node IDs are path-based.
- **Embedded decoding at known locations only:** byte strings are decoded
  automatically only where the format defines their content. Examples are the
  COSE protected header and payload, SD-CWT disclosures, the `kcwt` inner
  token, `cnf` keys, X.509 certificates (`x5c`, `x5chain`), and JOSE base64url
  segments. In future, structures learned from CDDL will count too. The decoded
  content appears as an expandable *decoded view* child. There is no automatic
  guessing anywhere else (#15).
- **Manual decode:** the user can select any other byte string and choose
  *Decode as CBOR*. It decodes and warns if the bytes are not exactly one data
  item (trailing or missing bytes).
- A decoded view can be toggled off per node or globally. The hex alignment
  always stays on the original bytes.
- **SD views:** disclosures are listed with their digest, salt, claim name or
  array position, and value. Each one shows whether it matched a digest in the
  payload, and the matching redacted slot is linked in the tree. Decoys are
  marked once they're identified (i.e. digests with no disclosure).

### 4.2 Key panel

Each key card shows: algorithm or key type, role (**Issuer / Holder /
Verifier**), kid, public/private status, provenance, and its JWK and COSE
thumbprints.

Operations:

- **Create:** any supported algorithm (P-256/384/521, Ed25519,
  RSA 2048/3072/4096, ML-DSA-44/65/87), either random or **deterministic from a
  seed** (user-supplied or a fixed well-known test seed).
- **Import** from file, clipboard, paste, or URL: PEM (SPKI, PKCS#8, SEC1,
  PKCS#1, and the LAMPS ML-DSA forms with seed, expanded, or both), JWK, JWK
  Set, COSE_Key, and COSE_KeySet (binary CBOR or EDN). A set imports as several
  keys.
- **Convert:** view any key as a JWK or as a CWK (COSE_Key, shown in EDN and
  hex), public or private, side by side.
- **Export** to file or clipboard in any of those formats, public or private.
  Exporting a private key needs an explicit choice, and its clipboard copy is
  labeled.
- **Derive public key** from a private key, as a new card linked to the original.
- **Thumbprints:** JWK (RFC 7638, plus the RFC 9278 URI form) and COSE
  (RFC 9679), with a selectable hash.
- **Auto kid:** set kid to the JWK thumbprint, the COSE thumbprint, or a user string.
- **Fetch from URL:** an explicit, user-confirmed fetch of a JWK Set, COSE_KeySet,
  or `/.well-known/jwt-vc-issuer` metadata. On the web, a CORS failure shows a
  clear explanation and offers to paste the content instead or use the desktop app.

### 4.3 Date/time chit

A small converter between time representations. All fields stay in sync, and
editing any one of them updates the rest:

- NumericDate / epoch seconds (integer or fractional), plus milliseconds.
- RFC 3339 in UTC and in the local time zone, with the relative offset from
  the clock ("in 3 h 12 m", "expired 2 d ago").
- CBOR: tag 1 (epoch, int or float), tag 0 (RFC 3339 text), tag 100 and
  tag 1004 (date only, RFC 8943). Shown as EDN (including `dt''`) and as hex.

Opening the chit from a time-valued node (`exp`, `nbf`, `iat`, a tag 0/1 item,
or a `dt''`) pre-fills it. In Live edit, **Insert** writes the chosen form back
into that node. A "Use as clock" button sets the validation clock override (§6).
Time claims in the tree also show an inline human-readable date.

## 5. Actions

Every action that produces a credential opens it in a **new tab**, derived from
the source.

| Action | Input | Output |
|---|---|---|
| **Issue** | Unsigned claim set (JSON or EDN) + issuer key + header options | JWT / CWT, or SD-JWT / SD-CWT if any claims are marked |
| **Redact** | EDN claim set with to-be-redacted and to-be-decoy tags (SD-CWT), or JSON with claims marked SD in the tree (SD-JWT) | SD-CWT / SD-JWT with disclosures and decoys |
| **Disclose** | SD credential + a chosen subset of disclosures | SD credential with that subset (no key binding) |
| **Present** | Credential + chosen disclosures + holder key + `aud`, `nonce`, `iat` | SD-JWT+KB-JWT, or an SD-KBT wrapping the SD-CWT. A **plain CWT** is wrapped in an SD-KBT with no disclosures. |
| **Validate** | Any credential + options (§6) | Validation report |
| **Edit & re-sign** | Credential edited in Live mode + a key | New signature over the edited content |
| **Tamper** | Credential + tamper op | Deliberately broken credential, *not* re-signed |
| **Re-encode** | Credential | Different outer encoding (base64url, base64, hex, raw binary; tagged or untagged CBOR; compact or JSON serialization) |
| **Edit disclosures** | SD credential | Disclosures added, removed, reordered, or forged; decoys added or removed |

**Live edit:** switching to Live edit turns the main pane into a text editor.
Every valid edit re-parses and updates the tree and raw pane. Once the content
changes, the tab is marked **modified – signature stale**, and the user picks
*Re-sign* (needs a key) or *Keep original signature* (a tamper). Unchanged
regions keep their original bytes. Edited CBOR honors the EDN encoding
indicators, so non-preferred encodings can be produced on purpose.

**Tamper ops:** flip a bit in a chosen segment or byte, swap `alg` (including
`none`), strip the signature, change or remove `kid`, truncate, duplicate a
disclosure, replace the protected header with an equivalent but differently
encoded one, and drop or alter the CBOR tag.

## 6. Validation

Inputs: candidate keys, a clock (**now** or a user-chosen instant), allowed
skew (default 60 s), and expected `aud` / `nonce` for key binding.

**Key selection, in order:**

1. A key in the panel whose kid or thumbprint matches the header.
2. Keys embedded in the credential: the `x5c`/`x5chain` leaf, and `cnf` (used
   for key binding). These are labeled *untrusted embedded key*. Chain
   validation is out of scope for v1.
3. If `kid` is a URL, or `iss` has issuer metadata, the user is offered a fetch.
   It never happens automatically.

**Report:** a checklist of `pass` / `fail` / `warn` / `skip` items. Each item
links to the tree nodes it concerns.

- Signature: which key verified, and how it was selected.
- Time claims: `exp`, `nbf`, `iat` against the clock, with skew.
- SD: every disclosure matches exactly one digest. The report also flags
  unmatched disclosures, duplicate digests, digests without disclosures
  (decoys or withheld claims), `sd_alg` validity, and forbidden claim names
  inside disclosures.
- Key binding: KB signature against the `cnf` key, `sd_hash` (or the SD-CWT
  equivalent), `aud`, `nonce`, and `iat` freshness.
- Conformance lint (warnings and info only):
  - **Non-preferred CBOR encodings anywhere** (RFC 8949 §4.1): a longer-than-needed
    argument, a float that could be shorter without losing its value,
    indefinite-length items. Each finding is located on the exact hex row and
    shows the preferred bytes. These are reported as *info*, and raised to
    *warn* where the spec requires deterministic encoding (e.g. inputs to
    digests or the COSE Sig_structure).
  - Map keys that aren't in deterministic order, where that order is required.
  - Duplicate map keys / JSON object members.
  - **Alg/key consistency,** using the requirements table from
    `tokenator-crypto`: key type (`kty`), curve (`crv`), RSA minimum size,
    ML-DSA parameter set, and an `alg` field inside the JWK/COSE_Key that
    doesn't agree with the header `alg`. This applies both to signing keys and
    to `cnf` keys.
  - Missing or unexpected `typ`, a critical header that isn't understood,
    and `alg: none`.

## 7. Claims and headers registry

- A bundled snapshot of the IANA CWT, COSE, JWT, and JOSE registries is
  generated at build time, plus local additions such as SD-CWT codepoints
  from the targeted draft.
- **Refresh:** an explicit "Update registries" action fetches the IANA
  registries, parses them, merges them over the snapshot, and caches the result
  (the only data that persists).
- The registry drives name annotation, label↔name mapping when converting
  between the JOSE and COSE views, and autocomplete in Live edit.

## 8. EDN

A parser and printer for draft-ietf-cbor-edn-literals (targeting -28):

- Full core grammar: comments, indefinite-length items, encoding indicators
  (`_0`–`_3`, `_i`), embedded CBOR (`<<…>>`), and all numeric forms. String
  concatenation uses the `b1''`/`t1''` extensions, because -28 removed
  juxtaposition.
- Application-extensions `h''`, `b64''`, `dt''`, `ip''`, and `hash''`. Other
  extensions round-trip as opaque values with a warning.
- The printer emits per-node text ranges for tree sync, and can print in
  compact or indented style.

## 9. Security and privacy notes (shown in the app's About box)

- Keys are held in page or process memory, unprotected. Use test keys only.
- RSA uses the pure-Rust `rsa` crate, which has a known timing side channel
  (RUSTSEC-2023-0071, "Marvin"). That's acceptable for a local playground, but
  not for production signing.
- A URL fetch reveals your IP address and the URL to that host.
- The web build sets a strict CSP. Script is loaded only from its own origin,
  and `connect-src` is limited to what user-initiated fetches need.

## 10. Distribution

- **Web:** a static build on GitHub Pages.
- **macOS:** a `.app` bundle attached to GitHub releases, unsigned for now.
  *Follow-up (#2):* produce an unsigned DMG. Signing and notarization come later.

## 11. Testing

- Rust unit tests per crate. Test vectors: RFC 9901, draft-ietf-spice-sd-cwt,
  RFC 8392, RFC 7638, RFC 9679, the ML-DSA JOSE/COSE draft examples, and
  `hildjj/cbor-test-vectors`.
- **Parity:** one corpus runs through the WASM engine and the native engine,
  and their outputs must be byte-identical.
- **UI end-to-end:** Playwright against the web build, and against the Tauri
  build through tauri-driver.
- **Fuzzing:** cargo-fuzz targets for CBOR decode, EDN parse, JSON parse,
  detection, and SD-JWT/SD-CWT parsing. Parsers must never panic.

## 12. Out of scope for v1 (future)

CDDL / JSON Schema validation and variant identification (WIMSE, SCITT); a CLI
(the core is built to support one); plugin formats (WebAuthn, Privacy Pass,
EUDI wallet, mdoc, W3C VC/VP); encryption (JWE / COSE_Encrypt); X.509 chain
validation; Linux and Windows desktop builds; signed DMG; an option to
display maps/objects sorted (deterministic CBOR order, or alphabetical for JSON).
