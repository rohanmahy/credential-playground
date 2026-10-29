# tokenator-core test plan

`tokenator-core` is the stateless Engine facade. It composes the merged
crates (cbor, edn with `hash`, json, crypto, keys, registry, detect, jose,
cose) and adds no format logic of its own. Everything it returns is a serde
DTO, so `tokenator-wasm`, the Tauri commands, and a future CLI are thin
wrappers. This file is the contract for the UI and wasm implementers: the
DTO shapes, the NodeId scheme, and the behaviour the tests pin.

Integration tests live in `tests/`, with shared helpers in
`tests/common/mod.rs`. They go through the `Engine` API only. Fixtures come
from `testdata/tokens/`, `testdata/keys/`, `testdata/rfc/` and
`testdata/iana/` (see their READMEs). Expectations are computed from the
fixtures with `tokenator-cbor`, `tokenator-edn`, `tokenator-json`, and
`serde_json` in the test helpers, never with core itself.

## 1. Engine shape

```rust
let engine = Engine::new()?;                         // bundled registry snapshot
let engine = Engine::with_registry_snapshot(&bytes)?; // after registry_merge
```

`Engine` holds only configuration (the registry). Every method takes
`&self` and DTOs, and returns DTOs. There is no I/O, no clock, and no
ambient RNG. The caller supplies time (`now`), randomness (a 32-byte
`randomness` seed that drives a ChaCha20 RNG), and key bytes. The same
`Engine` configuration plus the same inputs gives byte-identical serialized
outputs, which is what WASM/native parity relies on.

| Method | Request → Response |
|---|---|
| `info` | → `EngineInfo` (crate version, SD-CWT revision, registry dates) |
| `detect` | `&[u8]` → `Vec<Candidate>` |
| `open` | `&[u8]`, `&Candidate`, `&ViewOptions` → `Document` |
| `render` | `RenderRequest { doc, layers, view }` → `Document` |
| `parse_edit` | `EditRequest { kind, base, text, view }` → `EditResult` (never `Err`) |
| `issue` / `redact` | `IssueRequest` → `Document` |
| `disclose` | `DiscloseRequest { doc, keep, view }` → `Document` |
| `present` | `PresentRequest` → `Document` |
| `validate` | `ValidateRequest` → `ValidationReport` |
| `lint` | `LintRequest { doc, keys }` → `Vec<CheckItem>` |
| `resign` | `ResignRequest` → `Document` |
| `tamper` | `TamperRequest { doc, op, view }` → `Document` |
| `reencode` | `ReencodeRequest` → `Reencoded { output, document }` |
| `edit_disclosures` | `EditDisclosuresRequest` → `Document` |
| `decode_embedded` | `DecodeEmbeddedRequest { doc, node_id, view }` → `ManualDecode` |
| `key_import` | `KeyImportRequest` → `Vec<KeyInfo>` |
| `key_export` | `KeyExportRequest` → `KeyExport` |
| `key_public` | `KeyRef` → `KeyInfo` |
| `key_generate` | `KeyGenRequest` → `KeyInfo` |
| `key_thumbprint` | `ThumbprintRequest` → `Thumbprint` |
| `key_assign_kid` | `AssignKidRequest` → `KeyInfo` |
| `key_to_jwk` | `KeyConvertRequest` → `String` (JSON text) |
| `key_to_cwk` | `KeyConvertRequest` → `Document` (kind `CoseKey`: EDN + hex) |
| `datetime` | `DateTimeRequest` → `DateTimeForms` |
| `registry_lookup` | `RegistryQuery` → `Vec<RegistryEntry>` |
| `registry_merge` | `RegistryMergeRequest` → `RegistryMergeResult` (new snapshot + stats) |

Errors are `EngineError { code, message, node_id }` with a stable
snake_case `code`. Wrong input never panics.

## 2. Wire conventions

- **serde, snake_case everywhere.** Struct fields keep their Rust names.
  Unit-only enums serialize as snake_case strings (`"pass"`, `"edn"`).
  Enums with data are internally tagged with `"type"` and snake_case variant
  names: `{"type": "sd_jwt", "kb": true}`. A few small unions are
  untagged (`JsonPathSegment`, `RegistryLabel`: `string | number`).
- **Bytes** (`Bytes`) serialize as unpadded base64url strings. Hex appears
  only in display fields named `*_hex` or documented as hex.
- **Integers.** Offsets, lengths, and counts are `u32`. Times are `i64`
  seconds. ts-rs is configured with `large_int = "number"`, so `i64`/`u64`
  are `number` in TypeScript (tags above 2^53 lose precision there).
- **Text ranges are UTF-16 code units** into `Document.main.text` (what
  CodeMirror and JS strings index). Lines are 0-based, half-open
  (`line_start..line_end`). Byte ranges are UTF-8/binary byte offsets.
- **TypeScript.** Feature `ts` derives `ts_rs::TS` on every DTO.
  `tokenator_core::ts::bindings()` returns `(file name, declaration)` for
  each exported type without touching the file system; a build step writes
  them to `app/src/lib/engine/types/`.

## 3. Documents

```text
Document {
  kind: Kind, layers: Vec<Layer>, bytes: Bytes,
  signed: bool, signature_stale: bool,
  tree: Node, main: Rendered, raw: RawView,
  disclosures: Vec<DisclosureInfo>, undisclosed: Vec<SlotInfo>,
  diagnostics: Vec<Diagnostic>,
}
```

- **`bytes`** are the credential bytes as the format crates parse them:
  - JOSE: the compact token text, or the JWS JSON envelope text, trimmed.
  - COSE: the CBOR item *including its tags* (61, 18). Detection records
    trailing `CborTag` layers, but `open` keeps them in `bytes` so the hex
    view and the signature check see the exact item. `layers` holds only
    the outer transport layers (trim, header, JSON field, base64, hex).
  - Claim sets: the JSON text, the EDN text, or the CBOR bytes.
  - `CoseKey` (from `key_to_cwk`): the COSE_Key bytes.
- **`main`** is `Rendered { language: json | edn, text, line_count }`.
  COSE and CBOR/EDN claim sets render as EDN (indented, encoding indicators
  where non-preferred, registry comments `/ alg /`). An EDN claim set shows
  its own text, comments and all. JOSE renders as one JSON *view object*:

  ```json
  {
    "protected": {"alg":"ES256","typ":"example+sd-jwt"},
    "payload": {"_sd": [...], "iss": "...", ...},
    "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6...",
    "disclosures": [["2GLC42sKQveCfGfryNRN9w", "given_name", "John"], ...],
    "kb": {"protected": {...}, "payload": {...}, "signature": "..."}
  }
  ```

  Decoded parts are embedded with their original JSON text verbatim (CRLFs
  and spacing kept), so a slice of `main.text` at a node equals the decoded
  bytes of that node. Signatures stay base64url strings. A part that is not
  JSON (RFC 7515 A.4's `Payload`) shows its base64url segment as a string
  and gets a diagnostic. JWS JSON serializations use the same shape, plus
  `"unprotected": {...}` (flattened) or
  `"signatures": [{"protected", "unprotected", "signature"}, ...]`
  (general). With `ViewOptions.json_layout = pretty` the decoded parts are
  re-indented for display; then `parse_edit` needs `base` to keep unedited
  bytes (it always gets it).
- **`raw`** is `RawView`:
  - `hex { bytes, rows }` for COSE, CBOR/EDN claim sets, and COSE_Keys.
    `bytes` is the buffer the rows index (the credential bytes, or the CBOR
    encoding of an EDN claim set). One `HexRow` per data item and per break,
    in byte order, each `{ node_id, kind: item|break, depth, head, payload,
    description, comment }`, lined up with the EDN lines (from
    `tokenator_edn::annotated_hex` with the same embedded paths).
  - `segments { segments }` for JOSE: protected header, payload, signature,
    each disclosure, the KB-JWT parts (and, for JSON serializations,
    unprotected headers are not segments). Each `Segment { node_id, label,
    range, text, separator }`, `range` indexing `Document.bytes`.
  - `none` for JSON claim sets.
- **`Node`** is the shared tree for both panes:

  ```text
  Node { id: NodeId, kind: NodeKind, label: String,
         annotation: Option<Annotation>, main: Option<TextRange>,
         raw: Option<RawRange>, key: Option<Box<Node>>,
         time: Option<TimeHint>, sd: Option<SdMark>, children: Vec<Node> }
  ```

  `children` are in arrival order (maps and objects are never sorted). A map
  entry is one child: the node for the *value*, with the key's node in
  `key`. `main` is the value's text range (annotation comments excluded,
  encoding indicators included). `raw` is `{ start, end, row_start,
  row_end }`: for hex views, the item's byte span in `raw.bytes` and the
  rows it covers (including break rows and rows of decoded views); for
  segments, the base64url characters that encode the node (see §5) and the
  segment index as a one-row range. `annotation` comes from the registry
  through an adapter (`name`, `description`, `value_name` for registered
  values such as `alg -7 → ES256`, and spec links with
  `SpecRef::display_text()`, so no draft revisions in hover text).
  `time` is set on `exp`/`nbf`/`iat` claims and tag 0/1 items (`rfc3339`
  and, when `ViewOptions.now` is set, `relative`). `sd` marks digest slots
  (`slot { digest, disclosure }`), the redacted-keys array, and disclosure
  nodes.
- **`disclosures`** lists every disclosure in input order: `index`,
  `node_id`, `digest` (base64url for JOSE, hex for COSE), `salt` (string /
  hex), `claim` (JSON name, or the COSE key in compact EDN), `value` (compact
  JSON / EDN), `decoy` (a COSE `[salt]` disclosure), `status` (`matched`,
  `unmatched`, `duplicate`, `malformed`, `forbidden_name`, `kind_mismatch`,
  `name_collision`), and `slot` (the NodeId of the digest it fills).
  **`undisclosed`** lists digest slots that no disclosure fills (decoys or
  withheld claims).
- **`diagnostics`**: `{ severity: error|warning|info, code, message,
  node_id, main, raw }`. Codes are stable dotted strings, e.g.
  `jose.base64`, `jose.not_json`, `jose.segment_count`, `cose.diagnostic`,
  `edn.syntax`, `edn.warning.non_canonical_nan`, `cbor.trailing_bytes`,
  `cbor.decode`, `json.unsafe_integer`.
- **`signed`** is true for every signed kind. **`signature_stale`** is true
  for documents whose signed content changed without re-signing
  (`parse_edit` of signed content, `tamper`, `edit_disclosures` digest
  edits, `reencode` with `deep`).

## 4. NodeId scheme

A `NodeId` is a string: segments joined by `/`, the document root is `""`.
It is a path into the structure the *main pane shows*, so it is stable
across re-renders, view toggles that don't remove the node, and edits that
don't move the node. Both panes key collapse state and selection on it.

**Segments**

| Segment | Meaning |
|---|---|
| part names | `protected`, `unprotected`, `payload`, `signature`, `signatures`, `disclosures`, `kb` (see below) |
| `0`, `1`, … | array element by index |
| JSON member name | RFC 6901 escaped: `~` → `~0`, `/` → `~1` (`http:~1~1example.com~1is_root`) |
| CBOR map key | the key printed as compact EDN without encoding indicators, then RFC 6901 escaped: `1`, `-7`, `"country"`, `simple(59)`, `58(501)`, `h'01'` |
| `~k` | the key node of the entry named by the previous segment (`payload/~e/iss/~k`) |
| `~e`, `~e1`, … | decoded view of a byte string or base64url segment (item 0, item 1, … of the embedded CBOR sequence) |
| `~t` | content of a tag that is not an envelope tag (`.../501/0/~t` for `60(h'…')`) |
| `~c0`, … | chunk of an indefinite-length string |
| `~i3` | fallback: entry 3 by arrival index, used for container keys, keys longer than 64 characters of EDN, and the second and later occurrences of a duplicate key |

A literal `~` in a name is always written `~0`, so any segment starting with
`~` and a letter is one of the specials above.

**JOSE.** The root is the view object. Compact and flattened tokens have
`protected`, `unprotected` (JSON only), `payload`, `signature`. General JWS
JSON has `payload` and `signatures/<n>/{protected,unprotected,signature}`.
SD-JWT adds `disclosures/<n>`, and KB adds `kb/{protected,payload,signature}`.
Decoded JSON sits under `~e`: `protected/~e/alg`, `payload/~e/cnf/jwk/x`,
`disclosures/2/~e/1` (the claim name), `kb/payload/~e/nonce`.

**COSE.** The root is the outermost item. Envelope tags (61, 18) are folded
into the root (their hex rows carry `node_id ""`), so tagged and untagged
tokens have the same ids. The COSE_Sign1 elements are `protected`,
`unprotected`, `payload`, `signature` (extra elements `4`, …). So:
`protected/~e/1` (alg), `unprotected/4` (kid), `payload/~e/2` (sub),
`unprotected/17/0/~e/2` (the claim key of disclosure 0),
`payload/~e/simple(59)/0` (a redacted claim digest),
`payload/~e/503/"region"`. A COSE_Sign1 nested at a format-defined location
(the SD-KBT `kcwt`) uses the same part names below its own id:
`protected/~e/13/payload/~e/1`, `protected/~e/13/unprotected/17/0/~e`.

**Claim sets and keys.** The root is the map/object: `iss`, `address/street`
(JSON); `1`, `8/1/-2` (CBOR/EDN, COSE_Key).

**Helpers** (implemented, DTO-level): `NodeId::root`, `child`, `key`,
`decoded`, `parent`, `segments`, `is_ancestor_of`, `escape_segment`,
`unescape_segment`. A JSON claims NodeId with a leading `/` is the RFC 6901
pointer of that claim (`NodeId::to_json_pointer`), which is how SD marks
travel to `tokenator-jose`.

## 5. Range consistency (what the tests check)

- **COSE / CBOR.** For every node with both ranges, EDN-parsing the main
  slice and encoding with `Preserve` gives exactly `raw.bytes[raw.start..
  raw.end]`. For a byte string shown as `<<…>>` the slice is the `<<…>>`
  text and the bytes include the bstr head; for its `~e` child the bytes
  are the content. `rows[row_start].head.start == raw.start`, and every
  row in `row_start..row_end` lies inside `raw.start..raw.end`.
- **JOSE.** A part node's `raw` is exactly its segment. A node inside a
  decoded part covers the decoded bytes `a..b` of its segment; its `raw` is
  the base64url characters `seg + 4⌊a/3⌋ .. seg + min(4⌈b/3⌉, len)`, so
  decoding those characters yields bytes that contain the node's main
  slice. The main slice equals the decoded JSON text of the node.
- **Every node** with `main` has `line_start < line_end` (or equal for an
  empty range) consistent with the newlines in `main.text`.

## 6. Embedded CBOR: defined locations only

Decoded views (`~e`) appear only at: COSE `protected` and `payload` (when
the payload is complete CBOR), SD-CWT disclosures (`unprotected/17/<n>`),
the `kcwt` inner token's parts, tag 24/63 contents (`…/~t/~e`), and every
JOSE base64url segment except signatures. `cnf` keys and `x5c`/`x5chain`
get key/certificate annotations but no CBOR decoding. Nowhere else, even if
a byte string happens to be valid CBOR (#15). `ViewOptions.decoded_views =
false` removes them all; `hide_decoded` removes them per node;
`manual_decode` adds a decoded view at any byte string node and reports
`cbor.trailing_bytes` when the content is not exactly one item.
`decode_embedded` does the same for a single node and returns
`ManualDecode { text, tree, diagnostics }`; truncated or malformed content
is an `EngineError` with code `decode`.

## 7. Detection

`detect` wraps `tokenator-detect`, maps its candidates to DTOs (kind,
confidence, layers, payload range, breadcrumb), and confirms low-confidence
`EdnText` candidates with the EDN parser: a candidate that parses to a map
becomes `edn_claims`; anything else is dropped. `key_import` also accepts
COSE_Keys and COSE_KeySets written as EDN. Key kinds (`jwk`, `jwk_set`,
`cose_key`, `cose_key_set`, `pem`) are returned as candidates so the UI can
route them to the key panel. Breadcrumbs end with `Kind::label()`.

## 8. Validation report (SPEC §6)

`ValidationReport { overall, items, fetchable }`. `items` is an ordered
checklist of `CheckItem { id, category, status, message, node_ids, raw,
detail }` with `status ∈ pass | fail | warn | skip | info`. Order: signature,
time, SD, key binding, lint. `overall` is `fail` if any item fails, else
`warn` if any warns, else `skip` if the signature or key binding check was
skipped, else `pass`.

| id | category | Rule |
|---|---|---|
| `signature` | signature | Issuer signature. `detail.signature` names the key (`key_index` into `ValidateRequest.keys`, `key_label`), the `selection`, and `untrusted` |
| `time.exp`, `time.nbf`, `time.iat` | time | Against `now` with `skew` (default 60 s): expired iff `now >= exp + skew`; not yet valid iff `now + skew < nbf`; `iat` in the future (`iat > now + skew`) warns. Absent claims produce no item |
| `sd.sd_alg` | sd | `_sd_alg` / `sd_alg` supported (fail otherwise) |
| `sd.match` | sd | Pass when every disclosure matches exactly one digest |
| `sd.unmatched`, `sd.duplicate_digest`, `sd.duplicate_disclosure`, `sd.forbidden_name`, `sd.malformed` | sd | Fail, one item per finding, linking the disclosure and slot nodes |
| `sd.undisclosed` | sd | Info: digests without disclosures (decoys or withheld) |
| `kb` | key_binding | Skip when there is no KB and no expectation; fail when `expected_aud`/`expected_nonce` is set but there is no KB-JWT/SD-KBT |
| `kb.signature`, `kb.sd_hash`, `kb.aud`, `kb.nonce`, `kb.iat` | key_binding | KB signature against the `cnf` key, `sd_hash` (JOSE), `aud`, `nonce`/`cnonce`, `iat` freshness (`max_kb_age`) |
| `lint.encoding` | lint | Non-preferred argument, float, or indefinite length: info, warn where deterministic encoding is required (protected header, payload, disclosures, Sig_structure inputs); `raw` is the exact finding span, `detail.encoding.preferred_hex` the replacement |
| `lint.bignum`, `lint.nan` | lint | Bignum that fits an integer; non-canonical NaN |
| `lint.map_order` | lint | Map keys not in deterministic order where required |
| `lint.duplicate_key` | lint | Duplicate CBOR map key or JSON member (tokenator-cbor / tokenator-json / tokenator-jose detect, core warns) |
| `lint.alg_key` | lint | `tokenator_crypto::check_key` mismatches for the signing key and for `cnf` keys (kty, crv, RSA size, ML-DSA set, declared `alg`) |
| `lint.typ`, `lint.crit`, `lint.alg_none`, `lint.header` | lint | Missing/unexpected `typ`; `crit` not understood or malformed; `alg: none`; other header rules (label in both buckets, alg unprotected, empty protected not zero-length) |
| `lint.salt` | lint | SD-CWT salt not 16 bytes |
| `lint.json_number`, `lint.json_utf8` | lint | tokenator-json warnings (unsafe integer, overflow, underflow; invalid UTF-8) |

Lint items are only ever `warn` or `info`. `lint()` returns exactly the
lint items `validate()` would include.

**Key selection** for the issuer signature: (1) panel keys (`keys`) whose
kid or JWK/COSE thumbprint matches the header kid (`panel_kid`,
`panel_thumbprint`); (2) if none matches, every panel key that fits the alg
(`panel_unmatched`; if keys were tried and none verifies, `fail`); (3) embedded keys, labeled untrusted: the
`x5c`/`x5chain` leaf (`embedded_x5c`); (4) otherwise `skip`, and
`fetchable` lists hints that are never fetched: `kid_url` when the kid is a
URL, `issuer_metadata` (`https://host/.well-known/jwt-vc-issuer/path`) when
an SD-JWT `iss` is an https URL. Key binding uses the `cnf` key
(`embedded_cnf`, untrusted) or a panel key matched by `cnf` kid/thumbprint.
An unsupported alg (HS256) or no usable key gives `skip`; `alg: none` or a
bad signature gives `fail`.

## 9. Actions

- **Issue / Redact.** `IssueRequest { claims: DocRef, issuer, alg, header,
  sd, cnf, jose_serialization, cose_tags, randomness, view }`. JSON claims
  issue JOSE, EDN/CBOR claims issue COSE. SD marks: `sd.marks` are NodeIds
  of JSON claims; EDN uses tags 58/62. `redact` is `issue` that fails with
  `nothing_to_redact` when nothing is marked. Salts and decoys need
  `randomness` (or `sd.fixed_salts`), else `randomness` error. Signing is
  deterministic without `randomness` (RFC 6979 ECDSA, deterministic
  ML-DSA, Ed25519, PKCS#1 v1.5; PSS requires randomness).
- **Disclose / Present.** `keep` are disclosure indexes in input order.
  Present adds a KB-JWT (JOSE) or wraps the credential in an SD-KBT (COSE;
  a plain CWT gets an SD-KBT with no disclosures).
- **Resign** re-signs `doc.bytes` as they are (e.g. after `parse_edit`).
- **Tamper** ops: `flip_bit { part, bit }`, `flip_byte_bit { offset, bit }`,
  `set_alg { alg }` (JOSE name incl. `none`, or a COSE label),
  `remove_alg`, `strip_signature`, `set_kid { kid }`, `truncate { len }`,
  `duplicate_disclosure { index }`, `reencode_protected { how }`,
  `set_tags { tags }`. The result is never re-signed and has
  `signature_stale = true`.
- **Reencode.** `ReencodeRequest { doc, layers, cose_tags, cbor, deep, jose,
  view }`: new outer layers (rewrap), new COSE tags, CBOR serialization
  (`preserve`, `preferred_plus`, `deterministic`) applied to the outer item
  (and with `deep` also inside the protected header, payload, and
  disclosures, which makes the signature stale when bytes change), and JOSE
  serialization (compact / flattened / general).
- **Edit disclosures.** `remove`, `duplicate`, `move`, `select`, `append`,
  `forge`, `replace_value`, `add_decoy`, `remove_digest`. COSE supports the
  first seven; `add_decoy`/`remove_digest` on COSE return `unsupported`
  until tokenator-cose gains payload digest edits.
- **Live edit.** `parse_edit` parses `text` in the document's language and
  rebuilds bytes. Unedited regions keep their bytes (EDN encoding
  indicators, verbatim JSON). If any signed content changed relative to
  `base`, `signature_stale` is true; the signature bytes are kept. A text
  that doesn't parse gives `ok: false`, `bytes: None`, and an error
  diagnostic with its `main` range. Node ids of unedited nodes are unchanged.
- **Date/time chit.** `DateTimeRequest { input, now, local_offset_minutes }`
  → epoch text, millis, RFC 3339 UTC and local, the relative string, and
  the eight forms of `tokenator_edn::datetime::DateForm::ALL` as EDN + hex.
  Relative strings: `now` → `"now"`; otherwise the largest non-zero unit of
  `d`, `h`, `m`, `s`, plus the next unit if it is non-zero, as
  `"in 3 h 12 m"` (future) or `"2 d ago"` (past).

## 10. Decisions encoded in the tests (issues filed)

1. Wire conventions: base64url bytes, UTF-16 text ranges, snake_case,
   `i64` as `number` (#28).
2. The Engine holds the registry; `registry_merge` returns a new snapshot
   instead of mutating (#29).
3. Key-based NodeIds, COSE part names with envelope tags folded into the
   root, COSE tags kept in `Document.bytes`, the JOSE view object with
   verbatim decoded parts, and `tamper` always returning a Document (#30).
   JOSE unprotected header nodes have no `raw` range (they are not
   segments).
4. Key selection: kid/thumbprint match, then every fitting panel key; keys
   tried and none verifies → `fail`, no fitting key → `skip`. Unsupported
   alg → `skip`; future `iat` → `warn`; claim sets cannot be validated;
   presenting a presentation again is refused (#31). `lint` also accepts
   claim sets (encoding and duplicate findings in drafts).
5. Gaps in merged crates, worked around in core for now (#32): no
   x5c/x5chain key extraction (tokenator-keys reads no certificates), no
   COSE payload digest edits (`unsupported`), relative-time formatting
   done in core, EDN COSE_Keys parsed with tokenator-edn before
   `tokenator_keys::import`.

## 11. Files

| File | Covers |
|---|---|
| `detect.rs` | every token/key fixture classified; layers kept outside `bytes`; EDN candidate confirmation and dropping; breadcrumbs; key routing |
| `open_validate.rs` | paste → detect → open → validate for JWT (ES256, RS256, unsupported HS256, `alg: none`), SD-JWT compact/JSON with and without KB, CWT tagged/untagged/tag 61, SD-CWT, SD-KBT (nested too), decoys; key selection and fetch hints; claim sets open as unsigned drafts |
| `issue_present.rs` | issue → disclose → present → validate for JOSE and COSE with seeded keys; redact; `nothing_to_redact`; randomness requirements; plain CWT in an SD-KBT |
| `tamper.rs` | every tamper op fails the expected check (or keeps the signature, for equivalent encodings) |
| `resign_edit.rs` | resign; `parse_edit` stale flag, unedited bytes kept, invalid text diagnostics, encoding indicators |
| `reencode.rs` | outer layers, tags, preserve / preferred-plus / deterministic, `deep`, JOSE serializations |
| `disclosures.rs` | SD views, `edit_disclosures` ops for both families |
| `keys.rs` | import every key fixture, export, public, generate (seeded, well-known seed, entropy), thumbprints, assign kid, JWK ↔ CWK |
| `node_ids.rs` | the NodeId grammar on real documents, helpers, stability across re-render, tagging, and edits |
| `ranges.rs` | main ↔ raw range consistency for every fixture |
| `embedded.rs` | decoded views only at defined locations; toggles; manual decode |
| `lint.rs` | one fixture or constructed input per lint category |
| `datetime.rs` | conversions, local offsets, relative strings, errors |
| `registry.rs` | lookups, annotations in rendered text, merge returns a usable snapshot |
| `dto_serde.rs` | serde round trips and wire shapes of every DTO |
| `ts_export.rs` | (feature `ts`) declarations exist for every exported DTO |
| `determinism.rs` | the same seeded flow twice gives byte-identical serialized DTOs |
| `proptest_never_panic.rs` | `detect`, `open`, `render`, `parse_edit` never panic on random input |
