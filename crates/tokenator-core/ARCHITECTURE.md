# tokenator-core

Stateless Engine facade for The Tokenator. See the top-level
`ARCHITECTURE.md` for its role and `TEST-PLAN.md` for the contract (DTOs,
NodeId scheme, document model, validation rules; issues #28–#32).

| Module | Contents |
|---|---|
| `engine.rs` | `Engine` (holds only the registry); one-line delegations |
| `dto/` | serde DTOs (snake_case, `"type"`-tagged enums, base64url bytes), `NodeId` helpers |
| `view/mod.rs` | `build`/`document`: bytes of a kind → `Document`; COSE SD view; `unreadable` |
| `view/cbor.rs` | the CBOR walk: NodeIds, kinds, annotations, decoded views, EDN main pane, hex rows |
| `view/jose.rs` | the JOSE view object, segments, SD view; `with_parsed` |
| `view/json.rs` | JSON trees (claim sets, decoded JOSE parts) |
| `detect.rs` | `detect` (tokens, claim sets) and `detect_key` (keys) over one set of readings (plus EDN confirmation), layer conversions, `open` |
| `validate.rs` | `validate` (key selection, time, SD, key binding) and `lint` |
| `actions.rs` | `issue`, `redact`, `disclose`, `present`; error mapping; signing |
| `manipulate.rs` | `resign`, `tamper`, `reencode`, `edit_disclosures`, `decode_embedded` |
| `edit.rs` | `parse_edit` |
| `convert.rs` | `convert_claims`: claim sets between JSON and EDN |
| `keyring.rs` | `KeyRef` resolution (EDN COSE_Keys too), key cards, key panel calls; `not_a_key` for import of non-keys |
| `annotate.rs`, `reg.rs` | registry adapter; lookups, merge, `info` |
| `datetime.rs` | the date/time chit, relative strings, time hints |
| `cbor.rs`, `util.rs` | item helpers; hex, UTF-16 text index, randomness |

## Design notes

- **One walk per document.** `view/cbor.rs` walks the decoded item once and
  decides everything format-specific: NodeIds (key-based, `~iN` fallback),
  part names, envelope tags folded into the token's node, registry
  annotations, and which byte strings get decoded views (defined locations
  only, #15). The EDN printer and `annotated_hex` then get the same
  embedded paths and comments, so main ranges come from the printer's span
  map and rows line up. Row ranges are found by byte offset.
- **Bounded stack.** CBOR nesting is walked with an explicit task stack;
  only decoded views recurse, capped at 16 levels (nested `kcwt` byte
  strings are not bounded by the decoder's depth limit). At the limits a
  render needs < 256 KiB of stack in release builds and about 1 MiB in
  debug builds (tokenator-json and tokenator-cbor recurse too).
- **JOSE view object.** Decoded parts are embedded verbatim, then the whole
  view text is parsed with tokenator-json to get every node's span. A
  decoded node's raw range is the base64url characters covering its bytes.
  `parse_edit` compares each part's edited slice with the base rendering:
  unchanged parts keep their original encoded text (so unusual base64 and
  the pretty layout survive), changed parts are re-encoded. Text without
  `.` or `~` parses as a one-segment compact JWS (`jose.segment_count`).
  With an empty base (a tab typed from scratch, SPEC §4.1) the text is the
  token itself: compact text loses any whitespace inside it, and it must
  parse as the requested kind's serialization, whose parsed `kb` wins
  (`sd_jwt { kb: false }` reads an SD-JWT+KB as one). Nothing is stale
  against an empty base.
- **Lenient compact readings** (SPEC §3). A token with line breaks in it
  is detected through a `line_breaks` layer, so `open` decodes the text
  without them. A KB-less SD-JWT missing its final `~` (last part a
  disclosure) opens with all disclosures and a Document warning
  `sd_jwt.missing_trailing_tilde`.
- **EDN text** is classified by the CBOR it encodes, through
  `tokenator_detect::detect` on the encoding (#44): claims maps stay
  `edn_claims` (bytes = the text); COSE_Sign1s and COSE_Keys get a
  `Layer::Edn` (innermost) that `open` applies and `reencode` writes.
- **Tokens and keys are detected separately.** `detect` and `detect_key`
  filter one ranked list of readings by `Kind::is_key`, so a JWK or
  COSE_Key pasted as a credential opens as a claim set, and the key panel
  never sees a token. `tokenator-detect` itself still reports every kind.
- **JSON claim sets are EDN too.** `detect` adds an `edn_claims` reading
  one point below each `json_claims` one (same layers, confirmed by the
  EDN parser), so "Detected as…" can switch a draft to EDN; not for a JWS
  JSON or a token container, where a token reading peels the same layers.
- **JSON ↔ EDN** (`convert_claims`): integer lexemes that fit CBOR become
  ints, other numbers floats; EDN → JSON reports the first node with no
  JSON form (`convert.not_representable`, by NodeId of the EDN document).
- **TypeScript.** Request DTO fields that serde fills in when absent are
  optional in the `ts` export (#34): `field?: T` for `#[serde(default)]`
  fields (an explicit `null` would not deserialize) and `field?: T | null`
  for `Option` fields.
- **Validation** renders the document first (for node ids), so unreadable
  bytes are a `parse` error. Report node ids are mapped to the nearest
  existing node. Lint inside `validate` checks only the key that verified.
- **Randomness.** Every random value is drawn from a ChaCha20 stream keyed
  by `SHA-256("tokenator-core/v1/" || purpose || 0x00 || seed)` with the
  caller's 32-byte seed; purposes are `issue`, `salts`, `sign`, `present`,
  `resign`, `edit`, and `keygen`. Without a seed, signing is deterministic
  (RFC 6979 ECDSA, FIPS 204 deterministic ML-DSA): COSE through
  `tokenator-cose`'s `rng: None`, JOSE by re-signing the issued JWT or
  KB-JWT with `sign_deterministic` (tokenator-jose always takes an RNG).
  No `HashMap` order reaches any output.

## Deviations from the top-level `ARCHITECTURE.md`

- The engine holds the registry; `registry_merge` returns a new snapshot
  (#29). `render`, `reencode`, `edit_disclosures` and friends take request
  DTOs; `reencode` returns the output *and* the re-encoded document.
- NodeIds use the physical SD-CWT path (`unprotected/17/N`), not a
  `disclosure/N/value` alias (#30).
- Key cards reference a single key as a JWK, as a COSE_Key when the kid is
  binary, or as PKCS#8 PEM for an expanded-only ML-DSA key.
- A slot filled by a decoy disclosure (`[salt]`) is listed in
  `undisclosed` with a `disclosure: None` mark: it hides no claim.
- `max_kb_age` is checked without skew for both families, as tokenator-cose
  does (tokenator-jose adds the skew; #35).
- COSE `add_decoy`/`remove_digest` return `unsupported` until
  tokenator-cose edits payload digests (#32).
