# tokenator-jose

JWS, JWT, SD-JWT, and KB-JWT. See the top-level `ARCHITECTURE.md` for where
this fits and `TEST-PLAN.md` for the decisions the tests encode.

| file | contents |
|---|---|
| `b64.rs` | strict unpadded base64url |
| `parse.rs` | `Token`, `Jws`, `SdJwt`, `B64Part`, `Disclosure`, diagnostics, `parse` |
| `sd.rs` | disclosure views, `_sd_alg`, digests, `process` and `SdReport` |
| `issue.rs` | `IssueOptions`, `JsonStyle`, `issue` |
| `json_out.rs` | the private writer behind `JsonStyle` |
| `present.rs` | `select`, `present`, KB-JWT creation |
| `verify.rs` | `verify_signature`, `check_time_claims`, `check_kb_jwt` |
| `manipulate.rs` | `resign`, `assemble_compact`, `tamper`, `edit_disclosures`, conversions |
| `lint.rs` | header facts, duplicate members, `cnf`, key findings |
| `error.rs` | `JoseError` |

## Design

- Parsed parts borrow the input; each `B64Part` owns only its decoded
  bytes. JSON trees are parsed on demand from those bytes, so they borrow
  the token and their spans are relative to the decoded part.
- Signatures, digests, and `sd_hash` are always computed over the original
  encoded text, never re-serialized.
- Each `Jws` keeps its source: the compact text, or the parsed JSON
  envelope (boxed). Output that changes one thing copies the rest:
  `tamper` splices the new text into the target part's span; `resign`,
  `present` and `edit_disclosures` edit a copy of the envelope tree and
  print it with `Original` style.
- `process` is one depth-first walk (`Walker` in `sd.rs`) that lists slots,
  fills them, and builds the processed tree at once. An object's plain
  members are processed in order and its disclosed ones appended in `_sd`
  order. Disclosures are decoded once up front; each fills at most one
  slot, so recursion through disclosures cannot loop.
- `issue` validates everything first, then draws all salts, then random
  decoys, then signs, so a seeded RNG gives the same token. Disclosures
  are created by a post-order walk (inner first, document order).
- Generated JSON (`JsonStyle`) comes from `json_out.rs`, not
  `tokenator-json`'s printer, because strings are re-escaped by the style
  (Python `json.dumps` rules for `Spaced`). TODO: switch `Spaced` to the
  canonical-spacing printer from feat/json-3-4 when it lands.

## Caveats

- Each part is depth-limited by `tokenator-json`, but a chain of nested
  disclosures adds up: processing recurses once per level across the
  whole chain, so thousands of chained disclosures could exhaust a small
  (e.g. wasm) stack.
