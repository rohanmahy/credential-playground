# tokenator-detect test plan

Integration tests live in `tests/`. Fixtures are real examples under
`testdata/tokens/` and `testdata/keys/` at the repo root (sources in their
`README.md`). Shared helpers are in `tests/common/mod.rs`: fixture loading,
independent base64/hex/percent encoders (so expectations never use the code
under test), CBOR builders on top of `tokenator-cbor`, candidate lookups, and
`check_invariants()`, which every detection test runs:

- candidates are sorted by non-increasing confidence, and confidence <= 100;
- `payload_range` lies inside the input;
- `layers.len() <= MAX_LAYERS`;
- `unwrap_layers(input, &c.layers)` succeeds for every candidate;
- if every layer is positional, the payload equals `input[payload_range]`;
- `detect` is deterministic (two calls give equal results).

| File | What it covers |
|---|---|
| `jose.rs` | JWS compact / JWT from RFC 7519 and RFC 7515 A.1–A.5 (HS256, RS256, ES256, a non-JSON payload → `JwsCompact`, Unsecured JWS/JWT with an empty signature). SD-JWT compact from RFC 9901 §5.1 (no KB, trailing `~`) and §5.2 (with KB-JWT). JWS JSON general and flattened (RFC 7515 A.6, A.7) and SD-JWT JSON (RFC 9901 §8.2 with and without `kb_jwt`, §8.3 general). Negatives: a header that is not JSON, a header without `alg` (lower confidence), wrong segment counts, JWE-shaped five-part tokens. |
| `cose.rs` | RFC 8392 A.3 signed CWT: tag 18, tag 61 + 18, untagged, binary and hex. RFC 9052 C.2.1 COSE_Sign1 with a text payload → `CoseSign1`, not `Cwt`. SD-CWT and SD-KBT from draft-ietf-spice-sd-cwt-08 (minimal and nested). Synthetic COSE_Sign1s built with `tokenator-cbor` for each SD signal on its own (`sd_alg` 170 protected, `sd_claims` 17 unprotected, `simple(59)` in the payload, `kcwt` 13 protected), detached payloads, and an empty protected header. Negatives: COSE_Mac0 (RFC 8392 A.4, tag 61 + 17), 4-arrays with a non-bstr protected header, 3- and 5-arrays, trailing bytes. |
| `claims.rs` | Unsigned claim sets: JSON (RFC 7519 §3.1 with CRLF, RFC 9901 §5.1 input), CBOR (RFC 8392 A.1), and EDN text (draft-08 Figure 4 and small snippets) → `EdnText`, with lower confidence than structural kinds. JSON arrays, scalars, and prose are not claim sets. |
| `keys.rs` | JWK (RFC 9901 A.5, draft-08 C.1), JWK Sets (RFC 7517 A.1–A.3), COSE_Key (RFC 8392 A.2.1 and A.2.3, draft-08 C.1), COSE_KeySet (RFC 8152 C.7.1), PEM (SPKI, PKCS#8, SEC1, certificate, and a bundle of several blocks → one `Pem` candidate with every label). `Kind::is_key`. Binary keys ending in `0x0a` are not trimmed. |
| `layers.rs` | Every layer kind on its own and in combination, checking the exact layer list and `payload_range`: `Trim`, `Quotes`, `AuthorizationHeader`, `BearerPrefix`, `UrlEncoded`, `JsonField` (nested objects, arrays, several fields), `Base64Url`/`Base64Std` (padded or not, wrapped), `Hex` (lower/upper, spaces, colons, newlines, mid-byte line breaks), `CborTag` (18, 61, 55799). Combinations include `Authorization: Bearer <base64url of tagged CWT>`, `{"credential":"<sd-jwt>"}`, URL-encoded JSON containers, URL-encoded SD-JWT (`~` as `%7E`), base64 of base64, and JSON fields holding base64/hex CBOR. |
| `ambiguity.rs` | Ranking and multiple readings: token fields outrank their container's `JsonClaims`; one candidate per token field; key kinds outrank the claims catch-alls and vice versa for real claim sets; SD-KBT > SD-CWT > CWT > COSE_Sign1; hex readings outrank base64 readings of hex-looking text; JSON outranks EDN. |
| `rewrap.rs` | `rewrap` output for each layer on its own (exact bytes, including preferred CBOR tag heads and JSON escaping), layer order, `json_pointer` (RFC 6901 escaping), `unwrap_layers` success and failure (with the failing layer index), and `rewrap(unwrap_layers(x)) == x` for every top candidate of a table of canonical inputs. |
| `robustness.rs` | Empty input, whitespace only, NUL bytes, invalid UTF-8, lone quotes/prefixes, truncated fixtures (every prefix of a JWT and a CWT), bit-flipped fixtures, 4 MiB inputs (base64 alphabet, hex digits, `{`, CBOR `0x81` depth bombs), 20 levels of base64 nesting (capped at `MAX_LAYERS`), and many JSON fields. |
| `proptest.rs` | Never panics on arbitrary bytes, arbitrary strings, token-alphabet strings, and mutated fixtures, and `check_invariants` holds. `rewrap` then `unwrap_layers` round-trips arbitrary payloads through arbitrary layer stacks. |

## Decisions encoded in the tests

- Layers are listed outermost first, and only peeled layers are recorded (an
  exact token has no layers). `Trim` is always the outermost layer.
- Raw binary is tried as-is. Whitespace is never trimmed from input that
  parses as CBOR, so a COSE_Key ending in `0x0a` keeps its last byte.
- Tags 61 and 18 are both layers (`[CborTag(61), CborTag(18)]`), and the
  payload of a COSE kind is the untagged 4-array.
- Confidence is a `u8` in 0..=100 so results compare exactly across WASM and
  native. Tests only check relative order.
- The catch-alls: every JSON object also yields `JsonClaims`, and every CBOR
  map also yields `CborClaims`, at lower confidence than a more specific kind.
- An SD-JWT is recognized by its `~` structure alone. `kb` is true when the
  last part is non-empty.
- SD-CWT signals in draft-08: `sd_alg` (170) in the protected header,
  `sd_claims` (17) in the unprotected header, or a `simple(59)` key in the
  payload. SD-KBT: `kcwt` (13) in the protected header. SD-KBT wins over
  SD-CWT when both apply.
- COSE_Mac0, COSE_Encrypt0, and JWE are not supported in v1. They produce no
  JOSE/COSE signed kind (they may still produce catch-alls or nothing).
- Several PEM blocks in one input give a single `Pem` candidate listing every
  label; `tokenator-keys` imports them all.
- `UrlEncoded` treats `+` as a literal plus (tokens carry base64 `+`).
- `rewrap` is canonical: base64 lines and hex lines joined with `\n`,
  percent-escapes upper-case, JSON compact, preferred CBOR tag heads. Inputs
  that differ from that (mid-byte hex breaks, CRLF, lower-case `%xx`, a long
  tag head) are detected but not expected to round-trip byte-for-byte.
- Nothing recognized means an empty `Vec`, not an error.

## Running

`cargo test -p tokenator-detect`. Property tests run 1024 cases on bytes and
strings and 256 on mutated fixtures. The cargo-fuzz `detect` target belongs
in `fuzz/`.
