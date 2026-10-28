# tokenator-detect

Credential and key format detection and unwrapping. See the top-level
`ARCHITECTURE.md` for where it sits, and `TEST-PLAN.md` for the decisions
the tests encode.

## Modules

| File | Role |
|---|---|
| `lib.rs` | Public types (`Candidate`, `Layer`, `Kind`, `PathSegment`), `detect`, `unwrap_layers`, `rewrap`, `json_pointer`. |
| `detect.rs` | The search: explore readings depth first, rank, dedup, cap. |
| `classify.rs` | Structural classifiers: JOSE compact, JSON kinds (JWS JSON, SD-JWT JSON, JWK/JWKS, claims), CBOR kinds (COSE_Sign1 family, COSE_Key/KeySet, claims), PEM, EDN look-alike scan. Base confidences live in `classify::conf`. |
| `layers.rs` | One layer at a time: `unwrap_one` (positional layers return sub-slices of a `Cow`) and `wrap_one`. |
| `codec.rs` | Hand-written base64 (both alphabets), hex, percent-encoding, JSON string escaping, CBOR tag heads. |

## How detection works

Each node of the search is a byte string plus its `Origin`: either an offset
into the input (only positional layers so far, so the node borrows the input)
or the frozen range that the first decoding layer consumed. At each node:

1. **CBOR.** If the bytes are one CBOR item, classify it; a tag is peeled as
   a `CborTag` child (the inner item's span, so still positional). A map,
   array, or tag stops here: binary input is never trimmed or read as text.
2. **Cleanup (exclusive).** `Trim` (root only), then `Quotes`,
   `AuthorizationHeader`, `BearerPrefix`, each at most once and only before
   any other layer. When one applies, only the cleaned text is explored.
3. **Text.** Classify JOSE compact, PEM, and JSON (whose string fields become
   `JsonField` children, first member per name, in document order). EDN is
   only considered for top-level text that is not JSON.
4. **Decodings (branching).** `UrlEncoded` (needs a `%XX`, and not on JSON
   text), `Hex`, and base64 each add a child, so hex text is also read as
   base64. Decoded children own their bytes.

Confidence is the kind's base minus a small per-layer penalty (hex 1, base64
2, percent 1), so a hex reading beats a base64 one of the same kind. Results
are stably sorted (ties keep discovery order), deduplicated by
`(kind, layers)`, and capped at 64.

## Bounds

`MAX_LAYERS` (16) per candidate, 512 explored nodes per input, and a byte
budget of 8x the input (at least 1 MiB). Every child is no larger than its
parent, CBOR and JSON parsers have depth limits, and each node does linear
work, so detection is linear in the input with a constant factor. A 1 MB
adversarial input takes well under a second in release.

## Conventions worth knowing

- Base64 text needing no `=` is recorded as `Base64Std { padded: true }` for
  the classic alphabet and `Base64Url { padded: false }` for base64url.
  Decoding requires zero trailing bits and rejects mixed alphabets.
- A 4-array is read as COSE_Sign1 only when untagged or directly under tag
  18, 61, or 55799, so COSE_Mac0 (tag 17) and COSE_Sign (98) are not.
- `Kind::CoseKey` gets high confidence only for an integer `kty` registered
  with IANA (via `tokenator-registry`); a text `kty` ranks below
  `CborClaims`, because CWT `iss` is also label 1.
- JWS JSON, SD-JWT JSON, JWK, and JWK Set documents are not searched for
  token fields; other JSON is.
