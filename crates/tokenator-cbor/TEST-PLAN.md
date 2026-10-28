# tokenator-cbor test plan

Integration tests live in `tests/`. Shared helpers are in `tests/common/mod.rs`:
`h()` parses hex, `diag()` renders an item as EDN-like text that shows its
encoding details (`_0`..`_3`/`_i` indicators, `_ ` indefinite, float width
suffixes), `sem()` renders only the meaning (bignums folded into integers,
floats by bit pattern), and `check_spans()` checks span invariants against the
input, including that every sub-item re-encodes to exactly its own bytes.

| File | What it covers |
|---|---|
| `appendix_a.rs` | Every RFC 8949 Appendix A example: decoded value, byte-exact Preserve round trip, spans, Deterministic output, and whether findings are reported. |
| `vectors.rs` | All files from `testdata/cbor-test-vectors` (hildjj/cbor-test-vectors). Good cases: decode, Preserve round trip, spans, same meaning as `decoded`, no preferred findings when `roundtrip` is true, and Deterministic output that keeps the meaning, is idempotent, and has no findings. Bad cases must fail to decode. A guard test makes sure that new vector files get wired in. |
| `roundtrip.rs` | Non-preferred arguments (ints, lengths, tags), indefinite strings/arrays/maps (including empty and nested ones), and floats (f32/f64 that fit in f16, subnormals, NaN payloads, signaling NaNs) round trip exactly under Preserve and become preferred under Deterministic. Also covers map arrival order, duplicate keys, §4.2.1 key sorting (by the deterministic key encoding), `decode_seq`, builders, `with_width`, the fallback for widths that are too narrow, stale chunks after an edit, and edits that leave the other bytes untouched. |
| `zero_copy.rs` | Definite-length bytes and text are `Cow::Borrowed` and point into the input, at any nesting depth. Indefinite strings are owned, but their chunks borrow. |
| `spans.rs` | `start`/`end`/`head_len` for scalars, strings, chunks, nested arrays, maps, tags (including nested tags and long tag heads), indefinite items (the break byte is included), sequences (absolute offsets), and a mixed COSE-like document. |
| `findings.rs` | Every kind of finding: exact span (only the head for arguments; the whole item for floats, indefinite items, and map order), kind, and preferred bytes. Also checks ordering (by start, then kind), nested positions, and that `preferred_findings` ignores key order. For `deterministic_findings`: key order uses the deterministic key encoding, duplicates are not an order violation, and indefinite unsorted maps report both findings. Applying a finding's bytes fixes it without changing the meaning. |
| `malformed.rs` | Empty input, truncated heads and content, reserved ai 28–30 for every major type, indefinite length on major types 0/1/6, stray breaks, an odd number of items in an indefinite map, bad chunks, invalid UTF-8 (including a character split across chunks), `f8 00`..`f8 1f`, trailing bytes, exact `MAX_DEPTH` behavior, 1 MB depth bombs, huge declared lengths (which must fail fast), and the RFC 8949 Appendix F not-well-formed list. Error offsets are checked where they are unambiguous. |
| `tags_simple.rs` | Tags kept verbatim: unknown tags, tag numbers up to 2^64-1, nested tags, tag content that is not validated, and bignums that are not rewritten. All simple values 0–19 and 32–255 are kept, and the SD-CWT simple(59) map key works. |
| `properties.rs` | proptest. Random bytes and CBOR-like bytes never cause a panic, and any successful decode round-trips. Arbitrary built items (random widths, indefinite lengths, chunks, floats) survive Preserve unchanged. Deterministic output is canonical, and findings are empty exactly when the bytes are already deterministic. |

## Decisions encoded in the tests

- Only well-formedness and UTF-8 are validated. Tag content is not checked, so
  the two "date:" bad vectors are accepted.
- Preferred serialization does not normalize bignums (tags 2 and 3).
- NaN payloads are preserved. The preferred form of a NaN is the shortest
  width that keeps its payload.
- Duplicate map keys are kept, are not a key-order violation, and Deterministic
  keeps them in arrival order.
- `decode` rejects trailing bytes. `decode_seq` accepts empty input.
- `MAX_DEPTH = 1024` nested arrays, maps, and tags. Chunks don't count.
- Built items carry `Span::default()`.

## Running

`cargo test -p tokenator-cbor`. Property tests run 4096 cases on bytes and
1024 on items. A longer fuzz run belongs to the `fuzz/` cargo-fuzz targets.
