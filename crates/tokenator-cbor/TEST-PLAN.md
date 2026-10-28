# tokenator-cbor test plan

Integration tests live in `tests/`. Shared helpers are in `tests/common/mod.rs`:
`h()` parses hex, `diag()` renders an item as EDN-like text that shows its
encoding details (`_0`..`_3`/`_i` indicators, `_ ` indefinite, float width
suffixes), `sem()` renders only the meaning (bignums folded into integers,
floats by bit pattern), `sem_plus()`/`sem_canonical()` additionally treat all
NaNs as one (and the latter sorts maps), `plus()`/`det()` re-encode hex in
PreferredPlus/Deterministic mode, and `check_spans()` checks span invariants
against the input, including that every sub-item re-encodes to exactly its own
bytes.

Serialization terms follow draft-ietf-cbor-serialization-11: preferred-plus
(§4.1) and deterministic (§5.1).

| File | What it covers |
|---|---|
| `appendix_a.rs` | Every RFC 8949 Appendix A example: decoded value, byte-exact Preserve round trip, spans, PreferredPlus and Deterministic output, and whether findings are reported. |
| `vectors.rs` | All files from `testdata/cbor-test-vectors` (hildjj/cbor-test-vectors). Good cases: decode, Preserve round trip, spans, same meaning as `decoded`, no preferred-plus findings except `NonCanonicalNaN` when `roundtrip` is true, PreferredPlus and Deterministic output that keep the meaning (NaNs canonical), are idempotent, and have no findings. Bad cases must fail to decode. A guard test makes sure that new vector files get wired in. |
| `roundtrip.rs` | Non-preferred arguments, indefinite items, and floats round trip exactly under Preserve (every NaN bit pattern too) and become shortest/definite under PreferredPlus and Deterministic, which write every NaN as `f97e00`. PreferredPlus keeps arrival order (including duplicates and keys that become equal); only Deterministic sorts. PreferredPlus equals Deterministic without maps (§5.3.2). `encode` fails with `EncodeError::InvalidSimple` for Simple(24..=31), at any depth and in every mode. Also builders, `with_width`, too-narrow widths, stale chunks, and edits that leave other bytes untouched. |
| `zero_copy.rs` | Definite-length bytes and text are `Cow::Borrowed` and point into the input, at any nesting depth. Indefinite strings are owned, but their chunks borrow. |
| `spans.rs` | `start`/`end`/`head_len` for scalars, strings, chunks, nested arrays, maps, tags, indefinite items (the break byte is included), sequences (absolute offsets), and a mixed COSE-like document. |
| `findings.rs` | Every `FindingKind`, each tied to a draft rule: exact span (head only for arguments; whole item for floats, NaNs, bignums, indefinite items, and map order), kind, and suggested bytes. Non-canonical NaNs (wide quiet NaN, payloads, signaling, negative) suggest `f97e00`. Bignums that fit major type 0/1 suggest the plain integer, larger ones with leading zeros the stripped bignum. Ordering (by start, then kind), nested positions, combined findings, key order judged on deterministic key encodings (so `c24101` and `01` are equal keys), applying a finding fixes it, and PreferredPlus/Deterministic output is clean. |
| `duplicates.rs` | `duplicate_keys`: keys compared by deterministic encoding (non-preferred args, bignums, NaNs, float widths, indefinite vs definite, maps with different order all collide; `0.0`/`-0.0`, `1`/`1.0`, text/bytes do not). Paths through arrays, keys, values, and tags; outer before inner; later occurrences paired with the first; built items; nesting at `MAX_DEPTH`. Decoding still keeps duplicates. |
| `malformed.rs` | Empty input, truncated heads and content, reserved ai 28–30, indefinite length on major types 0/1/6, stray breaks, odd indefinite maps, bad chunks, invalid UTF-8, `f8 00`..`f8 1f`, trailing bytes, `MAX_DEPTH == 512` and exact depth behavior, 1 MB depth bombs, huge declared lengths, and the RFC 8949 Appendix F not-well-formed list. |
| `tags_simple.rs` | Tags kept verbatim (unknown tags, tag numbers up to 2^64-1, nested tags, unvalidated tag content). Bignums round trip under Preserve and are rewritten by PreferredPlus/Deterministic (§4.1 rule 5); tags 2/3 over non-bytes are left alone. All simple values 0–19 and 32–255 are kept; the SD-CWT simple(59) map key works. |
| `properties.rs` | proptest. Random bytes never cause a panic, and any successful decode round-trips and yields clean PreferredPlus/Deterministic output. Arbitrary built items (random widths, indefinite lengths, chunks, floats, NaN payloads, bignums) survive Preserve unchanged; PreferredPlus and Deterministic outputs conform and are idempotent; findings are empty exactly when the bytes already conform; an invalid simple anywhere fails every mode. |

## Decisions encoded in the tests

- Only well-formedness and UTF-8 are validated. Tag content is not checked, so
  the two "date:" bad vectors are accepted (tag validation is future work, #25).
- Preserve reproduces the input exactly, NaN bit patterns and bignums included.
- PreferredPlus and Deterministic follow draft-ietf-cbor-serialization-11 §4.1
  and §5.1: every NaN becomes `f97e00`; bignums lose leading zeros and become
  major type 0/1 when they fit. Only Deterministic sorts map keys.
- Findings flag and suggest, never modify (#7). `NonCanonicalNaN` and
  `NonPreferredBignum` are new kinds.
- Duplicate map keys are kept by decode and every encode mode, are not a
  key-order violation, and are reported by `duplicate_keys`, which compares
  deterministic encodings.
- `decode` rejects trailing bytes. `decode_seq` accepts empty input (#8).
- `MAX_DEPTH = 512` nested arrays, maps, and tags. Chunks don't count (#8).
- `encode` returns `Err(EncodeError::InvalidSimple(n))` for Simple(24..=31)
  in every mode (#8).
- Built items carry `Span::default()`.

## Running

`cargo test -p tokenator-cbor`. Property tests run 4096 cases on bytes and
1024 on items. A longer fuzz run belongs to the `fuzz/` cargo-fuzz targets.
