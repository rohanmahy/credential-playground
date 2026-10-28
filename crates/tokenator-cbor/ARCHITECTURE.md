# tokenator-cbor

Span-preserving, zero-copy CBOR decoder/encoder. See the top-level
`ARCHITECTURE.md` for its role; this file covers the internals.

| Module | Contents |
|---|---|
| `item.rs` | `Item`, `Value`, `Span`, `Width`, `FloatWidth`; builders; `into_owned` |
| `decode.rs` | `decode`, `decode_seq`, `MAX_DEPTH` |
| `encode.rs` | `encode`, `EncodeMode` (Preserve, PreferredPlus, Deterministic); internal `Mode` |
| `findings.rs` | `preferred_plus_findings`, `deterministic_findings`, `duplicate_keys` |
| `float.rs` | bit-exact f16/f32/f64 conversions |
| `error.rs` | `DecodeError`, `DecodeErrorKind`, `EncodeError` |

## Design notes

- **Iterative decoder.** Open arrays, maps, and tags live on an explicit
  `Vec<Frame>`, so nesting costs heap, not call stack. The depth check fires
  when an item would sit inside more than `MAX_DEPTH` containers.
- **Untrusted lengths.** A string length is checked against the remaining
  input before slicing. Array/map counts only size the initial `Vec` up to
  what the remaining input could hold; a short input then ends in
  `UnexpectedEof` (or `UnexpectedBreak` if a break comes first).
- **Zero copy.** Definite strings are `Cow::Borrowed` slices of the input.
  Indefinite strings own their concatenation; their chunks borrow.
- **Floats** go through bit patterns only (no `as` casts, no hardware
  conversion), so signaling NaNs and payloads survive. Narrowing succeeds
  only when no bit is lost; "preferred" means the shortest exact width.
- **Encoder fallbacks** instead of errors: a too-narrow width becomes the
  preferred width, a too-narrow float width the shortest exact one, and stale
  chunks are replaced by the value as one chunk. The only encode error is
  `Simple(24..=31)`, rejected in every mode.
- **PreferredPlus / Deterministic** (draft-ietf-cbor-serialization-11 §4.1,
  §5.1) share one code path: shortest heads, definite lengths, shortest exact
  floats, every NaN as `f97e00`, and bignums rewritten (no leading zeros;
  major type 0/1 when they fit in 64 bits). Only Deterministic sorts map
  entries, by their deterministic key encodings, stably.
- **Findings** only report. They reuse the encoder: `IndefiniteLength` and
  `NonPreferredBignum` bytes come from PreferredPlus, `MapKeyOrder` bytes
  from Deterministic. A finding whose replacement cannot be encoded is
  dropped. Results are sorted stably by `(start, kind)`.
- **Duplicates.** `duplicate_keys` walks the tree in pre-order and, per map,
  keeps a hash map from deterministic key encoding to the first entry index.
- **Stack use.** Encoding, findings, and drop recurse once per level.
  `into_owned` uses an explicit stack. At `MAX_DEPTH` (512) everything,
  including the derived `Clone`, fits in 1 MiB in release builds and 2 MiB
  in debug builds (a unit test checks this).
