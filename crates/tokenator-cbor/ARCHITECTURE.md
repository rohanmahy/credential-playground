# tokenator-cbor

Span-preserving, zero-copy CBOR decoder/encoder. See the top-level
`ARCHITECTURE.md` for its role; this file covers the internals.

| Module | Contents |
|---|---|
| `item.rs` | `Item`, `Value`, `Span`, `Width`, `FloatWidth`; builders; `into_owned` |
| `decode.rs` | `decode`, `decode_seq`, `MAX_DEPTH` |
| `encode.rs` | `encode`; internal `Mode` (Preserve, Preferred, Deterministic) |
| `findings.rs` | `preferred_findings`, `deterministic_findings` |
| `float.rs` | bit-exact f16/f32/f64 conversions |
| `error.rs` | `DecodeError`, `DecodeErrorKind` |

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
  chunks are replaced by the value as one chunk.
- **Findings** reuse the encoder: `IndefiniteLength` bytes come from the
  internal `Preferred` mode (no key sorting), `MapKeyOrder` bytes from
  `Deterministic`. Key order compares deterministic key encodings; equal keys
  are not a violation. Results are sorted stably by `(start, kind)`.
- **Stack use.** Encoding, findings, and drop recurse once per level.
  `into_owned` uses an explicit stack. At `MAX_DEPTH` everything fits in
  1 MiB in release builds and 2 MiB in debug builds (a unit test checks
  this). The derived `Clone` is the one exception: in debug builds it needs
  close to 2 MiB at that depth.
