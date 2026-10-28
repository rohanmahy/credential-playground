# tokenator-edn test plan

Grammar reference: **draft-ietf-cbor-edn-literals-28** (September 2026,
"Concise Diagnostic Notation (CDN)"), §2–§5, including the ABNF in §5.1–§5.2.
The `hash` app-extension is defined in §3.4 of that draft (`float` in §3.7,
`b1`/`t1` in §3.5, `ilbs`/`ilts` in §3.6). The unresolved-extension tag 999
comes from -27 §5.1; -28 dropped it (see "Decisions" below).

Integration tests live in `tests/`. Shared helpers are in `tests/common/mod.rs`:
`h()` parses hex, `hex()` renders it, `enc()` parses EDN and encodes it in
Preserve mode, `rt()` checks decode → print → parse → encode(Preserve) for a
byte string under several print options, `check_span_map()` checks the
invariants of a `SpanMap` against the item, the bytes and the text, and
`deep()` runs a closure on a thread with a large stack.

| File | What it covers |
|---|---|
| `vectors.rs` | Every `.edn`/`.cbor` pair in `testdata/cbor-test-vectors`: parsing the `.edn` file and encoding it gives exactly the `.cbor` file; the decoded `.cbor` file printed (compact, indented, annotated) parses back to the same bytes; every good `encoded` byte string survives decode → print → parse → encode(Preserve) under each print option; every `decoded` item prints and re-parses to the same encoding; span-map invariants hold on whole files. A guard test fails if a vector file is not wired in. |
| `appendix_a.rs` | Every RFC 8949 Appendix A example: the RFC diagnostic form parses to the RFC bytes, and decoding the bytes prints exactly the RFC form (with `_2`/`_3` added on the non-preferred f32/f64 infinities and NaNs, and with `ascii` escapes for the escaped text examples). |
| `grammar.rs` | Every grammar feature: all number forms (decimal, `+`/`-` signs, `-0`, `.5`, `3.`, exponents, `0x`/`0o`/`0b` in both cases, hex floats, `Infinity`/`-Infinity`/`NaN`, bignums to tags 2/3, leading-zero errors, overflow), text strings (JSON escapes, `\u{…}`, surrogate pairs, raw newlines, CR dropped, rejected tabs/controls/lone surrogates), single-quoted byte strings (their escape restrictions), raw strings (backquote delimiters, leading-newline and space-stripping rules), embedded CBOR `<<…>>` (nesting, indicators inside), arrays/maps (optional commas, trailing commas, `[[][]]` rejected, duplicate keys and arrival order kept), tags (leading zeros, u64 range), `simple(n)` (range, 24–31 rejected), `true`/`false`/`null`/`undefined`, streamstrings `(_ …)`, `''_`/`""_`, CRLF vs LF giving the same result, `parse_seq`. |
| `indicators.rs` | Encoding indicators reproduce exact non-preferred bytes: `_i`, `_0`–`_3` on ints, negative ints, byte/text strings, arrays, maps, tags, floats (`1.5_2`, `NaN_3`, `-Infinity_2`); `_` on arrays/maps; too-small indicators are errors (`256_0`, `1.1_1`, `24_i`); `_` on a scalar is an error; reserved indicators (`_4`–`_7`, `_x`) are accepted with a warning; and the printer emits indicators only where the encoding is not preferred (default), always, or never. |
| `extensions.rs` | `h` (blank space and all comment kinds inside, odd digits, bad digits, `h```), `b64` (classic and url alphabets, padding, `#` comments, `/` as data), `dt`/`DT` (Table 3), `ip`/`IP` (Table 4, `::`, prefixes truncated per RFC 9164, bad input), `hash` (Table 5, SHA-384, SHA-256/64, text input, unknown algorithm, non-string input), `b1`/`t1` (§3.5 examples, invalid UTF-8 from `t1`), `ilbs`/`ilts` (§3.6 table), `float` (§3.7 examples, wrong lengths, narrowing), unknown prefixes (opaque tag-999 values with a warning, or an error under the strict policy), round-tripping opaque values through the printer, mixed-case prefixes rejected, reserved names, custom extensions via the `AppExtension` trait (including replacing a built-in). |
| `comments.rs` | `/ … /`, `/* … */` (including `/` and `*` inside), `#` and `//` end-of-line comments, a comment at end of input without a newline, `//` no longer an empty comment, `/*foo/` running to `*/`, comments as separators, unterminated comments as errors. |
| `printer.rs` | Exact compact and indented output for scalars, nested containers, tags, indefinite items, streamstrings vs `ilbs`/`ilts` style, empty containers, indent width; text escaping (default UTF-8 vs `ascii`); float formatting (always re-parses as a float, RFC-style exponents); embedded-CBOR rendering (`Off`, `Containers`, `AnyItem`, tag 24, invalid embedded bytes stay `h''`); `dt''`/`ip''` output forms used only when they re-encode exactly; base64 byte style; annotator comments (placement, sanitizing `/` and `*/`, key and value positions). |
| `spans.rs` | `SpanMap` from `print`: text byte ranges, 0-based line ranges, CBOR spans (absolute, also inside embedded CBOR), in pre-order; every node has exactly one entry; ranges nest; every text range re-parses to exactly the bytes of its CBOR span; arrival order (never sorted); `Path` display/parse and lookups (`get`, `innermost_at`). `Parsed::spans` from `parse_with`: source ranges for nested input, comments excluded, embedded children and chunks. |
| `hex.rs` | `annotated_hex`: one row per data item plus break rows, head/payload ranges, depth, path, head descriptions (`unsigned(1)`, `array(*)`, `float16`, …), annotator comments, embedded-CBOR rows with absolute offsets, and row-for-row alignment with the indented printer's `SpanMap` (same paths in the same order). |
| `datetime.rs` | `Instant` conversions: RFC 3339 ↔ epoch (int and float, fractional seconds, negative epoch with fractions, nanosecond precision, rounding of float epochs), time-zone offsets normalized to UTC and rendered for a given offset, lowercase `t`/`z`, leap-second `:60`, invalid dates (month/day/leap year/hour/minute), year range; tags 0, 1, 100, 1004 (RFC 8943) to and from items, including negative days; EDN forms including `dt''`/`DT''`. |
| `errors.rs` | Malformed EDN: each error kind with its byte offset and 1-based line/column (columns count characters, CRLF is one line break), `Display` text, depth limit (`MAX_DEPTH + 1` nested containers fail cleanly; `MAX_DEPTH` succeeds). |
| `properties.rs` | proptest. Random strings (arbitrary Unicode and EDN-like alphabets) never panic `parse`, `parse_seq`, or `parse_with`. Random items built with the tokenator-cbor builders (random widths, indefinite lengths, chunks, floats incl. NaN payloads, tags, simple values) satisfy print → parse → encode(Preserve) == encode(Preserve) for every print option; decoding their bytes and printing gives a valid `SpanMap` and aligned hex rows. Random instants survive RFC 3339 and epoch round trips. |

## Decisions encoded in the tests

Open questions on these are tracked in issues #14 (grammar) and #15
(printer, hex, `hash`, date/time).

- **String juxtaposition is gone** (-28 §2.3): `"a" "b"` is two items (inside
  arrays) or trailing input (at top level). Concatenation is `b1<<…>>` /
  `t1<<…>>`. SPEC §8 "concatenated strings" is met by `b1`/`t1`.
- **Unknown app-extensions** become `999([prefix, [args…]])` (the -27 §5.1
  shape; for a string literal the args array holds one text string) plus a
  `WarningKind::UnknownExtension`. The arguments keep their encoding
  indicators. The printer turns such a tag back into `prefix'…'` /
  `prefix<<…>>` when that re-encodes exactly and the prefix is not built in.
  `UnknownExtensions::Error` makes them a parse error instead.
- **Ellipses** (`...` inside `h''`) are an error (`EdnErrorKind::Ellipsis`):
  -28 removed their CBOR representation.
- **Streamstrings** `(_ …)` are accepted (deprecated, no warning) and are the
  printer's default for indefinite strings; `IndefiniteStringStyle::AppExtension`
  prints `ilbs<<…>>`/`ilts<<…>>`.
- **Reserved encoding indicators** (`_4`–`_7`, `_foo`) and indicators on
  bignum literals are accepted and ignored with a warning. An indicator is
  `_` plus the longest run of word characters (`1_i0` is reserved `i0`).
- **Built-in extensions**: `h`, `b64`, `dt`, `ip`, `hash` (SPEC) plus `b1`,
  `t1`, `ilbs`, `ilts`, `float` (the vectors need `float`). `hash` supports
  -16 (default), -43, -44, -15, by number or registry name.
- **Float literals** that overflow binary64 (`1e400`) are errors; indicators
  too narrow for the exact value are errors.
- **`float'…'` without an indicator** follows preferred serialization (the
  shortest exact width); `float'fe00'_2` widens. The printer writes any NaN
  other than the canonical one as `float'…'` with the shortest exact bytes plus
  an indicator if the stored width is wider.
- **Printer float text**: shortest round-trip digits, always with `.` or `e`;
  plain notation for `1e-5 <= |x| < 1e16`, otherwise `d.ddde±N` with at least
  one fractional digit (`1.0e+300`, `5.960464477539063e-8`), matching RFC 8949
  Appendix A.
- **Bignums** print as `2(h'…')` / `3(h'…')`, never as decimal.
- **End-of-line comment at EOF** without a newline is accepted.
- **Positions**: `offset` is a byte offset; `line` and `column` are 1-based;
  columns count Unicode scalar values. `SpanMap` lines are 0-based row
  indices (`lines` is a half-open range), aligned with `HexRows`.
- **Text ranges** cover an item and its encoding indicator, not annotator
  comments. Items built by an extension share the literal's source range.
- **CBOR spans** in a `SpanMap` are `Some` only for decoded items
  (`span.end > 0`); inside embedded CBOR they are absolute offsets into the
  outer bytes (only for definite-length byte strings).
- **Embedded CBOR auto-detection** (`EmbeddedCbor::Containers`, what the UI
  uses): a byte string is shown as `<<…>>` if it decodes as exactly one item
  that is an array, map, or tag, or if it is the content of tag 24 or 63.
  `AnyItem` accepts any single item; `Off` (the default) always prints `h''`.
- **Hex rows**: break bytes get their own row at the container's depth;
  descriptions use the raw argument (`negative(0)` for -1), `(*)` for
  indefinite length, `float16`/`float32`/`float64` for floats.
- **Date/time**: leap second `:60` maps to the next second; offsets are
  normalized to UTC; lowercase `t`/`z` are accepted; a space instead of `T`
  is rejected; years 0000–9999; fractional digits beyond nanoseconds are
  truncated; float epochs round to the nearest nanosecond; `dt''` with a
  fraction yields the correctly rounded binary64 of the decimal epoch.
- **Depth**: `MAX_DEPTH` (1024, from tokenator-cbor) nested arrays, maps,
  tags, and embedded sequences; deeper input is `EdnErrorKind::DepthLimit`.
  Deep tests run on an 8 MiB thread.

## Running

`cargo test -p tokenator-edn`. Property tests run 2048 cases on strings and
512 on items.
