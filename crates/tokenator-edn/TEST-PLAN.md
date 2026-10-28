# tokenator-edn test plan

Grammar reference: **draft-ietf-cbor-edn-literals-28** (September 2026,
"Concise Diagnostic Notation (CDN)"), §2–§5, including the ABNF in §5.1–§5.2.
The `hash` app-extension is defined in §3.4 of that draft (`float` in §3.7,
`b1`/`t1` in §3.5, `ilbs`/`ilts` in §3.6). The unresolved-extension tag 999
comes from -27 §5.1 and the ellipsis tag 888 from -27 §5.2; -28 dropped
both (see "Decisions" below). NaN vectors come from draft-bormann-cbor-numbers-03,
Appendix B.1.3, Table 2 (`testdata/cbor-numbers-nan/`).

Integration tests live in `tests/`. Shared helpers are in `tests/common/mod.rs`:
`h()` parses hex, `hex()` renders it, `enc()` parses EDN and encodes it in
Preserve mode, `rt()` checks decode → print → parse → encode(Preserve) for a
byte string under several print options, `rt_embedded()` does the same with
every decodable byte string listed as embedded CBOR (`all_bstr_paths()`
computes that list), `check_span_map()` checks the
invariants of a `SpanMap` against the item, the bytes and the text, and
`deep()` runs a closure on a thread with a large stack.

| File | What it covers |
|---|---|
| `vectors.rs` | Every `.edn`/`.cbor` pair in `testdata/cbor-test-vectors`: parsing the `.edn` file and encoding it gives exactly the `.cbor` file; the decoded `.cbor` file printed (compact, indented, annotated) parses back to the same bytes; every good `encoded` byte string survives decode → print → parse → encode(Preserve) under each print option; every `decoded` item prints and re-parses to the same encoding; span-map invariants hold on whole files. A guard test fails if a vector file is not wired in. |
| `appendix_a.rs` | Every RFC 8949 Appendix A example: the RFC diagnostic form parses to the RFC bytes, and decoding the bytes prints exactly the RFC form (with `_2`/`_3` added on the non-preferred f32/f64 infinities and NaNs, and with `ascii` escapes for the escaped text examples). |
| `grammar.rs` | Every grammar feature: all number forms (decimal, `+`/`-` signs, `-0`, `.5`, `3.`, exponents, `0x`/`0o`/`0b` in both cases, hex floats, `Infinity`/`-Infinity`/`NaN`, bignums to tags 2/3, leading-zero errors, overflow), text strings (JSON escapes, `\u{…}`, surrogate pairs, raw newlines, CR dropped, rejected tabs/controls/lone surrogates), single-quoted byte strings (their escape restrictions), raw strings (backquote delimiters, leading-newline and space-stripping rules), embedded CBOR `<<…>>` (nesting, indicators inside), arrays/maps (optional commas, trailing commas, `[[][]]` rejected, duplicate keys and arrival order kept), tags (leading zeros, u64 range), `simple(n)` (range, 24–31 rejected), `true`/`false`/`null`/`undefined`, streamstrings `(_ …)`, `''_`/`""_`, CRLF vs LF giving the same result, `parse_seq`. |
| `indicators.rs` | Encoding indicators reproduce exact non-preferred bytes: `_i`, `_0`–`_3` on ints, negative ints, byte/text strings, arrays, maps, tags, floats (`1.5_2`, `NaN_3`, `-Infinity_2`); `_` on arrays/maps; too-small indicators are errors (`256_0`, `1.1_1`, `24_i`); `_` on a scalar is an error; reserved indicators (`_4`–`_7`, `_x`) are accepted with a warning; and the printer emits indicators only where the encoding is not preferred (default), always, or never. |
| `extensions.rs` | `h` (blank space and all comment kinds inside, odd digits, bad digits, `h```), `b64` (classic and url alphabets, padding, `#` comments, `/` as data), `dt`/`DT` (Table 3), `ip`/`IP` (Table 4, `::`, prefixes truncated per RFC 9164, bad input), `hash` (behind the `hash` cargo feature: Table 5, SHA-384, SHA-256/64, text input; malformed input and unknown algorithms are errors with or without the feature; without it, `hash''` is a built-in whose evaluation is an extension error naming the feature), `b1`/`t1` (§3.5 examples, invalid UTF-8 from `t1`), `ilbs`/`ilts` (§3.6 table), `float` (§3.7 examples, wrong lengths, narrowing), unknown prefixes (opaque tag-999 values with a warning, or an error under the strict policy), round-tripping opaque values through the printer, mixed-case prefixes rejected, reserved names, custom extensions via the `AppExtension` trait (including replacing a built-in). |
| `comments.rs` | `/ … /`, `/* … */` (including `/` and `*` inside), `#` and `//` end-of-line comments, a comment at end of input without a newline, `//` no longer an empty comment, `/*foo/` running to `*/`, comments as separators, unterminated comments as errors. |
| `printer.rs` | Exact compact and indented output for scalars, nested containers, tags, indefinite items, streamstrings vs `ilbs`/`ilts` style, empty containers, indent width; text escaping (default UTF-8 vs `ascii`); float formatting (always re-parses as a float, RFC-style exponents); embedded CBOR only at listed paths (shown as a CBOR sequence; unlisted byte strings are never guessed; invalid, truncated, trailing-garbage, or empty content stays `h''`; nested embedded CBOR is listed explicitly through `Embedded(i)`; encoding details inside are kept), tags 24 (one item) and 63 (a sequence) with `EmbeddedCbor::tagged`, a COSE_Sign1 with its protected header and payload listed; `dt''`/`ip''` output forms used only when they re-encode exactly; base64 byte style; annotator comments (placement, sanitizing `/` and `*/`, key and value positions). |
| `spans.rs` | `SpanMap` from `print`: text byte ranges, 0-based line ranges, CBOR spans (absolute, also inside embedded CBOR), in pre-order; every node has exactly one entry; ranges nest; every text range re-parses to exactly the bytes of its CBOR span; arrival order (never sorted); `Path` display/parse and lookups (`get`, `innermost_at`). `Parsed::spans` from `parse_with`: source ranges for nested input, comments excluded, embedded children and chunks. |
| `hex.rs` | `annotated_hex`: one row per data item plus break rows, head/payload ranges, depth, path, head descriptions (`unsigned(1)`, `array(*)`, `float16`, …), annotator comments, embedded-CBOR rows with absolute offsets, and row-for-row alignment with the indented printer's `SpanMap` (same paths in the same order). |
| `datetime.rs` | `Instant` conversions: RFC 3339 ↔ epoch (int and float, fractional seconds, negative epoch with fractions, nanosecond precision, rounding of float epochs), time-zone offsets normalized to UTC and rendered for a given offset, lowercase `t`/`z`, leap-second `:60`, invalid dates (month/day/leap year/hour/minute), year range; tags 0, 1, 100, 1004 (RFC 8943) to and from items, including negative days; EDN forms including `dt''`/`DT''`. |
| `manual_decode.rs` | `decode_embedded` (#15): the first item of a byte string's content, with absolute spans that borrow the input; trailing bytes are an `EmbeddedWarning::TrailingBytes` with offset and length; empty, truncated, malformed, or out-of-range content is a `DecodeError` with an absolute offset; printing the view gives absolute CBOR spans and `annotated_hex` on the outer bytes gives aligned rows; a clean view matches the inline view of the same path; indefinite byte strings via their concatenation. |
| `errors.rs` | Malformed EDN: each error kind with its byte offset and 1-based line/column (columns count characters, CRLF is one line break), `Display` text, depth limit (`MAX_DEPTH + 1` nested containers fail cleanly; `MAX_DEPTH` succeeds). |
| `warnings.rs` | The issue #14 warnings and `ParseOptions::strict`: ellipses in `h''` (the tag-888 forms, one warning per literal) and tag 888 in the input; streamstrings; encoding indicators other than `_0`–`_3`, `_i`, `_`; indicators on bignum literals; an end-of-line comment at EOF; non-canonical NaNs (#7: payloads, sign, signaling, `NaN_2`/`NaN_3`, nested and as a key, with bits kept); each with its position, and each an `EdnErrorKind::Strict` error in strict mode. Non-warning cases stay clean in strict mode. The printer's default output (`ilbs`/`ilts`) re-parses in strict mode without warnings; the old streamstring output is still available. Strict mode does not change unknown-extension handling. |
| `nan_vectors.rs` | `testdata/cbor-numbers-nan/nan.tsv`: Table 2 of draft-bormann-cbor-numbers-03 plus derived sign and binary16/32/64 variants. For each NaN: `float'…'` parses to preferred serialization, `float'…'_n` to the input width; input and preferred bytes print as the expected EDN (`NaN`, `NaN_2`, `float'7fff'_3`, …), which re-parses to the exact bytes, with a `NonCanonicalNaN` warning (a strict error) unless the bytes are `f97e00`; every print option round-trips. |
| `properties.rs` | proptest. Random strings (arbitrary Unicode and EDN-like alphabets) never panic `parse`, `parse_seq`, or `parse_with`. Random items built with the tokenator-cbor builders (random widths, indefinite lengths, chunks, floats incl. NaN payloads, tags, simple values) satisfy print → parse → encode(Preserve) == encode(Preserve) for every print option; the default output parses in strict mode without warnings (items without tags 888/999); decoding their bytes and printing gives a valid `SpanMap` and aligned hex rows. Random instants survive RFC 3339 and epoch round trips. |

## Decisions encoded in the tests

Issues #14 (grammar) and #15 (printer, hex, `hash`, date/time) are
answered, and the answers are encoded below. #20 tracks a possible option to
print bignums as plain integers.

- **Strict mode** (`ParseOptions::strict`) turns every warning except
  `UnknownExtension` into `EdnErrorKind::Strict(kind)` at the warning's
  position; unknown extensions keep their own `unknown_extensions` option.
  `parse`/`parse_seq` are lenient and drop warnings.

- **String juxtaposition is gone** (-28 §2.3): `"a" "b"` is two items (inside
  arrays) or trailing input (at top level). Concatenation is `b1<<…>>` /
  `t1<<…>>`. SPEC §8 "concatenated strings" is met by `b1`/`t1`.
- **Unknown app-extensions** become `999([prefix, [args…]])` (the -27 §5.1
  shape; for a string literal the args array holds one text string) plus a
  `WarningKind::UnknownExtension`. The arguments keep their encoding
  indicators. The printer turns such a tag back into `prefix'…'` /
  `prefix<<…>>` when that re-encodes exactly and the prefix is not built in.
  `UnknownExtensions::Error` makes them a parse error instead.
- **Ellipses** (`...` inside `h''`) are accepted with `WarningKind::Ellipsis`
  (#14) and become the -27 §5.2 "CPA888" form: `h'4711...0815'` is
  `888([h'4711', 888(null), h'0815'])`, `h'...'` is `888(null)`, adjacent
  ellipses count as one. A tag 888 written in the input also warns (one
  warning per tag). A bare `...` outside `h''` is still a syntax error (not
  in the -28 grammar). The printer prints these values as plain tags.
- **Streamstrings** `(_ …)` are accepted with `WarningKind::Streamstring`
  (#14). The printer defaults to `ilbs<<…>>`/`ilts<<…>>` so that its own
  output parses without warnings; `IndefiniteStringStyle::Streamstring` keeps
  the old syntax. `''_` and `""_` (the -28 §4.3 empty forms) do not warn.
- **Encoding indicators** other than `_0`–`_3` and `_i` warn
  (`ReservedEncodingIndicator`, #14); `_` for indefinite length is the
  standard indicator and does not warn. An indicator is `_` plus the longest
  run of word characters (`1_i0` is the reserved `i0`). Indicators on
  integer literals that become bignums warn (`IgnoredEncodingIndicator`).
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
- **End-of-line comment at EOF** without a newline is accepted with
  `WarningKind::EolCommentAtEof` (#14). The final comment that the `h''`
  and `b64''` content grammars allow does not warn.
- **Positions**: `offset` is a byte offset; `line` and `column` are 1-based;
  columns count Unicode scalar values. `SpanMap` lines are 0-based row
  indices (`lines` is a half-open range), aligned with `HexRows`.
- **Text ranges** cover an item and its encoding indicator, not annotator
  comments. Items built by an extension share the literal's source range.
- **CBOR spans** in a `SpanMap` are `Some` only for decoded items
  (`span.end > 0`); inside embedded CBOR they are absolute offsets into the
  outer bytes (only for definite-length byte strings).
- **No embedded-CBOR guessing** (#15). The printer and `annotated_hex` take
  `EmbeddedCbor { paths, tagged }`. `paths` lists the byte strings that the
  caller knows hold CBOR (protected header, payload, disclosures, `kcwt`,
  …); their content is shown as `<<…>>` if it is a complete CBOR sequence
  of one or more items (`Embedded(0..n)` children), else `h''`. With
  `tagged`, the content of tag 24 (exactly one item) and tag 63 (a
  sequence) is shown too; these tags are format knowledge, so they need no
  path. The default is `EmbeddedCbor::OFF` (basic output format §1.3.3:
  `h''` only); `EmbeddedCbor::at(paths)` also sets `tagged`. Empty byte
  strings and chunks of indefinite strings are never shown as embedded.
- **Manual decoding** (#15): `decode_embedded(outer, content_range)`
  decodes the first item of a byte string the user picked by hand, with
  spans absolute in `outer`. Trailing bytes give a warning, not an error.
  Without warnings, listing that path shows the same view inline; with
  trailing bytes the view is shown on its own (inline would not re-encode
  exactly).
- **`hash''` is an optional feature** (#15). The `hash` cargo feature (off
  by default) pulls in `sha2`. Without it, `hash` is still a built-in name
  (not opaque, no unknown-extension warning), and evaluating it is an
  `EdnErrorKind::Extension` whose message names the feature.
- **Hex rows**: break bytes get their own row at the container's depth;
  descriptions use the raw argument (`negative(0)` for -1), `(*)` for
  indefinite length, `float16`/`float32`/`float64` for floats.
- **Date/time**: leap second `:60` maps to the next second; offsets are
  normalized to UTC; lowercase `t`/`z` are accepted; a space instead of `T`
  is rejected; years 0000–9999; fractional digits beyond nanoseconds are
  truncated; float epochs round to the nearest nanosecond; `dt''` with a
  fraction yields the correctly rounded binary64 of the decimal epoch.
- **Depth**: `MAX_DEPTH` (512, from tokenator-cbor) nested arrays, maps,
  tags, and embedded sequences; deeper input is `EdnErrorKind::DepthLimit`.
  Deep tests run on an 8 MiB thread.

## Running

`cargo test -p tokenator-edn` (default features) and
`cargo test -p tokenator-edn --all-features` (adds the `hash` tests). CI must
run both: the feature-off tests (`hash_needs_the_hash_feature`) and the hash
tests are `#[cfg]`-gated against each other. Property tests run 2048 cases
on strings and 512 on items.
