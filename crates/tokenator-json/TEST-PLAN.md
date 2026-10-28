# tokenator-json test plan

Tests live in `tests/`. Run with `cargo test -p tokenator-json`.

## API under test

- `parse(&[u8]) -> Result<Node, JsonError>` (warnings dropped) and
  `parse_with_options(&[u8], &ParseOptions) -> Result<Parsed { node, warnings }, JsonError>`,
  with `Warning { offset, kind: WarningKind }`.
- `Node`: `span()`, `raw()`, `raw_bytes()`, `value()`, `is_original()`, `set_value()`,
  `value_mut()`, `get`/`get_all`/`get_mut`, `index`/`index_mut`, `members_mut`/`elements_mut`,
  `pointer`/`pointer_mut` (RFC 6901), `members()`, `elements()`.
- `Member`: `key()`, `key_span()`, `key_raw()`, `key_raw_bytes()`, `value()`, `value_mut()`, `set_key()`.
- `print(&Node, PrintStyle::{Original, Compact, Pretty}) -> String`,
  `print_with(&Node, &PrintOptions) -> String` (lossy for non-UTF-8 sources), and
  `print_bytes(&Node, &PrintOptions) -> Vec<u8>` (exact). `PrintOptions { style, inserted:
  InsertedLayout::{Compact (default), Canonical} }`.

## Decisions (resolved in #3 and #4)

| Topic | Decision |
|---|---|
| Top-level scalars | Accepted (RFC 8259). |
| Surrounding whitespace | Outside the root span. `print(Original)` returns the root span's bytes; inner whitespace is kept exactly. |
| String / key span | Includes the quotes. |
| Number | `Value::Number(Cow<str>)`, lexeme verbatim, never rejected for range. Warnings (offset = number start, at most one per number): `NumberOverflow` if it rounds to ±infinity as f64; else `UnsafeInteger` for an integer lexeme (no `.`/`e`) with abs value > 2^53 − 1; `NumberUnderflow` if a lexeme with a non-zero digit rounds to 0. |
| Escape-free strings | `Cow::Borrowed`; strings with escapes are `Cow::Owned`. |
| Duplicate keys | Kept in arrival order. `get` returns the first match, `get_all` returns all of them. |
| Lone / inverted surrogate escapes | Rejected: `ErrorKind::LoneSurrogate`, offset of the `\` of the offending escape. |
| Invalid UTF-8 in strings/keys | Accepted with one `WarningKind::InvalidUtf8` per U+FFFD (offset = first byte of the bad sequence). The decoded value equals `String::from_utf8_lossy` of the content (`Cow::Owned`). Spans are exact. `raw()`/`key_raw()` return `None` when the bytes are not UTF-8; `raw_bytes()`/`key_raw_bytes()` are always exact. Errors still win (e.g. truncation). |
| Invalid UTF-8 elsewhere / UTF-16 | `UnexpectedCharacter` (or `TrailingCharacters`) at the byte, by the normal grammar. UTF-16 input fails at its first NUL or 0xFF/0xFE byte. |
| Warnings | Sorted by offset. `y_` files produce none. |
| Check order | BOM, then the grammar. |
| UTF-8 BOM | Rejected: `ErrorKind::ByteOrderMark` at offset 0. Callers may strip it and lint. |
| Depth | `DEFAULT_MAX_DEPTH = 128` containers. Exceeding it gives `DepthLimitExceeded` at the offending `[`/`{`. It must never overflow the stack (100 000 levels tested). `i_structure_500_nested_arrays` is rejected. |
| Error offset | Byte offset of the first offending byte. If the input ends mid-construct (even mid-escape or mid-surrogate pair), the error is `UnexpectedEnd` at `input.len()`. Trailing data gives `TrailingCharacters` at the first non-whitespace byte after the value. A bad literal (`nulL`) points at the first wrong byte. A digit after a leading zero, or a missing fraction/exponent digit, gives `InvalidNumber` at that byte. `.5` and `+1` give `UnexpectedCharacter`. A BOM that is not at offset 0 is an `UnexpectedCharacter`. |
| Edited node span | The original span is kept, and `is_original()` becomes false. Synthesized nodes have `span() == None`. |
| `is_original()` | True only if the node was parsed, was never edited, and every descendant is original. |
| Original + edits | Gaps (whitespace, `:`, `,`) between unedited neighbours are copied from the source, including when the container is only touched via `*_mut` accessors. `print_bytes` copies non-UTF-8 source bytes exactly; `print`/`print_with` replace them with U+FFFD. |
| `InsertedLayout::Compact` (default) | Synthesized subtrees have no whitespace. Separators around inserted children are borrowed from neighbours (layout otherwise unspecified; must reparse and keep untouched bytes). |
| `InsertedLayout::Canonical` | A container is multi-line if the gap between its open bracket and first child has a newline; its child indent is the whitespace after the last newline there. A non-first inserted child is preceded by `,\n<child indent>` (multi-line) or `, `; the original gap before the next original sibling stays. A first child in an empty container gets no separator. Members use `": "`. Synthesized containers are Pretty-style from the indent of the source line they sit on, with unit = nearest multi-line original ancestor's child indent minus its line indent, else 2 spaces. A synthesized root equals Pretty. Ignored for Compact/Pretty styles. |
| Pretty escapes | Strings and keys normalized: U+0020..U+007E literal except `\"` and `\\`; controls as `\b\f\n\r\t` or lowercase `\u00xx`; above U+007E the original form is kept (escape text verbatim, or literal); invalid bytes print as U+FFFD. |
| Compact / Pretty | These re-emit only structural whitespace. In Compact, unedited scalars and keys keep their original token text (Pretty: see above). New or edited strings use minimal escaping (`\"`, `\\`, `\b\f\n\r\t`, other controls as `\u00xx` lowercase; non-ASCII raw; `/` unescaped). Pretty uses a 2-space indent, `": "`, `{}`/`[]` when empty, and no trailing newline. |

## Test files

- `json_test_suite.rs`: runs every file in `testdata/JSONTestSuite/test_parsing`.
  `y_` must parse, and print(Original) must equal the trimmed input. `n_` must
  fail. `i_` must match the table in the test (accept with exact warnings, or reject with a kind). Each panic is caught, and all failures
  are reported together.
- `spans.rs`: exact spans and `raw()` for scalars, nested containers, keys,
  escaped strings, multi-byte UTF-8, surrogate pairs, and whitespace.
- `structure.rs`: arrival order, duplicates, `get`/`get_all`, pointers (`~0`, `~1`,
  array indexes, misses), number lexemes, Cow borrowing, and decoded escapes.
- `printing.rs`: Original is byte-identical, plus exact Compact and Pretty outputs.
  Edits: change one value or key, edit nested values, insert or remove
  members/elements, replace a container, and add synthesized trees. Unedited
  bytes are preserved and the output reparses to the expected structure.
- `errors.rs`: error kinds and offsets for truncation, trailing garbage, BOM,
  surrogates, invalid UTF-8 outside strings and UTF-16, control characters, bad
  escapes and numbers, and depth (boundary and bomb).
- `warnings.rs`: invalid UTF-8 in strings/keys (lossy value, exact spans and
  bytes, printing, edits nearby), number range warnings and offsets, ordering.
- `pretty_escapes.rs`: Pretty escape normalization; Original/Compact unchanged.
- `inserted_layout.rs`: Compact vs Canonical layout for inserted members,
  inserted elements and synthesized subtrees (2-space, 4-space, tab, fallback).
- `proptest.rs`: random bytes never panic. Random JSON-ish mutations never
  panic. Arbitrary bytes inside a string decode lossily with exact `print_bytes`. For generated trees, Compact/Pretty output reparses to an equal
  structure and Original output is byte-identical.
