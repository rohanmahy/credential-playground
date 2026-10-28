# tokenator-json test plan

Tests live in `tests/`. Run with `cargo test -p tokenator-json`.

## API under test

- `parse(&[u8]) -> Result<Node, JsonError>` and `parse_with_options` (`max_depth`).
- `Node`: `span()`, `raw()`, `value()`, `is_original()`, `set_value()`,
  `value_mut()`, `get`/`get_all`/`get_mut`, `index`/`index_mut`, `members_mut`/`elements_mut`,
  `pointer`/`pointer_mut` (RFC 6901), `members()`, `elements()`.
- `Member`: `key()`, `key_span()`, `key_raw()`, `value()`, `value_mut()`, `set_key()`.
- `print(&Node, PrintStyle::{Original, Compact, Pretty}) -> String`.

## Decisions (defaults; open questions in #3 and #4)

| Topic | Decision |
|---|---|
| Top-level scalars | Accepted (RFC 8259). |
| Surrounding whitespace | Outside the root span. `print(Original)` returns the root span's bytes; inner whitespace is kept exactly. |
| String / key span | Includes the quotes. |
| Number | `Value::Number(Cow<str>)`, lexeme verbatim, never range-checked. All `i_number_*` accepted. |
| Escape-free strings | `Cow::Borrowed`; strings with escapes are `Cow::Owned`. |
| Duplicate keys | Kept in arrival order. `get` returns the first match, `get_all` returns all of them. |
| Lone / inverted surrogate escapes | Rejected: `ErrorKind::LoneSurrogate`, offset of the `\` of the offending escape. |
| Invalid UTF-8 (anywhere) | Rejected: `ErrorKind::InvalidUtf8`, offset of the first bad byte. The whole input is validated before the grammar, so UTF-16 input reports `InvalidUtf8` and not a NUL `UnexpectedCharacter`. |
| Check order | BOM, then UTF-8 validity of the whole input, then the grammar. |
| UTF-8 BOM | Rejected: `ErrorKind::ByteOrderMark` at offset 0. Callers may strip it and lint. |
| Depth | `DEFAULT_MAX_DEPTH = 128` containers. Exceeding it gives `DepthLimitExceeded` at the offending `[`/`{`. It must never overflow the stack (100 000 levels tested). `i_structure_500_nested_arrays` is rejected. |
| Error offset | Byte offset of the first offending byte. If the input ends mid-construct (even mid-escape or mid-surrogate pair), the error is `UnexpectedEnd` at `input.len()`. Trailing data gives `TrailingCharacters` at the first non-whitespace byte after the value. A bad literal (`nulL`) points at the first wrong byte. A digit after a leading zero, or a missing fraction/exponent digit, gives `InvalidNumber` at that byte. `.5` and `+1` give `UnexpectedCharacter`. A BOM that is not at offset 0 is an `UnexpectedCharacter`. |
| Edited node span | The original span is kept, and `is_original()` becomes false. Synthesized nodes have `span() == None`. |
| `is_original()` | True only if the node was parsed, was never edited, and every descendant is original. |
| Original + edits | Gaps (whitespace, `:`, `,`) between unedited neighbours are copied from the source, including when the container is only touched via `*_mut` accessors. Synthesized subtrees are printed Compact. The separator layout for inserted members is not specified; the output must reparse and keep the untouched bytes. |
| Compact / Pretty | These re-emit only structural whitespace. Unedited scalars and keys keep their original token text. New or edited strings use minimal escaping (`\"`, `\\`, `\b\f\n\r\t`, other controls as `\u00xx` lowercase; non-ASCII raw; `/` unescaped). Pretty uses a 2-space indent, `": "`, `{}`/`[]` when empty, and no trailing newline. |

## Test files

- `json_test_suite.rs`: runs every file in `testdata/JSONTestSuite/test_parsing`.
  `y_` must parse, and print(Original) must equal the trimmed input. `n_` must
  fail. `i_` must match the table above. Each panic is caught, and all failures
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
  surrogates, invalid UTF-8, control characters, bad escapes and numbers, and
  depth (boundary and bomb).
- `proptest.rs`: random bytes never panic. Random JSON-ish mutations never
  panic. For generated trees, Compact/Pretty output reparses to an equal
  structure and Original output is byte-identical.
