# tokenator-edn

CBOR Extended Diagnostic Notation (draft-ietf-cbor-edn-literals-28) parser
and printer. See the top-level `ARCHITECTURE.md` for its role; this file
covers the internals. Grammar decisions are listed in `TEST-PLAN.md`
("Decisions encoded in the tests") and tracked in issues #14 and #15.

| Module | Contents |
|---|---|
| `parse.rs` | `parse`, `parse_seq`, `parse_with`; lexer, frame stack, encoding indicators, numbers |
| `print.rs` | `print`, `PrintOptions`; `Node` (borrowed or owned item), embedded-CBOR detection |
| `hex.rs` | `annotated_hex` |
| `ext.rs` | `AppExtension`, `Extensions`, the built-ins |
| `datetime.rs` | `Instant` and the date/time chit's forms |
| `spans.rs`, `path.rs` | `SpanMap`, `Path` |
| `error.rs`, `annotate.rs` | errors, warnings, positions; `Annotator` |

## Design notes

- **No recursion on nesting.** The parser keeps open arrays, maps, tags,
  `<<…>>`, `p<<…>>`, and `(_ …)` on an explicit `Vec<Frame>`; the printer
  keeps open containers on a frame stack; the hex view uses a task stack.
  At `MAX_DEPTH` the whole round trip (parse, encode, decode, print, hex,
  drop) needs about 165 KiB of stack in release builds (`tests/stack.rs`
  runs it on a 1 MiB thread; `EDN_TEST_STACK` overrides the size). What
  remains recursive is tokenator-cbor's `encode` and `Drop`.
- **Depth** counts the same levels as the decoder: arrays, maps, and tags,
  plus `<<…>>` and known `p<<…>>`. An unresolved `p<<…>>` counts three
  (its arguments end up inside a tag and two arrays), and an extension's
  result may not push the tree past `MAX_DEPTH`. Streamstrings count zero:
  their chunks must start like a string, so they only nest through `<<`.
- **Encoding indicators** are applied when an item is complete, by one
  function (`apply_spec`) for every item kind. Float widths are checked by
  encoding at the target width: tokenator-cbor's bit-exact float helpers are
  `pub(crate)`, and its encoder silently widens a value that does not fit.
- **Extensions** receive `&[Item]`; a string literal arrives as one text
  string. Unknown prefixes become `999([prefix, [args]])`.
- **Ellipses** in `h''` are accepted (issue #14) in the -27 "CPA888" form:
  `h'4711...0815'` is `888([h'4711', 888(null), h'0815'])`, `h'...'` is
  `888(null)`, and adjacent ellipses merge. The parser warns when an
  extension returns tag 888 and when the input opens a tag 888. The printer
  shows these values as plain tags. `float''` still rejects ellipses.
- **Warnings** (`WarningKind`): `Ellipsis`, `Streamstring` (`(_ …)`),
  `ReservedEncodingIndicator` (anything except `_0`–`_3`, `_i`, and `_`),
  `IgnoredEncodingIndicator` (on bignum literals), `EolCommentAtEof`, and
  `UnknownExtension`. All go through one `warn()` call. With
  `ParseOptions::strict` it fails at once with `EdnErrorKind::Strict(kind)`,
  except for unknown extensions, which `unknown_extensions` controls. So the
  strict error is the first warning the parser meets. That is source order,
  except inside `p<<…>>`, whose own warning is only known at `>>`.
- **Print defaults** produce text that re-parses in strict mode with no
  warnings: indefinite-length strings print as `ilbs<<…>>`/`ilts<<…>>`
  (`IndefiniteStringStyle::AppExtension`). `Streamstring` keeps the old
  `(_ …)` syntax.
- **Printer `Node`s** are either borrowed from the caller's tree or owned.
  Owned nodes come from decoding an embedded byte string; they are taken
  apart by value as they are printed, so no self-referential storage is
  needed. Embedded items borrow the outer bytes, never copies.
- **Shown as one literal** (`DT'…'`, `IP'…'`, `p'…'`): chosen only if
  re-evaluating the literal re-encodes to the same bytes. All nodes of the
  item get span entries sharing the literal's range, so span maps and hex
  rows still list every node. In `p<<…>>`, the arguments get their own
  ranges.
- **Span maps** are built in pre-order: an entry is pushed when a node
  starts and its end is filled in when it closes. Lines come from a table
  of newline offsets. `SpanMap::get` uses a hash index.
- **Embedded detection** (`print::embedded`) is shared by the printer and
  the hex view so their rows line up. It also requires that the decoded
  item re-encodes to the exact bytes and that the expansion stays within
  `MAX_DEPTH`.
