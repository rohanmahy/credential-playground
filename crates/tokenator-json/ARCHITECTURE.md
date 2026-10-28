# tokenator-json

Span-preserving, order-preserving JSON parser. See the top-level `ARCHITECTURE.md`
and `TEST-PLAN.md` for the decisions (resolved in issues #3 and #4). No
dependencies.

## Modules

- `lib.rs`: public types (`Node`, `Member`, `Value`, `Span`, errors, warnings,
  print options), accessors, RFC 6901 pointers.
- `parse.rs`: checks the BOM, then runs a recursive-descent parser over the
  bytes. There is no up-front UTF-8 pass. Outside strings, any non-ASCII byte
  is simply a grammar error. Inside strings, non-ASCII bytes are validated one
  sequence at a time. Invalid sequences decode to U+FFFD (the same policy as
  `String::from_utf8_lossy`) and each one adds a warning. The depth limit is
  checked before each descent, so recursion is bounded by `max_depth`. Strings
  borrow from the input until their first escape or invalid sequence. Number
  lexemes always borrow. A lexeme only goes through `f64` parsing for the range
  warnings when it has an exponent or is longer than 15 bytes. Warnings are
  produced left to right, so they come out sorted.
- `print.rs`: `Compact`, `Pretty`, and `Original`, all written into a
  `Vec<u8>`. `print_bytes` returns that buffer. `print`/`print_with` turn it
  into a `String`, replacing invalid bytes with U+FFFD only if there are any.

## Edit model

Each `Node` keeps its `span`, its `raw` source bytes, and an `edited` flag.
`Member` has the same for its key. `raw()`/`key_raw()` validate those bytes as
UTF-8 on each call. `set_value`, `value_mut` and `set_key` set the flag;
`*_mut` lookups don't. Edited nodes keep their span and raw bytes.
`is_original()` is computed by walking the subtree, so ancestors don't need to
be marked.

## Original printing

Scalars print `raw` if unedited, otherwise a fresh token. A container whose `raw`
is the same kind of container is printed child by child. The "gaps" (the open
bracket, `,`, `:`, the close bracket, plus surrounding whitespace) are copied
from `raw` wherever the source text between two neighbours is exactly whitespace
around the expected punctuation. Neighbours are located by checking where each
child's `raw` pointer falls inside the parent's `raw`. Since only gaps that check
out are copied, the output is valid however nodes were moved, removed, or
replaced. A fully unedited container comes out byte-identical. An original child
whose new neighbour was inserted keeps its own `,` gap from the source.
Everything else follows `InsertedLayout`:

- `Compact` (default): reuse this container's first copyable `,`/`:` gap, or
  fall back to `,` plus the whitespace just inside the open bracket.
  Synthesized containers get compact punctuation.
- `Canonical`: `,\n<child indent>` if the source container is multi-line,
  otherwise `, `. Members get `": "`. Synthesized containers go through the same
  layout routine as Pretty. Each line starts with the indent of the output line
  the container is placed on, plus the indent unit. The unit is the nearest
  multi-line source ancestor's child indent minus its own line indent, falling
  back to two spaces. Line indents are read back from the output buffer, since
  unedited lines are copied verbatim.

Pretty uses the same layout routine with normalized tokens. Unedited strings
and keys are re-escaped from their raw text: U+0020..=U+007E become literal
(except `\"` and `\\`), and anything above U+007E keeps its source form.
