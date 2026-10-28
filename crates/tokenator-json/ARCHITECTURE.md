# tokenator-json

Span-preserving, order-preserving JSON parser. See the top-level `ARCHITECTURE.md`
and `TEST-PLAN.md` for the decisions (defaults from issues #3 and #4). No
dependencies.

## Modules

- `lib.rs`: public types (`Node`, `Member`, `Value`, `Span`, errors), accessors,
  RFC 6901 pointers.
- `parse.rs`: checks the BOM, then UTF-8 for the whole input
  (`str::from_utf8`), then runs a recursive-descent parser over the bytes.
  The depth limit is checked before each descent, so recursion is bounded by
  `max_depth`. Strings are scanned once: they borrow from the input until the
  first escape, then switch to an owned buffer. Number lexemes always borrow.
- `print.rs`: `Compact`, `Pretty`, and `Original`.

## Edit model

Each `Node` keeps its `span`, its `raw` source slice, and an `edited` flag.
`Member` has the same for its key. `set_value`, `value_mut` and `set_key` set the
flag; `*_mut` lookups don't. Edited nodes keep their span and raw text.
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
replaced. A fully unedited container comes out byte-identical. Gaps that can't
be copied reuse this container's first copyable `,` or `:` gap, or fall back to
`,` plus the whitespace just inside the open bracket. Containers without source
text use compact punctuation, but their children are still printed in
`Original` style.
