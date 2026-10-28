# tokenator-cose

COSE_Sign1, CWT, SD-CWT (draft-ietf-spice-sd-cwt-08), and SD-KBT. See the
top-level `ARCHITECTURE.md` for its role and `TEST-PLAN.md` for the
decisions the tests pin (#23, #24).

| file | contents |
|---|---|
| `model.rs` | `Sign1` (parts with spans, original bytes), `Bstr`, `Payload`, `Diagnostic`, header accessors, `TokenKind` |
| `backend.rs` | `Sign1Backend` (required: `parse`, `sig_structure`, `assemble`; provided: `sign`, `verify`), `CborBackend`, `Sign1Parts` |
| `claims.rs` | claim lookup, NumericDate, `check_times`, `cnf` parsing and resolution |
| `sd.rs` | `redact`, `issue`, disclosure encoding and digests, `SdCwt`, `match_disclosures` |
| `kbt.rs` | `disclose`, `present`, `verify_kbt` |
| `edit.rs` | `resign`, `tamper`, `edit_disclosures`; the shared `sd_claims` rewriter |
| `lint.rs` | conformance findings |
| `util.rs` | labels, map lookup, iterative tree walk, heads, byte splicing |

## Design

- **Parsing** decodes once with `tokenator-cbor`. Byte string contents
  that hold CBOR (protected header, payload, disclosures) are decoded
  eagerly into `Bstr::decoded`, with spans relative to the contents;
  `content_offset()` maps them back. Malformed parts give a partial
  `Sign1` with diagnostics; only non-CBOR, non-array, or other COSE
  structures are errors.
- **Original bytes.** The `Sig_structure` always uses the received
  protected and payload contents. `resign`, `tamper`, `disclose`, and
  `edit_disclosures` *splice* new encodings into the input at the spans
  of the parts they change. Everything else, including byte string heads,
  tags, and map arrival order, is copied. Edited byte strings keep their
  head width when it still fits.
- **Embedded SD-CWT.** An SD-KBT's `kcwt` is parsed from its own byte
  slice, so its spans are relative to the SD-CWT. `Sign1::base` records
  where it sits in the input. Editing it rewrites the slice and then the
  KBT protected bstr around it, and the KBT is not re-signed.
- **Digests** hash the disclosure bstr as received, head included
  (Appendix G and the signed examples; #23 for the Figure 8 discrepancy).
- **Redaction** is one recursive pass that follows the reference
  generator: nested disclosures are created before their parent, salts
  are requested in that order, and `simple(59)` is appended last. Copied
  items keep their encoding (new containers keep the old width when it
  fits), and new items are preferred.
- **Matching** walks the payload once. Each slot is recorded, and a
  matched disclosure's value is walked in turn. The same walk builds the
  processed claims: disclosed keys replace the `simple(59)` entry in
  digest order, elements are replaced in place, and everything else is
  cloned (so it still borrows the input). Each digest fills at most one
  slot, so the recursion ends.
- **Lint** runs `deterministic_findings` and a duplicate-key scan on the
  outer item (heads, unprotected header) and on each decoded content.
  Spans are made absolute with the content offset and `base`. Inside a
  KBT, findings that fall within the kcwt range are left to the
  recursive pass over the embedded SD-CWT, which reports them as
  `Part::Kcwt(..)`.
- Scans (indefinite lengths, SD markers, duplicate keys) use an explicit
  stack. The rebuilding walks (redaction, matching, widening integers)
  recurse, and 1000-deep payloads are tested.

## Deviations from the skeleton / top-level docs

- `SdReport` has a `diagnostics` field (the SD structural diagnostics of
  the `SdCwt`) so an empty `sd_claims` makes the report invalid (§9 step 2).
- The top-level doc names the third backend method `build`; it is
  `assemble`. `resign` signs through `Sign1Backend::sign`, then splices the
  returned signature into the input.

## Gaps

- An SD-KBT whose protected header is an indefinite-length bstr cannot be
  edited (its kcwt has no contiguous bytes); `verify_kbt` reports
  `KcwtNotSign1` for it.
- A `coset` backend is a follow-up (#26).
