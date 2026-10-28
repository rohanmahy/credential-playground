# tokenator-jose test plan

Integration tests live in `tests/`; helpers (independent oracles for
base64url, hashing, ordered JSON comparison, keys) in `tests/common/`.
`tests/fixtures.rs` checks the fixtures and helpers without calling this
crate, so it passes before the implementation exists.

Fixtures are in `testdata/tokens/` (see its README). The RFC 9901 ones were
extracted by `scripts/extract_rfc9901.py` and cross-checked with OpenSSL and
an independent Python model before the tests were written.

## Sources

| Spec | Used for |
|---|---|
| RFC 7515 App. A | A.1 (HS256: unsupported), A.2 (RS256: verify, reproduce byte for byte via re-signing), A.3/A.4 (verify; ECDSA k was random), A.5 (`alg: none`), A.6 general, A.7 flattened |
| RFC 7519 | §3.1 claims and `exp`, §6.1 unsecured JWT |
| RFC 9901 | §4.2 disclosure examples, every listed digest/disclosure pair (87), §5, §6.1–6.3, A.1–A.4 (parse, verify, match, processed payload, issuance reproduction), §8.2/8.3 JSON serialization, all KB-JWTs |
| RFC 7800 | `cnf` with `jwk` and `kid` |

## Decisions encoded by the tests

Defaults chosen for the questions in issues #21 and #22 (`ai-needs-clarification`).

1. **Parsing.** Input is `&str`; surrounding ASCII whitespace is ignored and
   spans stay relative to the full input. `{` ⇒ JSON serialization, else
   compact; `~` ⇒ SD-JWT; JSON is SD-JWT iff the *first* unprotected header
   has `disclosures` or `kb_jwt`. Only unrecognizable input is a
   `ParseError`; every per-part problem is a `Diagnostic` and the part is
   kept. A non-JSON payload of a plain JWS is still reported (RFC 7515 A.4).
   Compact with ≠3 segments: missing parts empty, extras in the third.
2. **Base64url** is strict: no padding/whitespace/`+`/`/`, canonical
   trailing bits; invalid bytes are reported before length errors.
3. **Processing order** (verified against every RFC processed payload):
   disclosed properties are appended to the end of their object in the
   order of their digests in `_sd`; array slots are replaced in place;
   unfilled slots removed; top-level `_sd_alg` removed.
4. **Problems never abort processing.** The offending disclosure is not
   inserted (forbidden name, kind mismatch, collision, malformed), a
   duplicated digest fills only its first slot, a repeated disclosure is
   used once; nested `_sd_alg` is reported and kept; an unsupported
   `_sd_alg` lists slots but matches nothing. Finding order is pinned in
   `SdReport::findings`. Slot walk order: depth-first, entering a matched
   disclosure right after its slot.
5. **Issuance layout** (reproduces RFC 9901 §5.1 and A.1–A.4 byte for
   byte with fixed salts and decoys and `JsonStyle::Spaced { ascii_only:
   true }`): header `alg, typ, kid, x5c, extra`; each object's `_sd` first,
   then its other members in input order; top-level `_sd_alg`, then `cnf`.
   Claims walked in document order, inner disclosures created first (this
   fixes salt order). Digests sorted by default (`DigestOrder::Creation`
   for experiments). Random salts are 16 bytes; random decoys hash the
   base64url of 16 random bytes; array decoys are appended. An SD-JWT is
   produced iff any claim is marked or any decoy requested.
6. **Presentation** sends exactly the requested disclosures in the
   requested order; missing parents (immediate only), unreachable
   disclosures and duplicates are reported, never fixed. KB-JWT header
   `alg, typ`; payload `nonce, aud, iat, sd_hash` (the RFC order, so §5.2's
   KB-JWT header and payload are reproduced). The input's serialization is
   kept; an old KB-JWT is dropped.
7. **Time checks**: expired iff `now >= exp + skew`; not yet valid iff
   `now + skew < nbf`; future iff `iat > now + skew`; KB too old iff
   `now > iat + max_age + skew`. Fractional dates allowed.
8. **KB holder key**: `cnf.jwk` (candidates ignored), else a candidate whose
   kid equals `cnf.kid`; anything else gives `VerifyError::NoKey` while the
   other checks still run.
9. **Manipulation**: `resign` keeps unedited part text exactly and prints
   edited trees with `Original` style; disclosures, KB-JWTs, and other
   signatures are copied (and may go stale). `tamper` is compact-only;
   `FlipBit` flips `0x80 >> (bit % 8)` of byte `bit / 8` of the decoded
   part. `edit_disclosures` never re-signs. Conversions carry disclosures
   and KB-JWT; compact reports dropped unprotected members.
10. **Crit**: this crate understands no extensions; `registered` lists RFC
    7515/7518 names that must not appear in `crit`.

## Coverage map

| File | Area |
|---|---|
| `b64.rs` | RFC 4648 vectors, strictness, agreement with base64ct |
| `parse_compact.rs` | RFC 7515/7519 compact, spans, CRLF headers, partial decoding, segment counts, fatal errors |
| `parse_json.rs` | A.6, A.7, RFC 9901 §8.2/8.3, `sd_hash_input`, envelope diagnostics, escaped strings |
| `rfc7515.rs` | Verify every App. A example, reproduce A.2, unsupported/none/wrong key/unprotected `alg` |
| `time.rs` | `exp`/`nbf`/`iat` boundaries with skew, fractions, non-numbers, extremes |
| `rfc9901_digests.rs` | §4.2 examples, encoding variants, all 87 digests, malformed disclosures |
| `rfc9901_process.rs` | Every RFC SD-JWT: structure, issuer signature, slot counts, processed payload (ordered), slot locations and walk order, §6, spans of processed nodes |
| `rfc9901_kb.rs` | Every RFC KB-JWT, wrong aud/nonce, unchecked values, iat freshness, sd_hash |
| `rfc9901_issue.rs` | Byte-for-byte issuance of §5.1, A.1 (decoys), A.2, A.3, A.4 |
| `sd_report.rs` | Every `SdFinding`, hash variants, recursion, ordering |
| `present.rs` | RFC presentations reproduced, KB layout, selection findings, JSON serialization, errors |
| `roundtrip.rs` | issue → present → verify for all 14 algorithms; plain JWTs; determinism; `cnf.kid`, missing/invalid `cnf`, wrong holder, bad KB payloads |
| `issue.rs` | Header/payload layout, styles, lexemes, salts, digest order, decoys, `_sd_alg`, errors |
| `tamper.rs` | Every tamper op and its verification failure; untouched bytes; assembly forgeries |
| `resign.rs` | Unedited bytes identical, edited payload/header, JSON layout kept, errors |
| `edit_disclosures.rs` | Every `DisclosureOp`, payload edits minimal, KB staleness, JSON |
| `convert.rs` | Compact ↔ flattened/general, dropped members, SD-JWT carry-over |
| `lint.rs` | `alg`/`typ`/`crit` facts, duplicate members, `cnf`, key/JWK findings |
| `proptest_parse.rs` | Never panic: random text, token alphabet, mutated/truncated fixtures, deep nesting |

## Not covered

- RFC 7797 unencoded payloads (`b64: false`) and JWE (out of scope).
- RFC 9901 §4.2.6's `5G1srw3…` disclosure: its exact encoding is not given.
- Signatures of RFC ECDSA examples are not reproducible (random k).
