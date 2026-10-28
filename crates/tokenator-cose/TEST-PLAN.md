# tokenator-cose test plan

Integration tests live in `tests/`; shared helpers in `tests/common/mod.rs`.
Fixtures come from `testdata/tokens/` and `testdata/keys/` (see their
READMEs). Inputs are built with `tokenator-cbor` builders or hex (EDN in
comments); `tokenator-edn` is not used.

Sources: RFC 9052 (COSE structures), RFC 8392 (CWT), RFC 8747 (`cnf`),
RFC 9596 (`typ`), RFC 9964 (ML-DSA in COSE), RFC 9679 (COSE Key
Thumbprint), and draft-ietf-spice-sd-cwt-08 ("sd-cwt", text from
datatracker, examples from the draft repository).

## Decisions pinned by the tests

1. **Digest input.** A disclosure digest is `sd_alg` over the disclosure's
   *encoded bstr* (head + contents), exactly as the bstr appears in
   `sd_claims`. This is what every signed example payload carries
   (sd-cwt §3.2 Figure 5, §14.1 Figure 26, §14.2 Figure 28, Appendix G "hash
   of the bstr-encoded-salted data structure", and the draft repository's
   `bare_disclosure_to_hash`, which double-encodes). Figures 8 and 9 show
   `d9df03da…`, the hash of the *contents* only; the tests record that value
   as a known erratum. A received bstr with a non-preferred head is hashed as
   received (original bytes are authoritative) and linted.
2. **Redaction output order** (sd-cwt §4.1, §11; matches the reference
   generator, so the draft examples are reproduced byte for byte):
   unredacted entries keep their order; `simple(59): [digests]` is appended
   as the map's last entry, digests in key order; disclosures are created
   post-order (nested disclosures before the disclosure that contains them)
   and salts are requested in that order. Copied input items are encoded
   with Preserve; new items are preferred.
3. **Reconstruction order.** Disclosed claim keys take the position of the
   `simple(59)` entry, in digest order; disclosed elements replace their
   `60(…)` in place; undisclosed digests and decoys are removed (sd-cwt §9
   step 10). Figure 29 shows sorted keys and `502: 17183928`; the tests use
   the fixture's value `1674004740` and arrival order.
4. **Protected header bytes** are never re-encoded: the `Sig_structure`
   uses the received contents with a preferred bstr head (RFC 9052 §4.4,
   §9), so widening only the *bstr head* keeps a signature valid, while any
   change inside the contents breaks it.
5. **Time checks** (RFC 8392 §2, SPEC §6, default skew 60 s): expired iff
   `now >= exp + skew`; not yet valid iff `now + skew < nbf`; iat in the
   future iff `iat > now + skew`. Floats beyond ±2^53, NaN, ±inf, and tagged
   dates are invalid (sd-cwt §5.2).
6. **Present** embeds the credential as `18([...])` in `kcwt` (tag 61
   removed, 18 added if missing), copying protected, payload, and signature
   bytes; the KBT header order is `alg, kcwt, typ` and the payload order
   `aud, iat, cti, cnonce` (as in Figure 26).
7. **Issue** writes `alg, kid, typ, sd_alg` (as in Figure 5); `typ` is 293
   for an SD-CWT and absent for a plain CWT unless asked; `sd_alg` -16 is
   written by default.
8. **Never-redacted claims** (sd-cwt Table 2) can still be redacted (it's a
   playground): `redact` warns and the report flags the disclosure.

## Files and what they cover

| File | Covers |
|---|---|
| `parse.rs` | RFC 8392 A.3 (tag 18, untagged, tag 61 + 18), A.1 claims, A.4/A.5/A.7 unsupported structures; RFC 9052 C.2.1; RFC 9964 A.2 (all three); every part's span and raw bytes; zero-length protected; detached payload; partial results and each `DiagnosticKind`; header accessors; `TokenKind` |
| `sign_verify.rs` | `Sig_structure` bytes (RFC 9964 `raw_to_be_signed`, RFC 8392 A.3 hand-built); verification of RFC 8392 A.3, RFC 9052 C.2.1, RFC 9964 ×3; deterministic ML-DSA re-signing reproduces RFC 9964 signatures; external AAD; detached payloads; `alg` override; sign/verify for all 14 algs; key unsuitable; no private key; PSS needs randomness; tags preserved |
| `backend.rs` | `Sign1Backend` as a trait object: a spy double that delegates and counts calls proves `issue`, `present`, `verify_kbt`, `resign`, `tamper`, `lint` go through it; a double with a different `Sig_structure` context cannot verify `CborBackend` output and vice versa |
| `claims.rs` | claim lookup (incl. non-preferred keys), NumericDate (int, float, RFC 8392 A.7 float `iat`, NaN, inf, ±2^53, tagged, text), `check_times` boundaries with skew; `cnf` COSE_Key / kid / ckt / encrypted / unknown / malformed; `resolve_cnf` |
| `sd_vectors.rs` | All sd-cwt-08 examples: issuer SD-CWT (Fig 5), SD-KBT (Fig 26), nested issuer SD-CWT and nested SD-KBT (Fig 28, Appendix D), decoys (Fig 20): signatures with the C.2 issuer key and C.1 holder key, each disclosure's content and digest, Figure 7 bytes, Figure 8 erratum, every slot location, processed claims (Fig 4/29 per decision 3), holder vs verifier validity |
| `redact.rs` | `redact` reproduces the payload and disclosures of the issuer, nested, and decoy examples from pre-issuance claims (Fig 21/22 style) with the fixture salts; `issue` reproduces the protected and unprotected bytes; ordering, Preserve, post-order salts, `RngSalts`/`FixedSalts`, SHA-384/512, every `RedactionError`, warnings, plain CWT issue, `force_sd`, `typ`/`sd_alg` options |
| `present.rs` | `disclose` keeps exact bytes; `present` reproduces Figure 26's KBT protected header and payload; `verify_kbt` on every fixture and every `KbtFinding`, each `TimeRule`, aud/cnonce/max_age, cnf kid/ckt resolution; plain CWT (and tag-61 CWT) in an SD-KBT |
| `roundtrip.rs` | issue → redact → present → verify for every `Alg` with seeded keys (issuer and holder), nested redaction and decoys, SHA-384/512 |
| `report.rs` | Every `SdReport` category: matched, unmatched, duplicate disclosures, duplicate digests, undisclosed (decoys and withheld), forbidden (never-redacted, pre-issuance tag, kind mismatch), malformed (each `MalformedDisclosure`), key collisions, sd_alg default/known/unsupported/invalid, empty and misplaced `sd_claims` |
| `tamper.rs` | Each `TamperOp` makes verification fail as expected (and `WideBstrHead` does not); `assemble` from raw parts; `resign` keeps unedited bytes (non-preferred heads, unprotected, tags) and verifies; `edit_disclosures` (select, remove, duplicate, move, append, replace, forge, decoy) with the expected report change and issuer signature still valid; editing an SD-KBT breaks only the KBT signature |
| `lint.rs` | non-preferred encodings (Info vs Warn by part, absolute spans incl. inside `kcwt`), indefinite lengths, map key order, duplicate keys, label in both buckets, alg missing/unsupported/unprotected, alg/key mismatch for signer and `cnf` (incl. the draft's ESP384-declared issuer key used with ES384), crit cases, typ cases, `h'a0'` protected, salt length; clean fixtures |
| `codepoints.rs` | constants agree with the `tokenator-registry` snapshot and its SD-CWT revision |
| `proptest.rs` | never panics: `parse`, `parse_sd_cwt`, `match_disclosures`, `verify_kbt`, `lint`, `tamper`, `edit_disclosures`, `disclose` on random bytes and on single-byte mutations / truncations of every fixture |

## Keys

- RFC 8392 A.2.3 (P-256, `testdata/keys/rfc8392-a2.3-ec-p256.cosekey.cbor`).
- RFC 9052 C.7.1 kid `11` (P-256, `testdata/keys/rfc8152/c7-1-public-keyset.cbor`).
- RFC 9964 A.2 ML-DSA (`testdata/keys/rfc9964/`, all-zero seed).
- sd-cwt C.1 holder (P-256) and C.2 issuer (P-384, declares `alg` -51).
- Generated: `tokenator_keys::generate(KeySpec::for_alg(alg), …, Some(seed))`;
  one RSA-2048 key is generated once per test binary (slow in debug).

## Open questions

Defaults above are pinned by tests and listed for confirmation in #23
(digest input, reconstruction and redaction order) and #24 (leniency
defaults, lint severities, `crit`, the C.2 key's declared alg).
