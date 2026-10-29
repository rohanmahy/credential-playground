# Fuzz targets

cargo-fuzz targets for the parsers and the Engine (SPEC §11: parsers must
never panic). Not a member of the root workspace; needs a nightly toolchain
and `cargo install cargo-fuzz`. CI pins the nightly (`FUZZ_TOOLCHAIN` in
`.github/workflows/ci.yml`) and runs every target for 60 s.

| Target | Input | Checks beyond "no panic" |
|---|---|---|
| `cbor_decode` | CBOR bytes | every decoded item (also of a sequence) re-encodes in Preserve mode to its exact bytes; PreferredPlus/Deterministic output decodes, is a fixed point, and has no findings |
| `edn_parse` | EDN text | single item, sequence, strict; print → parse re-encodes to the same bytes (compact and indented, indicators `NonPreferred`/`Always`); `Never` output parses |
| `edn_print` | flags byte + CBOR | CBOR → EDN (options from the flags) → CBOR gives the input back; annotated hex |
| `json_parse` | JSON text | Original print copies the source exactly; Compact/Pretty reparse to a fixed point |
| `detect` | anything | every candidate's layers unwrap; positional layers point at the payload; unwrap ∘ rewrap is the identity |
| `jose` | JWS/JWT/SD-JWT(+KB), compact or JSON | process, lint facts, verify, KB-JWT check; `to_compact`/`to_json` output parses |
| `cose` | COSE_Sign1/CWT/SD-CWT/SD-KBT | headers, claims, `cnf`, verify, disclosure matching, lint, SD-KBT verify; reassembled parts parse |
| `keys` | hint byte + key | import (JWK, JWK Set, COSE_Key(Set), PEM, X.509 DER); every export re-imports as the same material |
| `engine_open` | anything | Engine detect → open → validate, lint, render |
| `engine_validate` | kind byte + bytes | Engine validate without detection |

```sh
fuzz/seed-corpora.sh                 # seeds fuzz/corpus/<target>/ from testdata/ (gitignored)
cargo +nightly fuzz run cbor_decode fuzz/corpus/cbor_decode
fuzz/smoke.sh 60                     # every target for 60 s, in parallel; logs in fuzz/logs/
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-…   # minimize a crash
```

Minimized crashes live in `testdata/fuzz-regressions/<target>/` and are
replayed by a regression test in the crate that was fixed.
