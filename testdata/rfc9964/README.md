# RFC 9964 (ML-DSA for JOSE and COSE) examples

Extracted from RFC 9964 Appendix A (A.1 JOSE, A.2 COSE) with
`python3 -I crates/tokenator-crypto/scripts/extract_rfc9964.py rfc9964.txt testdata/rfc9964`
(text from <https://www.rfc-editor.org/rfc/rfc9964.txt>, May 2026).

Each file keeps `priv` (the 32-byte seed, all zero), `raw_public_key`,
`raw_to_be_signed` (JWS signing input or COSE Sig_structure), `raw_signature`,
and the serialized `jws` or `sign1` / `key`. The signatures are deterministic
ML-DSA (`rnd` = 0) with an empty context.
