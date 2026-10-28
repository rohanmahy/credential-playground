# Wycheproof test vectors (curated subset)

Source: <https://github.com/C2SP/wycheproof>, directory `testvectors_v1/`,
commit `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9` (2026-10-23).
License: Apache License 2.0, see [`LICENSE`](LICENSE) (copied from that commit).

Generated with
`python3 -I crates/tokenator-crypto/scripts/curate_wycheproof.py <download-dir> testdata/wycheproof`.
The script:

- drops the DER / PEM / ASN.1 / PKCS#8 key encodings (tokenator-crypto takes
  raw key components; tokenator-keys will bring its own PEM vectors),
- for ML-DSA, keeps only tests usable through JOSE/COSE (absent or empty
  context, a message rather than an external `mu`), at most 4 per
  (flags, result) pair,
- rewrites `numberOfTests` to the number of tests kept.

All other test groups and tests are unmodified.

| File | Used for |
|---|---|
| `ecdsa_secp256r1_sha256_p1363_test.json` | ES256 verify (raw `r‖s`) |
| `ecdsa_secp384r1_sha384_p1363_test.json` | ES384 verify |
| `ecdsa_secp521r1_sha512_p1363_test.json` | ES512 verify |
| `ed25519_test.json` | EdDSA / Ed25519 verify |
| `rsa_signature_2048_sha256_test.json` | RS256 verify |
| `rsa_signature_3072_sha384_test.json` | RS384 verify |
| `rsa_signature_4096_sha512_test.json` | RS512 verify |
| `rsa_pss_2048_sha256_mgf1_32_test.json` | PS256 verify (salt 32) |
| `rsa_pss_2048_sha384_mgf1_48_test.json` | PS384 verify (salt 48) |
| `rsa_pss_4096_sha512_mgf1_64_test.json` | PS512 verify (salt 64) |
| `mldsa_{44,65,87}_verify_test.json` | ML-DSA verify |
| `mldsa_{44,65,87}_sign_seed_test.json` | ML-DSA keygen from seed + deterministic and hedged signing |
