# IANA registry fixtures

Verbatim copies of the IANA registry XML, fetched once on **2026-10-28**. They
are the input to `tools/registry-gen` (the bundled snapshot in
`crates/tokenator-registry/data/` is generated from them) and the fixtures for
the `tokenator-registry` and `registry-gen` tests. Tests never hit the network.

| File | Source | IANA `<updated>` | SHA-256 |
|---|---|---|---|
| `cwt.xml` | https://www.iana.org/assignments/cwt/cwt.xml | 2026-07-20 | `ebced7e70f1db2641f2a0a5415e17780b6799553455a05651210b87799511fec` |
| `cose.xml` | https://www.iana.org/assignments/cose/cose.xml | 2026-08-25 | `765e0cbff5385b3bf3477689af3e82ee870910abbd74ea002513f0f5941cfdb6` |
| `jwt.xml` | https://www.iana.org/assignments/jwt/jwt.xml | 2026-07-20 | `66703b9d715809fa02b321b33d85ad2874b5dd3b6977b361285dfba05b8c4540` |
| `jose.xml` | https://www.iana.org/assignments/jose/jose.xml | 2026-09-29 | `647c61a6279d8d8a8f8a2ad1edbed4f83b5296eddbdafe1119fa48ed4608d75d` |

Notes on content as of this fetch (tests rely on them):

- ML-DSA (`ML-DSA-44/65/87`, COSE -48/-49/-50) and the `AKP` key type are
  registered (RFC 9964), so no local additions are needed for
  draft-ietf-cose-dilithium.
- SD-CWT header parameters `sd_claims` (17), `sd_alg` (170),
  `sd_aead_encrypted_claims` (171), `sd_aead` (172) and the CWT claim `vct`
  (11) are TEMPORARY registrations. The name element carries a
  `(TEMPORARY - registered …, expires …)` suffix.
- `kcwt` (COSE header 13) is permanently registered.
- SD-JWT's `_sd`, `...`, `_sd_alg`, `sd_hash` are registered JWT claims
  (RFC 9901). `vct` is *not* in the JWT claims registry; it appears only as the
  JWT name of CWT claim 11.

To refresh: re-download the four files, update this table, and re-run
`cargo run -p registry-gen` (the snapshot-in-sync test will fail until you do).
