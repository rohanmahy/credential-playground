# Key fixtures for `tokenator-keys`

Used by `crates/tokenator-keys/tests/`. The crate never runs OpenSSL; these
files were generated once and committed. All keys are test keys.

## `openssl/`

Generated with OpenSSL 4.1.0 by
`sh crates/tokenator-keys/scripts/make_openssl_fixtures.sh` (run from the
repository root). EC and RSA keys are random, so rerunning replaces them; the
ML-DSA seeds are SHA-256(`"tokenator ml-dsa-NN"`) and stay the same.

| Files | Contents |
|---|---|
| `pNNN-pkcs8.pem` | EC P-256/384/521 PKCS#8 `PRIVATE KEY` |
| `pNNN-sec1.pem` | the same key as SEC1 `EC PRIVATE KEY` (named curve, public key) |
| `pNNN-sec1-nopub.pem` | SEC1 without the optional public key |
| `pNNN-spki.pem` | SPKI `PUBLIC KEY` |
| `p256-ecparam-genkey.pem` | `EC PARAMETERS` block followed by an `EC PRIVATE KEY` |
| `ed25519-pkcs8.pem`, `ed25519-spki.pem` | Ed25519 |
| `rsaNNNN-pkcs8.pem`, `-pkcs1.pem`, `-pkcs1-pub.pem`, `-spki.pem` | RSA 2048/3072/4096: PKCS#8, PKCS#1 `RSA PRIVATE KEY`, PKCS#1 `RSA PUBLIC KEY`, SPKI |
| `rsapss2048-pkcs8.pem`, `-spki.pem` | RSA key with the `id-RSASSA-PSS` OID |
| `mldsaNN-seed.pem`, `-expanded.pem`, `-both.pem` | ML-DSA-44/65/87 PKCS#8 in the three RFC 9881 private key forms |
| `mldsaNN-spki.pem` | ML-DSA SPKI |
| `<name>.json` | the raw components (lowercase hex) from `openssl pkey -text`: EC `d`/`x`/`y`; Ed25519 `d`/`x`; RSA `n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `qi` (no leading zeros) and `bits`; ML-DSA `seed`, `expanded`, `pub` |
| `unsupported/` | inputs that must fail cleanly: X25519, Ed448, secp256k1, explicit EC parameters, an encrypted PKCS#8 key (password `tokenator`), and a certificate |

## RFC examples

Extracted by
`python3 -I crates/tokenator-keys/scripts/make_rfc_fixtures.py RFCDIR testdata/keys`
from the RFC texts at `https://www.rfc-editor.org/rfc/rfcNNNN.txt`
(fetched October 2026).

| Directory | Source |
|---|---|
| `rfc7517/` | RFC 7517 Appendix A.1 (public JWK Set), A.2 (private JWK Set), A.3 (symmetric JWK Set), Appendix B (RSA JWK with `x5c`) |
| `rfc7638/rsa.json` | RFC 7638 Section 3.1 JWK (thumbprint `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`) |
| `rfc8037/` | RFC 8037 Appendix A.1 (private) and A.2 (public) Ed25519 JWKs |
| `rfc8152/` | RFC 8152 Appendix C.7.1 (public) and C.7.2 (private) COSE_KeySets, binary CBOR (481 and 816 bytes, as stated in the RFC) |
| `rfc9679/ec2-p256.cbor` | RFC 9679 Section 6 COSE_Key (thumbprint `496bd8af…253ec`) |
| `rfc9881/` | RFC 9881 Appendix C.1 private keys (seed, expanded, both; seed `000102…1f`), C.2 public keys, C.4 inconsistent private keys (1: seed and expanded disagree; 2: `tr` does not match; 3: `t0` does not match) |
| `rfc9964/` | RFC 9964 Appendix A JWKs and COSE_Keys (all-zero seed), built from `testdata/rfc9964/`. `*-private.cbor` is the RFC's COSE_Key byte for byte; `*-public.cbor` drops `priv` (-2) |
