# tokenator-crypto test plan

Scope: the algorithm registry (JOSE names / COSE labels), format-neutral key
material, sign / verify / digest, key generation (random and from a seed), and
the alg/key requirements table that the linter uses (SPEC §2, §6).
JWK / COSE_Key / PEM parsing belongs to `tokenator-keys` and is out of scope.

Run with `cargo test -p tokenator-crypto`. The slow RSA-3072/4096 keygen tests
are `#[ignore]`d; run them with `-- --ignored`. The WASM check is
`crates/tokenator-crypto/scripts/check-wasm.sh`.

## Public API under test

```rust
pub enum Alg { ES256, ES384, ES512, EdDSA, Ed25519, RS256, RS384, RS512,
               PS256, PS384, PS512, MlDsa44, MlDsa65, MlDsa87 }  // Alg::ALL, fixed_signature_len()
pub fn alg_from_jose(&str) -> Option<Alg>;  pub fn alg_to_jose(Alg) -> &'static str;
pub fn alg_from_cose(i64) -> Option<Alg>;   pub fn alg_to_cose(Alg) -> i64;
pub enum HashAlg { Sha256, Sha384, Sha512 }  // name()/from_name() ("sha-256"), cose_label(), output_len()
pub enum Curve { P256, P384, P521, Ed25519 } // jwk_name, cose_label, key_type, field_len (+ inverses)
pub enum KeyType { Ec, Okp, Rsa, Akp }       // jwk_kty, cose_kty (+ inverses)
pub enum MlDsaParams { MlDsa44, MlDsa65, MlDsa87 } // alg, public_key_len, expanded_private_key_len, signature_len

pub enum PublicKeyMaterial  { Ec{curve,x,y}, Ed25519{x}, Rsa{n,e}, MlDsa{params,public} }
pub enum PrivateKeyMaterial { Ec{curve,d}, Ed25519{d}, Rsa(RsaPrivateMaterial), MlDsa{params,seed,expanded} }
PrivateKey::{from_material, to_material, public_key, params}   // Debug is redacted
PublicKey::{from_material, to_material, params}
pub enum KeySpec { P256, P384, P521, Ed25519, Rsa{bits}, MlDsa(MlDsaParams) }  // KeySpec::for_alg
pub fn generate(KeySpec, &mut dyn CryptoRng) -> Result<PrivateKey, CryptoError>;
pub fn generate_from_seed(KeySpec, &[u8; 32]) -> Result<PrivateKey, CryptoError>;

pub fn sign(Alg, &PrivateKey, &[u8], &mut dyn CryptoRng) -> Result<Vec<u8>, CryptoError>;  // hedged
pub fn sign_deterministic(Alg, &PrivateKey, &[u8]) -> Result<Vec<u8>, CryptoError>;      // RFC 6979 / FIPS 204 det.
pub fn verify(Alg, &PublicKey, &[u8], &[u8]) -> Result<(), CryptoError>;
pub fn digest(HashAlg, &[u8]) -> Vec<u8>;

pub struct KeyRequirements { kty, jwk_kty, cose_kty, crv, akp_param_set, min_rsa_bits }
pub struct KeyParams { kty, crv, rsa_bits, ml_dsa, declared_alg: Option<DeclaredAlg> }
pub enum DeclaredAlg { Known(Alg), UnknownJose(String), UnknownCose(i64) }
pub enum KeyMismatch { KeyType{..}, Curve{..}, RsaTooSmall{..}, MlDsaParamSet{..}, DeclaredAlg{..} }
pub fn requirements(Alg) -> KeyRequirements;
pub fn check_key(Alg, &KeyParams) -> Vec<KeyMismatch>;
pub fn algs_for_key(&KeyParams) -> Vec<Alg>;
pub enum CryptoError { InvalidKey(&str), KeyNotSuitable{alg, mismatches}, InvalidSignature,
                       RandomnessRequired(Alg), UnsupportedKeySpec(&str) }
```

`rand_core` is re-exported, so callers name the same `CryptoRng`.

## Dependencies (one RustCrypto generation, pure Rust)

| crate | version | notes |
|---|---|---|
| `rand_core` | 0.10 | `CryptoRng` is the injected-RNG trait (`&mut dyn CryptoRng`) |
| `signature` | 3 | |
| `sha2` | 0.11 | |
| `ecdsa` | 0.17 | RFC 6979 via `rfc6979 0.6` |
| `p256` / `p384` / `p521` | 0.14 | `default-features = false, features = ["ecdsa", "alloc"]` (`std` would pull in `getrandom`) |
| `ed25519-dalek` | 3.0 | `alloc, fast, rand_core, zeroize` |
| `rsa` | `=0.10.0-rc.19` | the only `rsa` on rand_core 0.10. The pin is tracked in #9 |
| `ml-dsa` | 0.1.1 | `alloc, rand_core, zeroize` (no `getrandom`, no `pkcs8`) |
| `rand_chacha` | 0.10 | drives EC/RSA `generate_from_seed` |

Dev: `hex`, `serde_json`, `base64ct`.

## Codepoints (checked against the live registries, 2026-10-28)

Sources:
[IANA JOSE](https://www.iana.org/assignments/jose/jose.xhtml) (`web-signature-encryption-algorithms.csv`,
`web-key-types.csv`, `web-key-elliptic-curve.csv`, `web-key-parameters.csv`);
[IANA COSE](https://www.iana.org/assignments/cose/cose.xhtml) (`algorithms.csv`,
`key-type.csv`, `elliptic-curves.csv`, `key-type-parameters.csv`);
[IANA Named Information hash names](https://www.iana.org/assignments/named-information/named-information.xhtml);
[RFC 9964](https://www.rfc-editor.org/rfc/rfc9964) (ML-DSA for JOSE and COSE, May 2026; this was draft-ietf-cose-dilithium);
[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864) (fully-specified algorithms);
FIPS 204 Table 2 (ML-DSA sizes).

| Alg | JOSE | COSE | key | IANA status / ref |
|---|---|---|---|---|
| ES256 | `ES256` | -7 | EC P-256 | JOSE Recommended+ (RFC 7518); COSE Deprecated (RFC 9864) |
| ES384 | `ES384` | -35 | EC P-384 | COSE Deprecated |
| ES512 | `ES512` | -36 | EC P-521 | COSE Deprecated |
| EdDSA | `EdDSA` | -8 | OKP Ed25519 | Deprecated in both (RFC 9864) |
| Ed25519 | `Ed25519` | -19 | OKP Ed25519 | RFC 9864 §2.2 |
| RS256/384/512 | `RS256`… | -257/-258/-259 | RSA ≥ 2048 | RFC 7518 §3.3, RFC 8812 |
| PS256/384/512 | `PS256`… | -37/-38/-39 | RSA ≥ 2048 | RFC 7518 §3.5, RFC 8230 |
| ML-DSA-44/65/87 | `ML-DSA-44`… | -48/-49/-50 | AKP | RFC 9964 |

Key types: JOSE `EC`/`OKP`/`RSA`/`AKP`; COSE OKP=1, EC2=2, RSA=3, AKP=7.
Curves: JOSE `P-256`/`P-384`/`P-521`/`Ed25519`; COSE 1/2/3/6.
AKP parameters: `pub` (-1) and `priv` (-2). RFC 9964 §3 says `priv` MUST be
the 32-byte seed. Hashes: `sha-256`/`sha-384`/`sha-512`; COSE -16/-43/-44.
ML-DSA sizes (pk / expanded sk / sig): 44 = 1312/2560/2420, 65 = 1952/4032/3309, 87 = 2592/4896/4627.
Not supported (map to `None`): `none`, HMAC, `ES256K`, Ed448, and the COSE
ESP256/384/512 (-9/-51/-52) labels. Their scope is tracked in #10.

## Test files

| file | covers |
|---|---|
| `tests/registry.rs` | JOSE/COSE alg tables both ways, round trips for every `Alg`, case sensitivity, unsupported names/labels, `fixed_signature_len`, curve/kty/hash tables, ML-DSA sizes |
| `tests/requirements.rs` | `requirements()` for every alg; `check_key` for matching keys, ES256 + P-384, every wrong EC curve, OKP vs EC, kty mismatch suppressing detail checks, RSA 1024 / 2047 / unknown size, ML-DSA-65 key with ML-DSA-44, AKP without a param set, declared alg disagreeing (known, unknown JOSE, unknown COSE, EdDSA vs Ed25519), finding order; `algs_for_key` table and its invariant (`== {a : check_key(a) is empty}`) over all params × declared algs |
| `tests/digest.rs` | SHA-256/384/512 of `""`, `"abc"`, the 448-bit message, and one million `a`s |
| `tests/keys.rs` | `KeySpec::for_alg`; generation with expected params; all randomness comes from the injected RNG; seeded generation is reproducible; EC seed == ChaCha20Rng(seed); Ed25519 seed == RFC 8032 secret; ML-DSA seed == RFC 9964 `xi`; fixed-width output; private/public material round trips; RFC 7515/8037 JWKs derive their public keys; RSA output is minimal and complete; RSA from n,e,d recovers p,q; RSA leading zeros are accepted; `params()`; redacted `Debug`; invalid EC scalars (0, n, > n, wrong width, wrong curve); off-curve points; Ed25519 lengths; inconsistent RSA (bad d, bad p, e = 1, empty n/e); ML-DSA seed/expanded/both/neither/mismatch/wrong param set/public length |
| `tests/keygen_rsa.rs` | RSA 2048 generation (3072/4096 ignored): bit length, e = 65537, CRT parts, sign+verify; unsupported sizes; seeded reproducibility == ChaCha20Rng(seed) |
| `tests/sign_verify.rs` | round trip for every alg (seeded keys, fresh keys, 0 B / 1 B / 1 MiB messages); `sign_deterministic` for all except PSS (→ `RandomnessRequired`); same RNG seed gives the same signature; randomized algs use the RNG and differ from deterministic output (hedging); deterministic algs ignore the RNG; EdDSA ≡ Ed25519; tampered message, tampered signature, wrong lengths (empty, ±1 byte, half, doubled, zeros); ECDSA DER is rejected and output is raw r‖s of fixed width; wrong public key; cross-RSA-alg confusion; `KeyNotSuitable` (with `check_key` findings) on sign/verify for wrong kty/curve/param set; ML-DSA cross-param-set; garbage never panics |
| `tests/kat_rfc.rs` | RFC 7515 A.2 (RS256 verify + exact sign), A.3 (ES256), A.4 (ES512) verify; RFC 8037 A.4 Ed25519 exact sign with both `EdDSA` and `Ed25519`; RFC 8032 §7.1 (5 vectors) keygen + exact sign + verify; RFC 6979 A.2.5–A.2.7 exact deterministic ECDSA for ES256/384/512 ("sample", "test"); RFC 9964 A.1/A.2 for all three param sets: verify, seed → public key, exact deterministic sign; extraction self-check |
| `tests/wycheproof.rs` | ECDSA P1363 P-256/384/521, Ed25519 (as both EdDSA and Ed25519), RSA PKCS#1 2048/3072/4096, RSA-PSS 2048-SHA256-32 / 2048-SHA384-48 / 4096-SHA512-64, ML-DSA verify 44/65/87, ML-DSA sign-from-seed 44/65/87 (deterministic exact match, plus the hedged vector fed through a fixed-byte RNG to pin `rnd` = the next 32 RNG bytes, and invalid seed lengths) |

That's 108 integration tests (2 ignored) plus 1 doctest. Every Wycheproof file is
asserted to run all of its vectors.

## Test vectors

All of them are under `testdata/` at the repo root, with provenance READMEs:

- `testdata/rfc/`: RFC 7515 App. A.2–A.4, RFC 8037 App. A, RFC 6979 A.2.5–A.2.7, RFC 8032 §7.1.
- `testdata/rfc9964/`: RFC 9964 App. A (JOSE and COSE, ML-DSA-44/65/87).
- `testdata/wycheproof/`: a curated subset of C2SP/wycheproof `testvectors_v1` at
  commit `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9`, with the Apache-2.0 LICENSE.

The generators are in `crates/tokenator-crypto/scripts/` (`extract_rfc9964.py`,
`extract_rfc_kat.py`, `curate_wycheproof.py`; run them with `python3 -I`).
FIPS 204 ACVP vectors aren't included: the Wycheproof ML-DSA sign-seed and verify files
already cover keygen-from-seed, deterministic and hedged signing, and the
verify edge cases, with JOSE/COSE's empty context. RFC 9964 adds the
JOSE/COSE examples.

Before committing, the vectors were cross-checked in a throwaway program
directly against the chosen backends (not committed). RFC 6979, RFC 7515
ES256, RFC 8037, RFC 9964 (seed → pk, verify, deterministic sign), Wycheproof
ML-DSA-44 sign-seed, and every ECDSA, Ed25519 (both `verify` and
`verify_strict`), RSA PKCS#1 2048, and PSS 2048 Wycheproof file all agree with
the backends.

## Constraints encoded for the implementation

- **No implicit randomness, no I/O.** All randomness comes from the injected
  `&mut dyn CryptoRng`. The same seed gives the same keys and signatures.
- **WASM:** `cargo build -p tokenator-crypto --target wasm32-unknown-unknown`
  must succeed, and `getrandom` must not be a normal dependency. Both are checked by
  `scripts/check-wasm.sh`. Don't enable `std`/`getrandom` features on the
  backends.
- **ECDSA** signatures are raw fixed-width `r‖s` (64/96/132 bytes), never DER.
  `sign_deterministic` is pure RFC 6979. `sign` is RFC 6979 hedged with
  RNG entropy.
- **ML-DSA** is pure ML-DSA with an empty context. `sign` uses the next 32 RNG
  bytes as `rnd`, and `sign_deterministic` uses `rnd` = 0.
- **PSS** salt length equals the hash length, and verify must enforce it.
- **Undersized RSA** (< 2048) is linted, not refused by sign/verify (#11).
  RSA keygen accepts only 2048/3072/4096.
- **Fixed-width inputs:** EC `d`/`x`/`y` and Ed25519 `d`/`x` must be exactly the field
  length (#11). RSA integers accept leading zeros and emit none.
- **`check_key` order:** KeyType (which suppresses the detail checks) → Curve /
  RsaTooSmall / MlDsaParamSet → DeclaredAlg. `algs_for_key` = the algs with no findings.

## Notes for the implementer

- Strip leading zeros before building `rsa::BoxedUint` values. With a leading
  `00` byte, Wycheproof RSA keys built using `from_be_slice_vartime` failed to verify.
- `RsaPublicKey::new` caps keys at 8192 bits.
- `ml_dsa::SigningKey::from_seed`, `ExpandedSigningKey::{from_expanded,
  to_expanded, sign_deterministic, sign_randomized}`, and
  `VerifyingKey::{decode, verify_with_context}` cover all of the ML-DSA needs.
- `ed25519-dalek`'s `verify` and `verify_strict` both pass the curated Wycheproof
  set. Prefer `verify_strict`.
- `KeyNotSuitable.mismatches` must equal `check_key(alg, &key.params())`.

## Open questions

#9 (rsa RC pin, seeded keygen stability), #10 (ESP256/384/512, EdDSA vs
Ed25519 declared alg, unknown declared algs), and #11 (weak RSA, keygen sizes,
fixed-width inputs, hedged signing, test seed). The defaults described there are
what the tests encode.
