# tokenator-keys test plan

Scope: the key model (material plus metadata), every key format (PEM, JWK,
JWK Set, COSE_Key, COSE_KeySet), JWK <-> COSE_Key conversion, thumbprints
and thumbprint URIs, params for the linter, generation, and kid assignment
(SPEC §4.2, §6 alg/key consistency). Cryptography (validation, public key
derivation, generation, hashing) belongs to `tokenator-crypto` and is only
exercised through it. EDN key input is converted to CBOR by the core and is
out of scope here.

Run with `cargo test -p tokenator-keys`. Slow RSA-3072/4096 generation and
the RFC 9881 C.4 `tr`/`t0` test (#18) are `#[ignore]`d. Fixtures live in
`testdata/keys/` (see its README); the scripts that made them are in
`scripts/`. The crate itself never runs OpenSSL.

## Public API under test

```rust
pub struct Key { /* material */ pub role: Option<Role>, pub kid: Option<Kid>,
                 pub alg: Option<DeclaredAlg>, pub key_use: Option<String>,
                 pub key_ops: Option<Vec<KeyOp>>, pub extras: Vec<Extra>, pub derived: bool }
Key::{from_private, from_public, is_private, private_key, public_key, key_type, same_material}
impl PartialEq for Key        // material (same_material) + every metadata field
pub enum Role { Issuer, Holder, Verifier }
pub enum Kid { Text(String), Bytes(Vec<u8>) }   // as_bytes(), to_jose_string()
pub enum KeyOp { Sign, Verify, Encrypt, Decrypt, WrapKey, UnwrapKey, DeriveKey, DeriveBits, Other(Label) }
pub enum Label { Text(String), Int(i64) }
pub enum Extra { Jose { name, json }, Cose { label, cbor } }
pub enum Visibility { Public, Private }

pub enum KeyFormat { Jwk, JwkSet, CoseKey, CoseKeySet, Pem(PemEncoding) }
pub enum PemEncoding { Auto, Spki, Pkcs8, Pkcs8MlDsa(MlDsaPrivateForm), Sec1, Pkcs1 }
pub enum MlDsaPrivateForm { Seed, Expanded, Both }
pub fn import(&[u8], Option<KeyFormat>) -> Result<Vec<Key>, KeyError>;
pub fn import_each(&[u8], Option<KeyFormat>) -> Result<Vec<Result<Key, KeyError>>, KeyError>;
pub fn export(&Key, KeyFormat, Visibility) -> Result<Vec<u8>, KeyError>;
pub fn export_set(&[Key], KeyFormat, Visibility) -> Result<Vec<u8>, KeyError>;

pub struct Jwk;      // parse, from_node, node, to_json, member_names, get_str
pub struct CoseKey;  // decode, from_item, item, to_cbor, labels, get
pub fn to_jwk(&Key, Visibility) -> Result<Jwk, KeyError>;   pub fn from_jwk(&Jwk) -> Result<Key, KeyError>;
pub fn to_cwk(&Key, Visibility) -> Result<CoseKey, KeyError>; pub fn from_cwk(&CoseKey) -> Result<Key, KeyError>;
pub fn params(&Key) -> KeyParams;
pub fn params_from_jwk(&Jwk) -> Result<KeyParams, KeyError>;   // no material needed
pub fn params_from_cwk(&CoseKey) -> Result<KeyParams, KeyError>;
pub fn to_public(&Key) -> Key;

pub enum ThumbprintKind { Jwk, Cose }
pub fn thumbprint(&Key, ThumbprintKind, HashAlg) -> Vec<u8>;
pub fn jwk_thumbprint(&Jwk, HashAlg) -> Result<Vec<u8>, KeyError>;      // RFC 7638, raw members
pub fn cose_thumbprint(&CoseKey, HashAlg) -> Result<Vec<u8>, KeyError>; // RFC 9679
pub fn jwk_thumbprint_uri(&Key, HashAlg) -> String;   // RFC 9278
pub fn cose_thumbprint_uri(&Key, HashAlg) -> String;  // RFC 9679 §5.7

pub const WELL_KNOWN_TEST_SEED: [u8; 32];
pub fn generate(KeySpec, Option<Role>, Option<&[u8]>, &mut dyn CryptoRng) -> Result<Key, KeyError>;
pub enum KidSource { JwkThumbprint(HashAlg), CoseThumbprint(HashAlg), Text(String), Bytes(Vec<u8>) }
pub fn assign_kid(&mut Key, KidSource);

pub enum KeyError { UnrecognizedFormat, Json, Cbor, Pem, Der, UnsupportedPemLabel,
    EncryptedPrivateKey, UnsupportedAlgorithm(oid), UnsupportedCurve, UnsupportedKeyType,
    MissingParameter(name), InvalidParameter{name, reason}, InconsistentKey, Crypto,
    NoPrivateKey, FormatNotApplicable{format, reason}, MlDsaSeedUnknown }
```

`DeclaredAlg`, `HashAlg`, `KeyParams`, and `KeySpec` are re-exported from
`tokenator-crypto`.

## Dependencies

| crate | version | why |
|---|---|---|
| `tokenator-crypto`, `-cbor`, `-json` | path | material, COSE_Key maps, JWK objects |
| `der` | 0.8 | ASN.1 for SEC1/PKCS#8/PKCS#1/RFC 9881 structures |
| `spki` | 0.8 | SubjectPublicKeyInfo |
| `pkcs8` | 0.11 | PrivateKeyInfo / OneAsymmetricKey |
| `sec1` | 0.8 | ECPrivateKey |
| `pkcs1` | 0.8.0-rc.5 | RSAPrivateKey / RSAPublicKey (only 0.8 release on der 0.8; RC like `rsa`) |
| `pem-rfc7468` | 1.0 | PEM armor |
| `base64ct` | 1.8 | base64url for JWK |

All are the RustCrypto generation `tokenator-crypto` already pulls in (der
0.8.3, spki 0.8.1, pkcs8 0.11.0, sec1 0.8.1 are already in `Cargo.lock`), are
pure Rust, and have no `getrandom`. Dev: `proptest`, `serde_json`, `hex`,
`rand_chacha`.

## Decisions encoded in the tests

Questions are filed as #16 (import scope), #17 (metadata mapping), #18
(crypto gaps). Defaults:

- **Detection:** a `-----BEGIN ` line means PEM; a first non-blank `{` means
  JSON (a `keys` array means a set); otherwise CBOR (a map means a key, an
  array a set; anything else is `UnrecognizedFormat`). Hints skip
  detection; `Jwk`/`JwkSet` both accept either JSON shape, and the same goes
  for COSE.
- **Sets:** `import` fails if any member fails; `import_each` reports each one.
  Empty sets import as no keys.
- **PEM:** text outside blocks and CRLF are tolerated, `EC PARAMETERS` is
  skipped, `CERTIFICATE` and `ENCRYPTED PRIVATE KEY` are errors, RSA-PSS OID
  keys import as RSA, X25519/Ed448/secp256k1/explicit curves are errors (OID
  in dotted form). PKCS#8 v2 public keys and SEC1 public keys must match the
  private key.
- **PEM export is byte-identical to OpenSSL 4.1:** SPKI; PKCS#8 v1 (EC inner
  ECPrivateKey with public key, no parameters; Ed25519 v1 without public key);
  SEC1 with named curve and public key; PKCS#1; RFC 9881 ML-DSA seed /
  expanded / both (default: seed when known). 64-column LF lines, final
  newline.
- **kid:** JOSE text, COSE bytes; to COSE always a bstr; to JWK the UTF-8
  text, or base64url for non-UTF-8 bytes.
- **alg:** known algs map between names and labels; unknown JOSE names become
  a COSE tstr, unknown COSE labels a JWK number. AKP keys always export an
  `alg` (from the parameter set if none is declared); thumbprints of AKP keys
  use the material's parameter set.
- **key_ops:** 1–8 map between names and labels; anything else is kept verbatim.
  **use:** dropped in COSE. **Extras:** kept in arrival order within their
  family, dropped across families. **Role:** never serialized.
- **Output order:** JWK `kty, kid, alg, use, key_ops`, key params, extras;
  COSE `1, 2, 3, 4`, then -1, -2, …, then extras; preferred CBOR encoding.
- **Material:** EC coordinates and scalars are fixed-width on output; short EC
  values are left-padded on input (#11); Ed25519/AKP lengths are strict; RSA
  integers have no leading zeros. AKP `priv` is the 32-byte seed; an
  expanded-only ML-DSA key has no private JWK/COSE_Key (`MlDsaSeedUnknown`).
- **Strictness:** duplicate members/labels, wrong value types, and bad
  base64url are `InvalidParameter`; crv/kty contradictions and private/public
  disagreement are `InconsistentKey`; off-curve points are `Crypto`. AKP needs
  `alg`. `params_from_*` and the thumbprint functions do not validate material.
- **Seeds:** 32 bytes are used as is; other lengths are SHA-256 hashed first.
  `WELL_KNOWN_TEST_SEED` is 32 zero bytes (RFC 9964 Appendix A).

## Test files

| file | covers |
|---|---|
| `rfc_jwk.rs` | RFC 7517 A.1/A.2/A.3/B (sets, private, symmetric unsupported, `x5c` extra); RFC 8037 A.1–A.4 (Ed25519, exact `to_jwk` text, thumbprint, signature verifies); RFC 7638 §3.1 thumbprint (base64url and octets); RFC 9278 URI; RFC 9964 A.1 (AKP import, kid = JWK thumbprint, JWS verifies, member order, AKP `alg` always present) |
| `rfc_cose.rs` | RFC 8152 C.7.1/C.7.2 key sets (481/816 bytes; symmetric keys unsupported; `import_each`); RFC 9679 §6 thumbprint, §5.7 URI, exact `to_cwk` bytes; RFC 9964 A.2 (kid = COSE thumbprint, Sign1 verifies, label order); COSE text kid, unknown labels kept, compressed point is an error |
| `pem.rs` | every OpenSSL fixture form imports with the expected components; RSA 2048/3072/4096 sizes; RSA-PSS OID; ML-DSA seed/expanded/both; RFC 8410 v1/v2; RFC 9881 C.1/C.2 and C.4 #1 (C.4 #2/#3 ignored, #18); byte-exact exports vs OpenSSL and the RFC texts; formats that don't apply; multi-block, surrounding text, CRLF; unsupported algorithms and labels; malformed armor; DER truncated at every length; trailing DER; wrong label for contents; off-curve point; SEC1/PKCS#8 public key mismatch; inconsistent PKCS#1 |
| `roundtrip.rs` | 8 key types × every applicable format × public/private: `import(export(k)) == k` (metadata included for JOSE/COSE), hints don't change results, re-export is byte-stable, secrets survive; sets of every kind; single-key set shape; empty sets; `export_set` arity; private export of a public key |
| `convert.rs` | JWK → COSE → JWK keeps material, kid, and alg; kid helpers; key_ops mapping and unknown ops; known/unknown alg mapping; `use` dropped; JOSE extras keep order and lexemes; extras don't cross families; no private params in public exports; member/label order per key type; value types and widths; expanded-only ML-DSA; `Jwk`/`CoseKey` helpers and embedded `cnf` keys; RFC 9964 JWK converts to the RFC COSE_Key |
| `key_model.rs` | constructors and accessors; `to_public` keeps metadata, marks derived, is idempotent; `same_material`; equality over every field; seed vs expanded ML-DSA keys are equal; `Debug` hides secrets |
| `params.rs` | `params` from material plus declared alg (with `check_key`); params agree across Key/JWK/COSE; `params_from_jwk`/`_cwk` without material, contradictions reported faithfully, unknown curves, RSA bits from `n` (leading zero, 2041, 1024 too small, undecodable), AKP set from `alg` or `pub` length; errors; params work where `from_*` fails |
| `thumbprint.rs` | proptest: JWK thumbprint ignores member order, extra members, whitespace; COSE thumbprint ignores map order, extra labels, non-preferred widths; exact canonical inputs for each hash; no material needed; missing members; Key thumbprints equal format thumbprints for public/private; metadata independence; AKP alg; `assign_kid` from every source, reproducing the RFC 9964 and RFC 9679 kids |
| `generate.rs` | seeded generation reproducible and independent of the RNG; matches `generate_from_seed`; different seeds differ; RNG-driven generation; only `role` set; other seed lengths hashed; well-known seed; RFC 8037 / RFC 9964 / RFC 9881 keys from their seeds; RSA 2048 seeded (3072/4096 ignored) |
| `errors.rs` | JWK: not JSON / not an object, kty missing/unsupported/case, missing members per key type, AKP without `alg`, unsupported curves, crv/kty mismatch, bad base64url, wrong types, duplicates, wrong lengths, short EC values padded, off-curve, private/public disagreement, inconsistent RSA, AKP mismatches, set element errors, deep nesting. COSE: malformed CBOR, trailing bytes, non-map items, missing/unsupported kty/crv, crv/kty mismatch, wrong value types, duplicate labels, private/public disagreement, set element errors, deep nesting. Hint mismatches, empty input, garbage |
| `proptest.rs` | never panic: random bytes, random text, mutated and truncated fixtures of every format, JWK-shaped objects, COSE-shaped maps, PEM with random or mutated DER under every label; `Kid::to_jose_string` reversible; seeded keys round-trip |

## Not covered (follow-ups)

- ML-DSA expanded keys with a wrong `tr`/`t0`, and compressed EC points, both need
  tokenator-crypto support (#18).
- Arrival-order-preserving re-export (#17), certificate import (#16).
- EDN COSE_Key input (core → tokenator-edn → CBOR → `import`).
