# tokenator-keys

Key model, PEM/JWK/COSE_Key conversion, thumbprints, key generation. See the
top-level `ARCHITECTURE.md` for where this fits and `TEST-PLAN.md` for the
decisions the tests encode (#16, #17, #18).

| file | contents |
|---|---|
| `key.rs` | `Key` (material + metadata), `Kid`, `KeyOp`, `Label`, `Extra`, `Role`, `Visibility`; alg/op name tables |
| `material.rs` | `Components` (decoded parameters) → validated material; base64url, padding, export helpers |
| `jwk.rs` | `Jwk`, `to_jwk`, `from_jwk`, `params_from_jwk`, `jwk_thumbprint` |
| `cwk.rs` | `CoseKey`, `to_cwk`, `from_cwk`, `params_from_cwk`, `cose_thumbprint` |
| `pem.rs` | PEM armor; SPKI, PKCS#8, SEC1, PKCS#1, RFC 9881 ML-DSA forms (import and export) |
| `format.rs` | `KeyFormat`, detection, `import`/`import_each`, `import_certificate`, `export`/`export_set` |
| `ops.rs` | `to_public`, `params`, thumbprints and URIs, `generate`, `assign_kid` |

## Design

- `Key` holds a `tokenator_crypto::PrivateKey` or `PublicKey`; this crate
  never touches key bytes beyond moving them between formats. Every
  import goes through `PrivateKey`/`PublicKey::from_material`, and a
  private part must derive exactly the public part that came with it
  (JWK/COSE public members, SEC1 / PKCS#8 v2 public keys).
- JWK and COSE parsing share one path: format code decodes and checks
  shapes and lengths (left-padding short EC values, #11), producing
  `Components`; `Components::into_material` does the crypto validation.
- `Jwk` and `CoseKey` are only "an object" / "a map", so `params_from_*`
  and the thumbprint functions work without valid material. `Jwk` holds an
  owned copy of the JSON tree (spans are dropped, number lexemes kept).
  Their `Debug` shows member names / labels only.
  A `CoseKey` must encode (no `simple(24..=31)`), so `to_cbor` stays
  infallible even though `tokenator_cbor::encode` returns a `Result`.
- Thumbprints of a `Key` are built from its public material (AKP `alg` from
  the parameter set), not from any stored JWK/COSE_Key, so metadata never
  changes them.
- PEM: blocks are found by scanning for `-----BEGIN `; the body is
  whitespace-stripped base64, so CRLF and any line width are accepted.
  DER uses the RustCrypto `spki`/`pkcs8`/`pkcs1`/`sec1` types, except
  `ECPrivateKey` decoding (to report explicit curve parameters as
  `UnsupportedCurve`) and the RFC 9881 private key CHOICE. Exports
  match OpenSSL byte for byte.
- `import_certificate` reads only an X.509 certificate's
  SubjectPublicKeyInfo (`x509-cert`, same RustCrypto generation as
  `der`/`spki` 0.8) for the `x5c`/`x5chain` leaf. Nothing else is checked
  (no signature, validity, or chain); `import` still rejects
  `CERTIFICATE` PEM blocks.
- Secrets that pass through this crate (decoded PEM bodies, private DER,
  decoded `d`/`priv`, raw `PrivateKeyMaterial`) are zeroized after use.
- COSE_KeySet members are moved out of the decoded array, never cloned.

## Gaps

- Compressed EC points and the RFC 9881 C.4 `tr`/`t0` check need
  tokenator-crypto support (#18).
