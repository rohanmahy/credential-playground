//! Import and export across all key formats.

use crate::{Key, KeyError, Visibility};

/// A key serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyFormat {
    /// A single JWK (JSON text).
    Jwk,
    /// A JWK Set, `{"keys": [...]}` (RFC 7517 §5).
    JwkSet,
    /// A single COSE_Key (binary CBOR map).
    CoseKey,
    /// A COSE_KeySet (binary CBOR array of COSE_Key maps).
    CoseKeySet,
    /// PEM text (RFC 7468) holding DER.
    Pem(PemEncoding),
}

/// The DER structure inside a PEM block.
///
/// On import the PEM label decides, so every `Pem(_)` hint means "PEM".
/// On export these choose the structure; exports are byte-for-byte what
/// OpenSSL writes for the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PemEncoding {
    /// Export: SPKI for [`Visibility::Public`], PKCS#8 for
    /// [`Visibility::Private`].
    Auto,
    /// SPKI, `PUBLIC KEY` (RFC 5280 §4.1.2.7; RFC 5480, RFC 8410, RFC 8017,
    /// RFC 9881 §4). Public only.
    Spki,
    /// PKCS#8 v1, `PRIVATE KEY` (RFC 5208 / RFC 5958). Private only. EC keys
    /// carry an RFC 5915 ECPrivateKey with the public key and without
    /// parameters; Ed25519 keys an RFC 8410 CurvePrivateKey; RSA keys a
    /// PKCS#1 RSAPrivateKey; ML-DSA keys the seed form when the seed is
    /// known, else the expanded form (RFC 9881 §6).
    Pkcs8,
    /// PKCS#8 with an explicit ML-DSA private key form (RFC 9881 §6).
    /// Only for ML-DSA keys.
    Pkcs8MlDsa(MlDsaPrivateForm),
    /// SEC1 ECPrivateKey, `EC PRIVATE KEY` (RFC 5915), with the named curve
    /// and the public key. EC keys only, private only.
    Sec1,
    /// PKCS#1 (RFC 8017 Appendix A.1): `RSA PRIVATE KEY` for
    /// [`Visibility::Private`], `RSA PUBLIC KEY` for [`Visibility::Public`].
    /// RSA keys only.
    Pkcs1,
}

/// The RFC 9881 §6 `ML-DSA-PrivateKey` CHOICE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlDsaPrivateForm {
    /// `seed [0] OCTET STRING (SIZE (32))`. Needs a known seed.
    Seed,
    /// `expandedKey OCTET STRING`.
    Expanded,
    /// `both SEQUENCE { seed, expandedKey }`. Needs a known seed.
    Both,
}

/// Parses keys from bytes.
///
/// Without a hint the format is detected: input containing a PEM
/// `-----BEGIN ` line is PEM; input whose first non-whitespace byte is `{`
/// is JSON (a JWK, or a JWK Set if it has a `keys` array); anything else is
/// CBOR (a map is a COSE_Key, an array a COSE_KeySet). A hint skips
/// detection: `Jwk` and `JwkSet` both mean JSON (either shape), `CoseKey`
/// and `CoseKeySet` both mean CBOR, `Pem(_)` means PEM.
///
/// Sets and inputs with several PEM blocks give several keys, in order.
/// Text outside PEM blocks is ignored, as are `EC PARAMETERS` blocks. If
/// any key fails, the whole import fails; use [`import_each`] to keep the
/// keys that parse.
pub fn import(input: &[u8], hint: Option<KeyFormat>) -> Result<Vec<Key>, KeyError> {
    unimplemented!()
}

/// Like [`import`], but returns one result per key (set member or PEM
/// block). The outer error is for input that cannot be split into keys at
/// all (not PEM / JSON / CBOR, not an object / map / set).
pub fn import_each(
    input: &[u8],
    hint: Option<KeyFormat>,
) -> Result<Vec<Result<Key, KeyError>>, KeyError> {
    unimplemented!()
}

/// Serializes one key.
///
/// JWK and JWK Set output is compact JSON (see [`to_jwk`](crate::to_jwk));
/// a set holds just this key. COSE output is binary CBOR (see
/// [`to_cwk`](crate::to_cwk)). PEM output uses 64-character lines, LF line
/// endings, and a final newline. JOSE and COSE metadata (kid, alg,
/// key_ops, extras) does not exist in PEM and is dropped.
pub fn export(key: &Key, format: KeyFormat, visibility: Visibility) -> Result<Vec<u8>, KeyError> {
    unimplemented!()
}

/// Serializes several keys: a JWK Set, a COSE_KeySet, or concatenated PEM
/// blocks. `Jwk` and `CoseKey` accept exactly one key.
pub fn export_set(
    keys: &[Key],
    format: KeyFormat,
    visibility: Visibility,
) -> Result<Vec<u8>, KeyError> {
    unimplemented!()
}
