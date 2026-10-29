//! Import and export across all key formats.

use tokenator_cbor::Value as CborValue;
use tokenator_json::Value as JsonValue;

use crate::{CoseKey, Jwk, Key, KeyError, Visibility, from_cwk, from_jwk, pem, to_cwk, to_jwk};

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
    import_each(input, hint)?.into_iter().collect()
}

/// Like [`import`], but returns one result per key (set member or PEM
/// block). The outer error is for input that cannot be split into keys at
/// all (not PEM / JSON / CBOR, not an object / map / set).
///
/// ```
/// use tokenator_keys::{KeyError, import, import_each};
///
/// // A JWK Set with a symmetric key, which is not supported.
/// let set = br#"{"keys":[{"kty":"oct","k":"AAAA"},
///   {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#;
/// assert_eq!(import(set, None), Err(KeyError::UnsupportedKeyType("oct".into())));
/// let each = import_each(set, None)?;
/// assert!(each[0].is_err() && each[1].is_ok());
/// # Ok::<(), KeyError>(())
/// ```
pub fn import_each(
    input: &[u8],
    hint: Option<KeyFormat>,
) -> Result<Vec<Result<Key, KeyError>>, KeyError> {
    let first = input.iter().find(|b| !b.is_ascii_whitespace());
    let family = match hint {
        Some(KeyFormat::Jwk | KeyFormat::JwkSet) => Family::Json,
        Some(KeyFormat::CoseKey | KeyFormat::CoseKeySet) => Family::Cbor,
        Some(KeyFormat::Pem(_)) => Family::Pem,
        None => match first {
            None => return Err(KeyError::UnrecognizedFormat),
            Some(b'{') => Family::Json,
            Some(_) if pem::looks_like_pem(input) => Family::Pem,
            Some(_) => Family::Cbor,
        },
    };
    match family {
        Family::Json => import_json(input),
        Family::Cbor => import_cbor(input),
        Family::Pem => pem::import_blocks(input),
    }
}

/// The three serializations import can detect.
enum Family {
    Json,
    Cbor,
    Pem,
}

/// A JWK, or a JWK Set when the object has a `keys` member.
fn import_json(input: &[u8]) -> Result<Vec<Result<Key, KeyError>>, KeyError> {
    let root = tokenator_json::parse(input)?;
    if root.members().is_none() {
        return Err(KeyError::UnrecognizedFormat);
    }
    let Some(keys) = root.get("keys") else {
        return Ok(vec![Jwk::from_node(&root).and_then(|jwk| from_jwk(&jwk))]);
    };
    let JsonValue::Array(keys) = keys.value() else {
        return Err(KeyError::InvalidParameter {
            name: "keys".into(),
            reason: "not an array",
        });
    };
    Ok(keys
        .iter()
        .map(|node| Jwk::from_node(node).and_then(|jwk| from_jwk(&jwk)))
        .collect())
}

/// A COSE_Key (map) or a COSE_KeySet (array of maps).
fn import_cbor(input: &[u8]) -> Result<Vec<Result<Key, KeyError>>, KeyError> {
    let item = tokenator_cbor::decode(input)?.into_owned();
    match item.value {
        CborValue::Map(_) => Ok(vec![CoseKey::from_owned(item).and_then(|k| from_cwk(&k))]),
        // Each member is moved, not cloned: cloning deep items is costly.
        CborValue::Array(items) => Ok(items
            .into_iter()
            .map(|item| CoseKey::from_owned(item).and_then(|k| from_cwk(&k)))
            .collect()),
        _ => Err(KeyError::UnrecognizedFormat),
    }
}

/// Serializes one key.
///
/// JWK and JWK Set output is compact JSON (see [`to_jwk`](crate::to_jwk));
/// a set holds just this key. COSE output is binary CBOR (see
/// [`to_cwk`](crate::to_cwk)). PEM output uses 64-character lines, LF line
/// endings, and a final newline. JOSE and COSE metadata (kid, alg,
/// key_ops, extras) does not exist in PEM and is dropped.
pub fn export(key: &Key, format: KeyFormat, visibility: Visibility) -> Result<Vec<u8>, KeyError> {
    export_set(core::slice::from_ref(key), format, visibility)
}

/// Serializes several keys: a JWK Set, a COSE_KeySet, or concatenated PEM
/// blocks. `Jwk` and `CoseKey` accept exactly one key.
pub fn export_set(
    keys: &[Key],
    format: KeyFormat,
    visibility: Visibility,
) -> Result<Vec<u8>, KeyError> {
    let single = || match keys {
        [key] => Ok(key),
        _ => Err(KeyError::FormatNotApplicable {
            format,
            reason: "holds exactly one key",
        }),
    };
    match format {
        KeyFormat::Jwk => Ok(to_jwk(single()?, visibility)?.to_json().into_bytes()),
        KeyFormat::CoseKey => Ok(to_cwk(single()?, visibility)?.to_cbor()),
        KeyFormat::JwkSet => {
            let members = keys
                .iter()
                .map(|key| to_jwk(key, visibility).map(|jwk| jwk.to_json()))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(format!(r#"{{"keys":[{}]}}"#, members.join(",")).into_bytes())
        }
        KeyFormat::CoseKeySet => {
            let items = keys
                .iter()
                .map(|key| to_cwk(key, visibility).map(|cwk| cwk.item().clone()))
                .collect::<Result<Vec<_>, _>>()?;
            // The items come from valid COSE_Keys, which always encode.
            tokenator_cbor::encode(
                &tokenator_cbor::Item::array(items),
                tokenator_cbor::EncodeMode::Preserve,
            )
            .map_err(|_| KeyError::UnrecognizedFormat)
        }
        KeyFormat::Pem(enc) => {
            let mut out = Vec::new();
            for key in keys {
                out.extend(pem::export(key, enc, visibility)?);
            }
            Ok(out)
        }
    }
}
