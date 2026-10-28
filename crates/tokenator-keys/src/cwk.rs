//! COSE_Key (RFC 9052 §7, RFC 9053 §7, RFC 8230 §4, RFC 9964 §3)
//! conversion.

use tokenator_cbor::{EncodeMode, Item, Value};
use tokenator_crypto::{
    Curve, DeclaredAlg, HashAlg, KeyParams, KeyType, MlDsaParams, PrivateKeyMaterial,
    PublicKeyMaterial, alg_to_cose, digest,
};
use zeroize::Zeroizing;

use crate::key::declared_alg_from_cose;
use crate::material::{
    Components, RsaPrivate, alg_for_export, bit_len, exact_len, left_pad, ml_dsa_for_alg,
    ml_dsa_for_public_len, private_for_export,
};
use crate::{Extra, Key, KeyError, KeyOp, Kid, Label, Visibility};

const KTY: i64 = 1;
const KID: i64 = 2;
const ALG: i64 = 3;
const KEY_OPS: i64 = 4;

/// A COSE_Key: one CBOR map, entries in arrival order.
///
/// Like [`Jwk`](crate::Jwk), a `CoseKey` is only known to be a map, so
/// [`params_from_cwk`] and [`cose_thumbprint`] work on keys with missing or
/// broken material.
///
/// Labels used by this crate: common 1 `kty`, 2 `kid`, 3 `alg`,
/// 4 `key_ops`; OKP -1 `crv`, -2 `x`, -4 `d`; EC2 -1 `crv`, -2 `x`, -3 `y`,
/// -4 `d`; RSA -1 `n`, -2 `e`, -3 `d`, -4 `p`, -5 `q`, -6 `dP`, -7 `dQ`,
/// -8 `qInv`; AKP -1 `pub`, -2 `priv`.
///
/// ```
/// use tokenator_keys::{CoseKey, Label};
///
/// // {1: 1, -1: 6, -2: h'00'} (an OKP key with a too-short x)
/// let cwk = CoseKey::decode(&[0xa3, 0x01, 0x01, 0x20, 0x06, 0x21, 0x41, 0x00])?;
/// assert_eq!(cwk.labels(), [Label::Int(1), Label::Int(-1), Label::Int(-2)]);
/// assert!(cwk.get(-2).is_some());
/// assert_eq!(cwk.to_cbor(), [0xa3, 0x01, 0x01, 0x20, 0x06, 0x21, 0x41, 0x00]);
/// # Ok::<(), tokenator_keys::KeyError>(())
/// ```
#[derive(Clone, PartialEq)]
pub struct CoseKey {
    item: Item<'static>,
}

/// Shows labels only, so private keys never end up in logs.
impl core::fmt::Debug for CoseKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CoseKey")
            .field("labels", &self.labels())
            .finish_non_exhaustive()
    }
}

impl CoseKey {
    /// Decodes CBOR bytes that must be a single map.
    pub fn decode(cbor: &[u8]) -> Result<CoseKey, KeyError> {
        CoseKey::from_owned(tokenator_cbor::decode(cbor)?.into_owned())
    }

    /// Copies a map item, e.g. the `COSE_Key` of a `cnf` claim.
    pub fn from_item(item: &Item<'_>) -> Result<CoseKey, KeyError> {
        match item.value {
            Value::Map(_) => CoseKey::from_owned(item.clone().into_owned()),
            _ => Err(KeyError::UnrecognizedFormat),
        }
    }

    /// Takes an owned map item. A map that cannot be encoded (it holds a
    /// `simple(24..=31)`) is not a COSE_Key, so `to_cbor` never fails.
    pub(crate) fn from_owned(item: Item<'static>) -> Result<CoseKey, KeyError> {
        match item.value {
            Value::Map(_) if tokenator_cbor::encode(&item, EncodeMode::Preserve).is_ok() => {
                Ok(CoseKey { item })
            }
            _ => Err(KeyError::UnrecognizedFormat),
        }
    }

    /// The map as a CBOR item.
    pub fn item(&self) -> &Item<'static> {
        &self.item
    }

    /// The CBOR encoding, preserving the recorded encoding details
    /// (`EncodeMode::Preserve`). A decoded key encodes to its input bytes.
    pub fn to_cbor(&self) -> Vec<u8> {
        // `from_owned` only accepts maps that encode.
        tokenator_cbor::encode(&self.item, EncodeMode::Preserve).unwrap_or_default()
    }

    /// Map labels in order, duplicates included. Labels that are neither
    /// integers nor text are skipped.
    pub fn labels(&self) -> Vec<Label> {
        self.entries()
            .iter()
            .filter_map(|(k, _)| label_of(k))
            .collect()
    }

    /// The value of integer label `label` (the first one, if duplicated).
    pub fn get(&self, label: i64) -> Option<&Item<'static>> {
        self.entries()
            .iter()
            .find(|(k, _)| int_of(k) == Some(label))
            .map(|(_, v)| v)
    }

    fn entries(&self) -> &[(Item<'static>, Item<'static>)] {
        match &self.item.value {
            Value::Map(entries) => entries,
            _ => &[],
        }
    }

    /// A byte string value, if present.
    fn bytes_opt(&self, label: i64) -> Result<Option<Vec<u8>>, KeyError> {
        match self.get(label).map(|i| &i.value) {
            None => Ok(None),
            Some(Value::Bytes(b)) => Ok(Some(b.to_vec())),
            Some(_) => Err(invalid(label, "not a byte string")),
        }
    }

    /// A required byte string value.
    fn bytes_req(&self, label: i64) -> Result<Vec<u8>, KeyError> {
        self.bytes_opt(label)?.ok_or_else(|| missing(label))
    }

    /// A secret byte string, if present.
    fn secret_opt(&self, label: i64) -> Result<Option<Zeroizing<Vec<u8>>>, KeyError> {
        Ok(self.bytes_opt(label)?.map(Zeroizing::new))
    }

    /// The key type, which every operation needs first.
    fn kty(&self) -> Result<KeyType, KeyError> {
        match self.get(KTY).map(|i| &i.value) {
            None => Err(missing(KTY)),
            Some(Value::Text(t)) => Err(KeyError::UnsupportedKeyType(t.to_string())),
            Some(v) => {
                let kty = int_value(v).ok_or_else(|| invalid(KTY, "not an integer or text"))?;
                KeyType::from_cose_kty(kty)
                    .ok_or_else(|| KeyError::UnsupportedKeyType(kty.to_string()))
            }
        }
    }

    /// The `crv` label (-1) of an EC2 / OKP key.
    fn crv(&self) -> Result<i64, KeyError> {
        match self.get(-1).map(|i| &i.value) {
            None => Err(missing(-1)),
            Some(Value::Text(t)) => Err(KeyError::UnsupportedCurve(t.to_string())),
            Some(v) => int_value(v).ok_or_else(|| invalid(-1, "not an integer or text")),
        }
    }
}

fn int_value(v: &Value<'_>) -> Option<i64> {
    match v {
        Value::Uint(n) => i64::try_from(*n).ok(),
        Value::Nint(n) => i64::try_from(*n).ok().map(|n| -1 - n),
        _ => None,
    }
}

fn int_of(item: &Item<'_>) -> Option<i64> {
    int_value(&item.value)
}

fn label_of(item: &Item<'_>) -> Option<Label> {
    match &item.value {
        Value::Text(t) => Some(Label::Text(t.to_string())),
        v => int_value(v).map(Label::Int),
    }
}

fn label_name(label: &Label) -> String {
    match label {
        Label::Int(n) => n.to_string(),
        Label::Text(t) => t.clone(),
    }
}

fn invalid(label: i64, reason: &'static str) -> KeyError {
    KeyError::InvalidParameter {
        name: label.to_string(),
        reason,
    }
}

fn missing(label: i64) -> KeyError {
    KeyError::MissingParameter(label.to_string())
}

/// The labels a key type defines (besides 1-4).
fn key_labels(kty: KeyType) -> &'static [i64] {
    match kty {
        KeyType::Ec => &[-1, -2, -3, -4],
        KeyType::Okp => &[-1, -2, -4],
        KeyType::Rsa => &[-1, -2, -3, -4, -5, -6, -7, -8],
        KeyType::Akp => &[-1, -2],
    }
}

/// Builds the COSE_Key for `key`.
///
/// Entry order: 1 `kty`, 2 `kid`, 3 `alg`, 4 `key_ops`, then the key-type
/// parameters in descending label order (-1, -2, ...), then COSE
/// [`Extra`](crate::Extra)s in arrival order. Every item uses preferred
/// (shortest) encoding. The kid is always a bstr (see [`Kid`](crate::Kid)).
/// AKP keys always get `alg`. JWK `use` is dropped. As with [`to_jwk`], an
/// expanded-only ML-DSA key cannot be exported privately.
///
/// ```
/// use tokenator_crypto::{KeySpec, MlDsaParams, generate_from_seed};
/// use tokenator_keys::{Key, Visibility, to_cwk};
///
/// // The RFC 9964 Appendix A ML-DSA-44 key (all-zero seed).
/// let key = Key::from_private(generate_from_seed(KeySpec::MlDsa(MlDsaParams::MlDsa44), &[0; 32])?);
/// let cwk = to_cwk(&key, Visibility::Public)?;
/// // kty 7 (AKP) and alg -48 (ML-DSA-44), although the key declares no alg.
/// assert_eq!(&cwk.to_cbor()[..5], [0xa3, 0x01, 0x07, 0x03, 0x38]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// [`to_jwk`]: crate::to_jwk
pub fn to_cwk(key: &Key, visibility: Visibility) -> Result<CoseKey, KeyError> {
    let secret = private_for_export(key, visibility)?;
    let public = key.public_key().to_material();
    let mut entries: Vec<(Item<'static>, Item<'static>)> = Vec::new();
    let mut push = |label: i64, value: Item<'static>| entries.push((Item::int(label), value));

    push(KTY, Item::int(key.key_type().cose_kty()));
    if let Some(kid) = &key.kid {
        push(KID, Item::bytes(kid.as_bytes().to_vec()));
    }
    match alg_for_export(key, &public) {
        Some(DeclaredAlg::Known(alg)) => push(ALG, Item::int(alg_to_cose(alg))),
        Some(DeclaredAlg::UnknownCose(label)) => push(ALG, Item::int(label)),
        Some(DeclaredAlg::UnknownJose(name)) => push(ALG, Item::text(name)),
        None => {}
    }
    if let Some(ops) = &key.key_ops {
        let ops = ops
            .iter()
            .map(|op| match (op.cose_value(), op) {
                (Some(v), _) => Item::int(v),
                (None, KeyOp::Other(Label::Int(n))) => Item::int(*n),
                (None, KeyOp::Other(Label::Text(t))) => Item::text(t.clone()),
                // Every named op has a COSE value.
                (None, _) => Item::new(Value::Null),
            })
            .collect();
        push(KEY_OPS, Item::array(ops));
    }

    let bytes = |b: &[u8]| Item::bytes(b.to_vec());
    match &public {
        PublicKeyMaterial::Ec { curve, x, y } => {
            push(-1, Item::int(curve.cose_label()));
            push(-2, bytes(x));
            push(-3, bytes(y));
        }
        PublicKeyMaterial::Ed25519 { x } => {
            push(-1, Item::int(Curve::Ed25519.cose_label()));
            push(-2, bytes(x));
        }
        PublicKeyMaterial::Rsa { n, e } => {
            push(-1, bytes(n));
            push(-2, bytes(e));
        }
        PublicKeyMaterial::MlDsa { public, .. } => push(-1, bytes(public)),
    }
    match secret.as_ref().map(|s| &s.0) {
        Some(PrivateKeyMaterial::Ec { d, .. } | PrivateKeyMaterial::Ed25519 { d }) => {
            push(-4, bytes(d));
        }
        Some(PrivateKeyMaterial::Rsa(m)) => {
            push(-3, bytes(&m.d));
            for (label, value) in [
                (-4, &m.p),
                (-5, &m.q),
                (-6, &m.dp),
                (-7, &m.dq),
                (-8, &m.qi),
            ] {
                if let Some(value) = value {
                    push(label, bytes(value));
                }
            }
        }
        Some(PrivateKeyMaterial::MlDsa {
            seed: Some(seed), ..
        }) => push(-2, bytes(seed)),
        Some(PrivateKeyMaterial::MlDsa { seed: None, .. }) | None => {}
    }

    for extra in &key.extras {
        if let Extra::Cose { label, cbor } = extra {
            let value = tokenator_cbor::decode(cbor)
                .map_err(|_| KeyError::InvalidParameter {
                    name: label_name(label),
                    reason: "extra value is not valid CBOR",
                })?
                .into_owned();
            let label = match label {
                Label::Int(n) => Item::int(*n),
                Label::Text(t) => Item::text(t.clone()),
            };
            entries.push((label, value));
        }
    }
    CoseKey::from_owned(Item::map(entries))
}

/// Parses a COSE_Key into a key, validating the material with
/// `tokenator-crypto`. The rules match [`from_jwk`](crate::from_jwk):
/// public and private parts must agree, duplicate labels are rejected,
/// unrecognized entries become COSE extras, and short EC values are
/// left-padded.
///
/// ```
/// use tokenator_keys::{CoseKey, KeyError, from_cwk};
///
/// // {1: 2, -1: 1, -2: x, -3: true}: a compressed EC2 point, which
/// // tokenator-crypto cannot decompress yet (#18).
/// let mut cbor = vec![0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20];
/// cbor.extend([0x11; 32]);
/// cbor.extend([0x22, 0xf5]);
/// let err = from_cwk(&CoseKey::decode(&cbor)?).unwrap_err();
/// assert!(matches!(err, KeyError::InvalidParameter { name, .. } if name == "-3"));
/// # Ok::<(), KeyError>(())
/// ```
pub fn from_cwk(cwk: &CoseKey) -> Result<Key, KeyError> {
    let mut labels = Vec::new();
    for (k, _) in cwk.entries() {
        let label = label_of(k).ok_or_else(|| KeyError::InvalidParameter {
            name: "label".into(),
            reason: "map label is not an integer or text",
        })?;
        if labels.contains(&label) {
            return Err(KeyError::InvalidParameter {
                name: label_name(&label),
                reason: "duplicated",
            });
        }
        labels.push(label);
    }
    let kty = cwk.kty()?;

    let kid = match cwk.get(KID).map(|i| &i.value) {
        None => None,
        Some(Value::Bytes(b)) => Some(Kid::Bytes(b.to_vec())),
        Some(Value::Text(t)) => Some(Kid::Text(t.to_string())),
        Some(_) => return Err(invalid(KID, "not a byte string")),
    };
    let alg = match cwk.get(ALG).map(|i| &i.value) {
        None => None,
        Some(Value::Text(t)) => Some(DeclaredAlg::UnknownJose(t.to_string())),
        Some(v) => Some(declared_alg_from_cose(
            int_value(v).ok_or_else(|| invalid(ALG, "not an integer or text"))?,
        )),
    };
    let key_ops = match cwk.get(KEY_OPS).map(|i| &i.value) {
        None => None,
        Some(Value::Array(ops)) => Some(
            ops.iter()
                .map(|op| match &op.value {
                    Value::Text(t) => Ok(KeyOp::Other(Label::Text(t.to_string()))),
                    v => int_value(v)
                        .map(KeyOp::from_cose_value)
                        .ok_or_else(|| invalid(KEY_OPS, "not an array of integers")),
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Some(_) => return Err(invalid(KEY_OPS, "not an array")),
    };

    let components = match kty {
        KeyType::Ec | KeyType::Okp => {
            let crv = cwk.crv()?;
            let curve = Curve::from_cose_label(crv)
                .ok_or_else(|| KeyError::UnsupportedCurve(crv.to_string()))?;
            if curve.key_type() != kty {
                return Err(KeyError::InconsistentKey("crv does not belong to kty"));
            }
            let len = curve.field_len();
            let x = cwk.bytes_req(-2)?;
            if kty == KeyType::Ec {
                let y = match cwk.get(-3).map(|i| &i.value) {
                    None => return Err(missing(-3)),
                    Some(Value::Bytes(y)) => y.to_vec(),
                    Some(Value::Bool(_)) => {
                        return Err(invalid(-3, "compressed points are not supported (#18)"));
                    }
                    Some(_) => return Err(invalid(-3, "not a byte string")),
                };
                let d = cwk
                    .secret_opt(-4)?
                    .map(|d| left_pad("-4", d.to_vec(), len).map(Zeroizing::new))
                    .transpose()?;
                Components::Curve {
                    curve,
                    x: left_pad("-2", x, len)?,
                    y: Some(left_pad("-3", y, len)?),
                    d,
                }
            } else {
                exact_len("-2", &x, len)?;
                let d = cwk.secret_opt(-4)?;
                if let Some(d) = &d {
                    exact_len("-4", d, len)?;
                }
                Components::Curve {
                    curve,
                    x,
                    y: None,
                    d,
                }
            }
        }
        KeyType::Rsa => {
            let n = cwk.bytes_req(-1)?;
            let e = cwk.bytes_req(-2)?;
            let private = match cwk.secret_opt(-3)? {
                None => None,
                Some(d) => {
                    let [p, q, dp, dq, qi] = [-4, -5, -6, -7, -8].map(|l| cwk.secret_opt(l));
                    let crt = [p?, q?, dp?, dq?, qi?];
                    let crt = if crt.iter().all(Option::is_none) {
                        None
                    } else {
                        let [p, q, dp, dq, qi] = crt;
                        Some([
                            p.ok_or_else(|| missing(-4))?,
                            q.ok_or_else(|| missing(-5))?,
                            dp.ok_or_else(|| missing(-6))?,
                            dq.ok_or_else(|| missing(-7))?,
                            qi.ok_or_else(|| missing(-8))?,
                        ])
                    };
                    Some(RsaPrivate { d, crt })
                }
            };
            Components::Rsa { n, e, private }
        }
        KeyType::Akp => {
            let params = match &alg {
                None => return Err(missing(ALG)),
                Some(DeclaredAlg::Known(a)) => ml_dsa_for_alg(*a),
                Some(_) => None,
            }
            .ok_or_else(|| invalid(ALG, "not an ML-DSA algorithm"))?;
            let public = cwk.bytes_req(-1)?;
            if public.len() != params.public_key_len() {
                return Err(KeyError::InconsistentKey(
                    "pub has the wrong length for alg",
                ));
            }
            let seed = cwk.secret_opt(-2)?;
            if let Some(seed) = &seed {
                exact_len("-2", seed, MlDsaParams::SEED_LEN)?;
            }
            Components::Akp {
                params,
                public,
                seed,
            }
        }
    };

    let mut key = Key::with_material(components.into_material()?);
    key.kid = kid;
    key.alg = alg;
    key.key_ops = key_ops;
    let known = key_labels(kty);
    key.extras = cwk
        .entries()
        .iter()
        .filter_map(|(k, v)| {
            let label = label_of(k)?;
            let recognized = matches!(label, Label::Int(n) if (KTY..=KEY_OPS).contains(&n) || known.contains(&n));
            (!recognized).then(|| {
                let cbor = tokenator_cbor::encode(v, EncodeMode::Preserve)
                    .map_err(|_| KeyError::UnrecognizedFormat)?;
                Ok(Extra::Cose { label, cbor })
            })
        })
        .collect::<Result<_, KeyError>>()?;
    Ok(key)
}

/// Describes a COSE_Key without validating its material; the COSE
/// counterpart of [`params_from_jwk`](crate::params_from_jwk). RSA size is
/// the bit length of `n` (-1).
///
/// ```
/// use tokenator_crypto::{Alg, MlDsaParams};
/// use tokenator_keys::{CoseKey, DeclaredAlg, params_from_cwk};
///
/// // {1: 7, 3: -49}: an AKP key with only an alg.
/// let p = params_from_cwk(&CoseKey::decode(&[0xa2, 0x01, 0x07, 0x03, 0x38, 0x30])?)?;
/// assert_eq!(p.ml_dsa, Some(MlDsaParams::MlDsa65));
/// assert_eq!(p.declared_alg, Some(DeclaredAlg::Known(Alg::MlDsa65)));
/// # Ok::<(), tokenator_keys::KeyError>(())
/// ```
pub fn params_from_cwk(cwk: &CoseKey) -> Result<KeyParams, KeyError> {
    let kty = cwk.kty()?;
    let declared_alg = match cwk.get(ALG).map(|i| &i.value) {
        Some(Value::Text(t)) => Some(DeclaredAlg::UnknownJose(t.to_string())),
        Some(v) => int_value(v).map(declared_alg_from_cose),
        None => None,
    };
    let bytes = |label: i64| match cwk.get(label).map(|i| &i.value) {
        Some(Value::Bytes(b)) => Some(b.to_vec()),
        _ => None,
    };
    let crv = match kty {
        KeyType::Ec | KeyType::Okp => cwk
            .get(-1)
            .and_then(int_of)
            .and_then(Curve::from_cose_label),
        KeyType::Rsa | KeyType::Akp => None,
    };
    let rsa_bits = match kty {
        KeyType::Rsa => bytes(-1).as_deref().and_then(bit_len),
        _ => None,
    };
    let ml_dsa = match kty {
        KeyType::Akp => match &declared_alg {
            Some(DeclaredAlg::Known(alg)) if ml_dsa_for_alg(*alg).is_some() => ml_dsa_for_alg(*alg),
            Some(DeclaredAlg::Known(_)) => None,
            _ => bytes(-1).and_then(|p| ml_dsa_for_public_len(p.len())),
        },
        _ => None,
    };
    Ok(KeyParams {
        kty,
        crv,
        rsa_bits,
        ml_dsa,
        declared_alg,
    })
}

/// The RFC 9679 COSE Key thumbprint: the deterministic encoding (RFC 8949
/// §4.2.1) of a map holding only the required parameters, hashed.
///
/// Required parameters: OKP 1, -1, -2; EC2 1, -1, -2, -3; RSA 1, -1, -2;
/// AKP 1, 3, -1 (RFC 9964 §6). Values are copied as they appear.
///
/// ```
/// use tokenator_keys::{CoseKey, HashAlg, KeyError, cose_thumbprint};
///
/// // {1: 7, -1: h'01'}: AKP needs alg (3) for its thumbprint.
/// let cwk = CoseKey::decode(&[0xa2, 0x01, 0x07, 0x20, 0x41, 0x01])?;
/// assert_eq!(
///     cose_thumbprint(&cwk, HashAlg::Sha256),
///     Err(KeyError::MissingParameter("3".into()))
/// );
/// # Ok::<(), KeyError>(())
/// ```
pub fn cose_thumbprint(cwk: &CoseKey, hash: HashAlg) -> Result<Vec<u8>, KeyError> {
    let kty = cwk.kty()?;
    let entries = thumbprint_labels(kty)
        .iter()
        .map(|label| {
            let value = cwk.get(*label).ok_or_else(|| missing(*label))?;
            Ok((Item::int(*label), value.clone()))
        })
        .collect::<Result<Vec<_>, KeyError>>()?;
    hash_map(entries, hash)
}

/// RFC 9679 §4 / RFC 9964 §6 required labels.
fn thumbprint_labels(kty: KeyType) -> &'static [i64] {
    match kty {
        KeyType::Okp => &[KTY, -1, -2],
        KeyType::Ec => &[KTY, -1, -2, -3],
        KeyType::Rsa => &[KTY, -1, -2],
        KeyType::Akp => &[KTY, ALG, -1],
    }
}

fn hash_map(
    entries: Vec<(Item<'static>, Item<'static>)>,
    hash: HashAlg,
) -> Result<Vec<u8>, KeyError> {
    let cbor = tokenator_cbor::encode(&Item::map(entries), EncodeMode::Deterministic)
        .map_err(|_| KeyError::UnrecognizedFormat)?;
    Ok(digest(hash, &cbor))
}

/// The RFC 9679 thumbprint of `key`'s public part.
pub(crate) fn key_thumbprint(key: &Key, hash: HashAlg) -> Vec<u8> {
    let kty = Item::int(key.key_type().cose_kty());
    let entries = match key.public_key().to_material() {
        PublicKeyMaterial::Ec { curve, x, y } => vec![
            (Item::int(KTY), kty),
            (Item::int(-1), Item::int(curve.cose_label())),
            (Item::int(-2), Item::bytes(x)),
            (Item::int(-3), Item::bytes(y)),
        ],
        PublicKeyMaterial::Ed25519 { x } => vec![
            (Item::int(KTY), kty),
            (Item::int(-1), Item::int(Curve::Ed25519.cose_label())),
            (Item::int(-2), Item::bytes(x)),
        ],
        PublicKeyMaterial::Rsa { n, e } => vec![
            (Item::int(KTY), kty),
            (Item::int(-1), Item::bytes(n)),
            (Item::int(-2), Item::bytes(e)),
        ],
        PublicKeyMaterial::MlDsa { params, public } => vec![
            (Item::int(KTY), kty),
            (Item::int(ALG), Item::int(alg_to_cose(params.alg()))),
            (Item::int(-1), Item::bytes(public)),
        ],
    };
    // Integers and byte strings always encode.
    hash_map(entries, hash).unwrap_or_default()
}
