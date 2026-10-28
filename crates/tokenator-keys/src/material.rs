//! Format-neutral key components shared by the JWK and COSE_Key parsers and
//! builders, and their validation through `tokenator-crypto`.

use base64ct::{Base64UrlUnpadded, Encoding};
use tokenator_crypto::{
    Curve, MlDsaParams, PrivateKey, PrivateKeyMaterial, PublicKey, PublicKeyMaterial,
    RsaPrivateMaterial,
};
use zeroize::Zeroizing;

use crate::KeyError;
use crate::key::{Material, wipe};

/// Decoded key parameters, before validation. Secrets are wiped on drop.
pub(crate) enum Components {
    /// EC or OKP: `x` (and `y` for EC) plus an optional private scalar.
    Curve {
        curve: Curve,
        x: Vec<u8>,
        y: Option<Vec<u8>>,
        d: Option<Zeroizing<Vec<u8>>>,
    },
    /// RSA public key, or private key when `d` is present.
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
        private: Option<RsaPrivate>,
    },
    /// AKP (ML-DSA) public key plus an optional seed.
    Akp {
        params: MlDsaParams,
        public: Vec<u8>,
        seed: Option<Zeroizing<Vec<u8>>>,
    },
}

/// RSA private exponent plus the optional CRT values (all or none).
pub(crate) struct RsaPrivate {
    pub(crate) d: Zeroizing<Vec<u8>>,
    pub(crate) crt: Option<[Zeroizing<Vec<u8>>; 5]>,
}

impl Components {
    /// Validates the components with `tokenator-crypto`. A private part must
    /// produce exactly the public part that was given.
    pub(crate) fn into_material(self) -> Result<Material, KeyError> {
        let (public, private) = match self {
            Components::Curve { curve, x, y, d } => {
                let public = match y {
                    Some(y) => PublicKeyMaterial::Ec { curve, x, y },
                    None => PublicKeyMaterial::Ed25519 { x },
                };
                let private = d.map(|d| match curve {
                    Curve::Ed25519 => PrivateKeyMaterial::Ed25519 { d: d.to_vec() },
                    _ => PrivateKeyMaterial::Ec {
                        curve,
                        d: d.to_vec(),
                    },
                });
                (public, private)
            }
            Components::Rsa { n, e, private } => {
                let private = private.map(|RsaPrivate { d, crt }| {
                    let [p, q, dp, dq, qi] = match crt {
                        Some(values) => values.map(|v| Some(v.to_vec())),
                        None => [None, None, None, None, None],
                    };
                    PrivateKeyMaterial::Rsa(RsaPrivateMaterial {
                        n: n.clone(),
                        e: e.clone(),
                        d: d.to_vec(),
                        p,
                        q,
                        dp,
                        dq,
                        qi,
                    })
                });
                (PublicKeyMaterial::Rsa { n, e }, private)
            }
            Components::Akp {
                params,
                public,
                seed,
            } => {
                let private = seed.map(|seed| PrivateKeyMaterial::MlDsa {
                    params,
                    seed: Some(seed.to_vec()),
                    expanded: None,
                });
                (PublicKeyMaterial::MlDsa { params, public }, private)
            }
        };
        let public = PublicKey::from_material(&public)?;
        match private {
            None => Ok(Material::Public(public)),
            Some(mut material) => {
                let private = PrivateKey::from_material(&material);
                wipe(&mut material);
                let private = private?;
                if private.public_key() != public {
                    return Err(KeyError::InconsistentKey(
                        "the private key does not match the public key",
                    ));
                }
                Ok(Material::Private(private))
            }
        }
    }
}

/// Decodes unpadded base64url.
pub(crate) fn b64u_decode(name: &str, text: &str) -> Result<Vec<u8>, KeyError> {
    Base64UrlUnpadded::decode_vec(text).map_err(|_| KeyError::InvalidParameter {
        name: name.to_owned(),
        reason: "not unpadded base64url",
    })
}

/// Encodes unpadded base64url.
pub(crate) fn b64u_encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Left-pads a big-endian EC value that lost leading zero bytes (#11).
pub(crate) fn left_pad(name: &str, value: Vec<u8>, len: usize) -> Result<Vec<u8>, KeyError> {
    match value.len().cmp(&len) {
        core::cmp::Ordering::Equal => Ok(value),
        core::cmp::Ordering::Greater => Err(KeyError::InvalidParameter {
            name: name.to_owned(),
            reason: "longer than the curve's field length",
        }),
        core::cmp::Ordering::Less => {
            let mut padded = vec![0; len - value.len()];
            padded.extend_from_slice(&value);
            drop(Zeroizing::new(value));
            Ok(padded)
        }
    }
}

/// Requires an exact length (Ed25519 and AKP values).
pub(crate) fn exact_len(name: &str, value: &[u8], len: usize) -> Result<(), KeyError> {
    if value.len() == len {
        Ok(())
    } else {
        Err(KeyError::InvalidParameter {
            name: name.to_owned(),
            reason: "wrong length",
        })
    }
}

/// The ML-DSA parameter set whose public key has `len` bytes.
pub(crate) fn ml_dsa_for_public_len(len: usize) -> Option<MlDsaParams> {
    [
        MlDsaParams::MlDsa44,
        MlDsaParams::MlDsa65,
        MlDsaParams::MlDsa87,
    ]
    .into_iter()
    .find(|p| p.public_key_len() == len)
}

/// The ML-DSA parameter set of an algorithm.
pub(crate) fn ml_dsa_for_alg(alg: tokenator_crypto::Alg) -> Option<MlDsaParams> {
    use tokenator_crypto::Alg;
    match alg {
        Alg::MlDsa44 => Some(MlDsaParams::MlDsa44),
        Alg::MlDsa65 => Some(MlDsaParams::MlDsa65),
        Alg::MlDsa87 => Some(MlDsaParams::MlDsa87),
        _ => None,
    }
}

/// Bit length of a big-endian unsigned integer (leading zeros ignored).
pub(crate) fn bit_len(n: &[u8]) -> Option<u32> {
    let start = n.iter().position(|b| *b != 0)?;
    let rest = n.get(start..)?;
    let top = rest.first()?;
    let bytes = u32::try_from(rest.len()).ok()?;
    bytes
        .checked_sub(1)?
        .checked_mul(8)?
        .checked_add(8 - top.leading_zeros())
}

/// Raw private material for an export; wiped on drop.
pub(crate) struct Secret(pub(crate) PrivateKeyMaterial);

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// The private material to write for `visibility`, or `None` for a public
/// export. An expanded-only ML-DSA key has no JWK/COSE_Key private form.
pub(crate) fn private_for_export(
    key: &crate::Key,
    visibility: crate::Visibility,
) -> Result<Option<Secret>, KeyError> {
    if visibility == crate::Visibility::Public {
        return Ok(None);
    }
    let secret = Secret(
        key.private_key()
            .ok_or(KeyError::NoPrivateKey)?
            .to_material(),
    );
    if let PrivateKeyMaterial::MlDsa { seed: None, .. } = secret.0 {
        return Err(KeyError::MlDsaSeedUnknown);
    }
    Ok(Some(secret))
}

/// The `alg` to write: the declared one, or for AKP keys (which must have
/// one, RFC 9964 §3) the algorithm of the parameter set.
pub(crate) fn alg_for_export(
    key: &crate::Key,
    public: &PublicKeyMaterial,
) -> Option<tokenator_crypto::DeclaredAlg> {
    match (&key.alg, public) {
        (Some(alg), _) => Some(alg.clone()),
        (None, PublicKeyMaterial::MlDsa { params, .. }) => {
            Some(tokenator_crypto::DeclaredAlg::Known(params.alg()))
        }
        (None, _) => None,
    }
}
