//! Format-neutral key material, parsed keys, and key generation.

use core::fmt;

use ecdsa::elliptic_curve::Generate;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, SeedableRng};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BoxedUint, RsaPrivateKey, RsaPublicKey};

use crate::{Alg, CryptoError, Curve, KeyParams, MlDsaParams};

/// Raw public key components.
///
/// Fixed-width fields (`x`, `y` for EC; `x` for Ed25519; ML-DSA `public`)
/// must have exactly the length the curve or parameter set requires. RSA
/// integers are unsigned big-endian; leading zero bytes are accepted on input
/// and never produced on output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKeyMaterial {
    /// EC point as affine coordinates, each [`Curve::field_len`] bytes.
    Ec {
        /// P-256, P-384, or P-521.
        curve: Curve,
        /// x coordinate.
        x: Vec<u8>,
        /// y coordinate.
        y: Vec<u8>,
    },
    /// Ed25519 public key (32 bytes).
    Ed25519 {
        /// Encoded point.
        x: Vec<u8>,
    },
    /// RSA public key.
    Rsa {
        /// Modulus.
        n: Vec<u8>,
        /// Public exponent.
        e: Vec<u8>,
    },
    /// ML-DSA encoded public key (FIPS 204 `pkEncode`).
    MlDsa {
        /// Parameter set.
        params: MlDsaParams,
        /// Encoded public key.
        public: Vec<u8>,
    },
}

/// Raw RSA private key components. `p`, `q`, `dp`, `dq`, `qi` are optional on
/// input (RFC 7518 §6.3.2 allows `n`, `e`, `d` alone) and always present on
/// output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPrivateMaterial {
    /// Modulus.
    pub n: Vec<u8>,
    /// Public exponent.
    pub e: Vec<u8>,
    /// Private exponent.
    pub d: Vec<u8>,
    /// First prime factor.
    pub p: Option<Vec<u8>>,
    /// Second prime factor.
    pub q: Option<Vec<u8>>,
    /// `d mod (p-1)`.
    pub dp: Option<Vec<u8>>,
    /// `d mod (q-1)`.
    pub dq: Option<Vec<u8>>,
    /// `q^-1 mod p`.
    pub qi: Option<Vec<u8>>,
}

/// Raw private key components (the secret only; derive the public half with
/// [`PrivateKey::public_key`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateKeyMaterial {
    /// EC private scalar, [`Curve::field_len`] bytes, big-endian.
    Ec {
        /// P-256, P-384, or P-521.
        curve: Curve,
        /// Private scalar.
        d: Vec<u8>,
    },
    /// Ed25519 secret key (the 32-byte RFC 8032 seed).
    Ed25519 {
        /// Secret key.
        d: Vec<u8>,
    },
    /// RSA private key.
    Rsa(RsaPrivateMaterial),
    /// ML-DSA private key: the 32-byte seed, the FIPS 204 expanded encoding
    /// (`skEncode`), or both (which must agree). At least one is required.
    /// On output the seed is present when known and `expanded` always is.
    MlDsa {
        /// Parameter set.
        params: MlDsaParams,
        /// Seed `xi`.
        seed: Option<Vec<u8>>,
        /// Expanded private key.
        expanded: Option<Vec<u8>>,
    },
}

/// A validated private key, ready to sign. `Debug` never prints secrets.
#[derive(Clone)]
pub struct PrivateKey {
    pub(crate) inner: PrivateInner,
}

/// A validated public key, ready to verify.
#[derive(Clone, PartialEq)]
pub struct PublicKey {
    pub(crate) inner: PublicInner,
}

// Every backend key type compares by value; ML-DSA's `VerifyingKey` only
// lacks the `Eq` marker.
impl Eq for PublicKey {}

#[derive(Clone)]
pub(crate) enum PrivateInner {
    Ec(EcSigningKey),
    Ed25519(Box<ed25519_dalek::SigningKey>),
    Rsa(Box<RsaPrivateKey>),
    MlDsa(MlDsaPrivate),
}

#[derive(Clone, PartialEq)]
pub(crate) enum PublicInner {
    Ec(EcVerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
    Rsa(Box<RsaPublicKey>),
    MlDsa(MlDsaPublic),
}

#[derive(Clone)]
pub(crate) enum EcSigningKey {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    P521(Box<p521::ecdsa::SigningKey>),
}

#[derive(Clone, PartialEq)]
pub(crate) enum EcVerifyingKey {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    P521(Box<p521::ecdsa::VerifyingKey>),
}

/// Runs `$body` with `$k` bound to the curve-specific key inside an
/// [`EcSigningKey`] or [`EcVerifyingKey`]; the body is written once and
/// monomorphized per curve.
macro_rules! with_ec {
    ($key:expr, $enum:ident, $k:ident => $body:expr) => {
        match $key {
            $enum::P256($k) => $body,
            $enum::P384($k) => $body,
            $enum::P521($k) => $body,
        }
    };
}
pub(crate) use with_ec;

/// Same as [`with_ec`] for the three ML-DSA parameter sets.
macro_rules! with_ml_dsa {
    ($key:expr, $enum:ident, $k:ident => $body:expr) => {
        match $key {
            $enum::MlDsa44($k) => $body,
            $enum::MlDsa65($k) => $body,
            $enum::MlDsa87($k) => $body,
        }
    };
}
pub(crate) use with_ml_dsa;

#[derive(Clone)]
pub(crate) enum MlDsaPrivate {
    MlDsa44(Box<MlDsaKey<ml_dsa::MlDsa44>>),
    MlDsa65(Box<MlDsaKey<ml_dsa::MlDsa65>>),
    MlDsa87(Box<MlDsaKey<ml_dsa::MlDsa87>>),
}

#[derive(Clone, PartialEq)]
pub(crate) enum MlDsaPublic {
    MlDsa44(Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa44>>),
    MlDsa65(Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa65>>),
    MlDsa87(Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa87>>),
}

/// An ML-DSA private key with its (cached) public key.
#[derive(Clone)]
pub(crate) struct MlDsaKey<P: ml_dsa::MlDsaParams> {
    secret: MlDsaSecret<P>,
    public: ml_dsa::VerifyingKey<P>,
}

/// The seed is kept when known: it is the preferred serialization (RFC 9964 §3).
#[derive(Clone)]
enum MlDsaSecret<P: ml_dsa::MlDsaParams> {
    Seed(ml_dsa::SigningKey<P>),
    Expanded(Box<ml_dsa::ExpandedSigningKey<P>>),
}

impl<P: ml_dsa::MlDsaParams> MlDsaKey<P> {
    fn from_seed(seed: &[u8; 32]) -> Self {
        let sk = ml_dsa::SigningKey::<P>::from_seed(&ml_dsa::Seed::from(*seed));
        let public = sk.expanded_key().verifying_key();
        Self {
            secret: MlDsaSecret::Seed(sk),
            public,
        }
    }

    fn from_parts(
        params: MlDsaParams,
        seed: Option<&[u8]>,
        expanded: Option<&[u8]>,
    ) -> Result<Self, CryptoError> {
        let expanded = match expanded {
            Some(bytes) => {
                if bytes.len() != params.expanded_private_key_len() {
                    return Err(CryptoError::InvalidKey(
                        "ML-DSA expanded key has the wrong length",
                    ));
                }
                Some(bytes)
            }
            None => None,
        };
        match (seed, expanded) {
            (Some(seed), expanded) => {
                let seed: &[u8; 32] = seed
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKey("ML-DSA seed must be 32 bytes"))?;
                let key = Self::from_seed(seed);
                if let Some(expanded) = expanded
                    && key.expanded_bytes() != expanded
                {
                    return Err(CryptoError::InvalidKey(
                        "ML-DSA seed and expanded key do not match",
                    ));
                }
                Ok(key)
            }
            (None, Some(expanded)) => Self::from_expanded(params, expanded),
            (None, None) => Err(CryptoError::InvalidKey(
                "ML-DSA private key needs a seed or an expanded key",
            )),
        }
    }

    // Kept out of `from_parts`: the unoptimized expanded key is ~100 KiB, and
    // debug builds give every local of every branch its own stack slot.
    #[inline(never)]
    fn from_expanded(params: MlDsaParams, expanded: &[u8]) -> Result<Self, CryptoError> {
        // `from_expanded` asserts on out-of-range s1/s2 coefficients, so
        // check them first.
        if !ml_dsa_secret_vectors_in_range(params, expanded) {
            return Err(CryptoError::InvalidKey("malformed ML-DSA expanded key"));
        }
        let bytes = ml_dsa::ExpandedSigningKeyBytes::<P>::try_from(expanded)
            .map_err(|_| CryptoError::InvalidKey("ML-DSA expanded key has the wrong length"))?;
        #[allow(deprecated)] // the expanded form is still a valid input (RFC 9964 §3)
        let sk = Box::new(ml_dsa::ExpandedSigningKey::<P>::from_expanded(&bytes));
        let public = sk.verifying_key();
        Ok(Self {
            secret: MlDsaSecret::Expanded(sk),
            public,
        })
    }

    pub(crate) fn expanded(&self) -> &ml_dsa::ExpandedSigningKey<P> {
        match &self.secret {
            MlDsaSecret::Seed(sk) => sk.expanded_key(),
            MlDsaSecret::Expanded(sk) => sk,
        }
    }

    fn seed_bytes(&self) -> Option<Vec<u8>> {
        match &self.secret {
            MlDsaSecret::Seed(sk) => Some(sk.as_seed().to_vec()),
            MlDsaSecret::Expanded(_) => None,
        }
    }

    fn expanded_bytes(&self) -> Vec<u8> {
        #[allow(deprecated)] // FIPS 204 skEncode; part of the material we expose
        let bytes = self.expanded().to_expanded();
        bytes.to_vec()
    }
}

/// Checks that every s1/s2 coefficient of a FIPS 204 `skEncode` output lies
/// in `[0, 2*eta]` (Algorithm 17 BitUnpack's precondition).
fn ml_dsa_secret_vectors_in_range(params: MlDsaParams, sk: &[u8]) -> bool {
    // (2 * eta, bits per coefficient, l + k)
    let (max, bits, vectors) = match params {
        MlDsaParams::MlDsa44 => (4u32, 3usize, 4 + 4),
        MlDsaParams::MlDsa65 => (8, 4, 5 + 6),
        MlDsaParams::MlDsa87 => (4, 3, 7 + 8),
    };
    // rho (32) || K (32) || tr (64) || s1 || s2 || t0; 256 coefficients per polynomial.
    let Some(s) = sk.get(128..128 + vectors * 32 * bits) else {
        return false;
    };
    if bits == 4 {
        s.iter()
            .all(|b| u32::from(b & 0x0f) <= max && u32::from(b >> 4) <= max)
    } else {
        // Eight 3-bit coefficients per 3 bytes, least significant bits first.
        s.as_chunks::<3>().0.iter().all(|&[b0, b1, b2]| {
            let w = u32::from(b0) | (u32::from(b1) << 8) | (u32::from(b2) << 16);
            (0..8).all(|i| (w >> (3 * i)) & 0x7 <= max)
        })
    }
}

impl PrivateKey {
    /// Validates and parses raw material.
    ///
    /// EC scalars must be in `[1, n)`, RSA components must be consistent
    /// (missing primes are recovered from `n`, `e`, `d`; given CRT values
    /// are checked), and an ML-DSA seed and expanded key must agree.
    pub fn from_material(material: &PrivateKeyMaterial) -> Result<Self, CryptoError> {
        let inner = match material {
            PrivateKeyMaterial::Ec { curve, d } => {
                if d.len() != curve.field_len() {
                    return Err(CryptoError::InvalidKey(
                        "EC private scalar has the wrong length",
                    ));
                }
                let bad = |_| CryptoError::InvalidKey("EC private scalar is out of range");
                PrivateInner::Ec(match curve {
                    Curve::P256 => {
                        EcSigningKey::P256(p256::ecdsa::SigningKey::from_slice(d).map_err(bad)?)
                    }
                    Curve::P384 => {
                        EcSigningKey::P384(p384::ecdsa::SigningKey::from_slice(d).map_err(bad)?)
                    }
                    Curve::P521 => EcSigningKey::P521(Box::new(
                        p521::ecdsa::SigningKey::from_slice(d).map_err(bad)?,
                    )),
                    Curve::Ed25519 => {
                        return Err(CryptoError::InvalidKey("Ed25519 is not an EC curve"));
                    }
                })
            }
            PrivateKeyMaterial::Ed25519 { d } => {
                let d: &[u8; 32] = d
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKey("Ed25519 secret key must be 32 bytes"))?;
                PrivateInner::Ed25519(Box::new(ed25519_dalek::SigningKey::from_bytes(d)))
            }
            PrivateKeyMaterial::Rsa(m) => PrivateInner::Rsa(Box::new(rsa_private_key(m)?)),
            PrivateKeyMaterial::MlDsa {
                params,
                seed,
                expanded,
            } => {
                let (seed, expanded) = (seed.as_deref(), expanded.as_deref());
                PrivateInner::MlDsa(match params {
                    MlDsaParams::MlDsa44 => MlDsaPrivate::MlDsa44(Box::new(MlDsaKey::from_parts(
                        *params, seed, expanded,
                    )?)),
                    MlDsaParams::MlDsa65 => MlDsaPrivate::MlDsa65(Box::new(MlDsaKey::from_parts(
                        *params, seed, expanded,
                    )?)),
                    MlDsaParams::MlDsa87 => MlDsaPrivate::MlDsa87(Box::new(MlDsaKey::from_parts(
                        *params, seed, expanded,
                    )?)),
                })
            }
        };
        Ok(Self { inner })
    }

    /// The raw components (see [`PrivateKeyMaterial`] for what is filled in).
    pub fn to_material(&self) -> PrivateKeyMaterial {
        match &self.inner {
            PrivateInner::Ec(k) => PrivateKeyMaterial::Ec {
                curve: ec_signing_curve(k),
                d: with_ec!(k, EcSigningKey, k => k.to_bytes().to_vec()),
            },
            PrivateInner::Ed25519(k) => PrivateKeyMaterial::Ed25519 {
                d: k.to_bytes().to_vec(),
            },
            PrivateInner::Rsa(k) => {
                let primes = k.primes();
                PrivateKeyMaterial::Rsa(RsaPrivateMaterial {
                    n: uint_to_bytes(k.n().as_ref()),
                    e: uint_to_bytes(k.e()),
                    d: uint_to_bytes(k.d()),
                    p: primes.first().map(uint_to_bytes),
                    q: primes.get(1).map(uint_to_bytes),
                    dp: k.dp().map(uint_to_bytes),
                    dq: k.dq().map(uint_to_bytes),
                    qi: k.crt_coefficient().as_ref().map(uint_to_bytes),
                })
            }
            PrivateInner::MlDsa(k) => PrivateKeyMaterial::MlDsa {
                params: ml_dsa_private_params(k),
                seed: with_ml_dsa!(k, MlDsaPrivate, k => k.seed_bytes()),
                expanded: Some(with_ml_dsa!(k, MlDsaPrivate, k => k.expanded_bytes())),
            },
        }
    }

    /// The matching public key.
    pub fn public_key(&self) -> PublicKey {
        let inner = match &self.inner {
            PrivateInner::Ec(k) => PublicInner::Ec(match k {
                EcSigningKey::P256(k) => EcVerifyingKey::P256(*k.verifying_key()),
                EcSigningKey::P384(k) => EcVerifyingKey::P384(*k.verifying_key()),
                EcSigningKey::P521(k) => EcVerifyingKey::P521(Box::new(*k.verifying_key())),
            }),
            PrivateInner::Ed25519(k) => PublicInner::Ed25519(k.verifying_key()),
            PrivateInner::Rsa(k) => PublicInner::Rsa(Box::new(k.to_public_key())),
            PrivateInner::MlDsa(k) => PublicInner::MlDsa(match k {
                MlDsaPrivate::MlDsa44(k) => MlDsaPublic::MlDsa44(Box::new(k.public.clone())),
                MlDsaPrivate::MlDsa65(k) => MlDsaPublic::MlDsa65(Box::new(k.public.clone())),
                MlDsaPrivate::MlDsa87(k) => MlDsaPublic::MlDsa87(Box::new(k.public.clone())),
            }),
        };
        PublicKey { inner }
    }

    /// Format-neutral description (no declared alg).
    pub fn params(&self) -> KeyParams {
        match &self.inner {
            PrivateInner::Ec(k) => KeyParams::curve(ec_signing_curve(k)),
            PrivateInner::Ed25519(_) => KeyParams::curve(Curve::Ed25519),
            PrivateInner::Rsa(k) => KeyParams::rsa(k.n().bits()),
            PrivateInner::MlDsa(k) => KeyParams::ml_dsa(ml_dsa_private_params(k)),
        }
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("params", &self.params())
            .finish_non_exhaustive()
    }
}

impl PublicKey {
    /// Validates and parses raw material (EC points must be on the curve).
    pub fn from_material(material: &PublicKeyMaterial) -> Result<Self, CryptoError> {
        let inner = match material {
            PublicKeyMaterial::Ec { curve, x, y } => {
                let len = curve.field_len();
                if x.len() != len || y.len() != len {
                    return Err(CryptoError::InvalidKey(
                        "EC coordinate has the wrong length",
                    ));
                }
                // Uncompressed SEC1 encoding; parsing rejects off-curve points.
                let mut sec1 = Vec::with_capacity(1 + 2 * len);
                sec1.push(0x04);
                sec1.extend_from_slice(x);
                sec1.extend_from_slice(y);
                let bad = |_| CryptoError::InvalidKey("EC point is not on the curve");
                PublicInner::Ec(match curve {
                    Curve::P256 => EcVerifyingKey::P256(
                        p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(bad)?,
                    ),
                    Curve::P384 => EcVerifyingKey::P384(
                        p384::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(bad)?,
                    ),
                    Curve::P521 => EcVerifyingKey::P521(Box::new(
                        p521::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(bad)?,
                    )),
                    Curve::Ed25519 => {
                        return Err(CryptoError::InvalidKey("Ed25519 is not an EC curve"));
                    }
                })
            }
            PublicKeyMaterial::Ed25519 { x } => {
                let x: &[u8; 32] = x
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKey("Ed25519 public key must be 32 bytes"))?;
                PublicInner::Ed25519(
                    ed25519_dalek::VerifyingKey::from_bytes(x).map_err(|_| {
                        CryptoError::InvalidKey("Ed25519 public key is not a point")
                    })?,
                )
            }
            PublicKeyMaterial::Rsa { n, e } => {
                let key = RsaPublicKey::new(
                    rsa_uint(n, "RSA n is zero or empty")?,
                    rsa_uint(e, "RSA e is zero or empty")?,
                )
                .map_err(|_| CryptoError::InvalidKey("invalid RSA public key"))?;
                PublicInner::Rsa(Box::new(key))
            }
            PublicKeyMaterial::MlDsa { params, public } => {
                if public.len() != params.public_key_len() {
                    return Err(CryptoError::InvalidKey(
                        "ML-DSA public key has the wrong length",
                    ));
                }
                PublicInner::MlDsa(match params {
                    MlDsaParams::MlDsa44 => MlDsaPublic::MlDsa44(Box::new(ml_dsa_public(public)?)),
                    MlDsaParams::MlDsa65 => MlDsaPublic::MlDsa65(Box::new(ml_dsa_public(public)?)),
                    MlDsaParams::MlDsa87 => MlDsaPublic::MlDsa87(Box::new(ml_dsa_public(public)?)),
                })
            }
        };
        Ok(Self { inner })
    }

    /// The raw components.
    pub fn to_material(&self) -> PublicKeyMaterial {
        match &self.inner {
            PublicInner::Ec(k) => {
                let curve = ec_verifying_curve(k);
                let sec1 =
                    with_ec!(k, EcVerifyingKey, k => k.to_sec1_point(false).as_bytes().to_vec());
                // 0x04 || x || y
                let xy = sec1.get(1..).unwrap_or_default();
                let (x, y) = xy.split_at(xy.len() / 2);
                PublicKeyMaterial::Ec {
                    curve,
                    x: x.to_vec(),
                    y: y.to_vec(),
                }
            }
            PublicInner::Ed25519(k) => PublicKeyMaterial::Ed25519 {
                x: k.to_bytes().to_vec(),
            },
            PublicInner::Rsa(k) => PublicKeyMaterial::Rsa {
                n: uint_to_bytes(k.n().as_ref()),
                e: uint_to_bytes(k.e()),
            },
            PublicInner::MlDsa(k) => PublicKeyMaterial::MlDsa {
                params: ml_dsa_public_params(k),
                public: with_ml_dsa!(k, MlDsaPublic, k => k.encode().to_vec()),
            },
        }
    }

    /// Format-neutral description (no declared alg).
    pub fn params(&self) -> KeyParams {
        match &self.inner {
            PublicInner::Ec(k) => KeyParams::curve(ec_verifying_curve(k)),
            PublicInner::Ed25519(_) => KeyParams::curve(Curve::Ed25519),
            PublicInner::Rsa(k) => KeyParams::rsa(k.n().bits()),
            PublicInner::MlDsa(k) => KeyParams::ml_dsa(ml_dsa_public_params(k)),
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("params", &self.params())
            .finish_non_exhaustive()
    }
}

fn ec_signing_curve(k: &EcSigningKey) -> Curve {
    match k {
        EcSigningKey::P256(_) => Curve::P256,
        EcSigningKey::P384(_) => Curve::P384,
        EcSigningKey::P521(_) => Curve::P521,
    }
}

fn ec_verifying_curve(k: &EcVerifyingKey) -> Curve {
    match k {
        EcVerifyingKey::P256(_) => Curve::P256,
        EcVerifyingKey::P384(_) => Curve::P384,
        EcVerifyingKey::P521(_) => Curve::P521,
    }
}

fn ml_dsa_private_params(k: &MlDsaPrivate) -> MlDsaParams {
    match k {
        MlDsaPrivate::MlDsa44(_) => MlDsaParams::MlDsa44,
        MlDsaPrivate::MlDsa65(_) => MlDsaParams::MlDsa65,
        MlDsaPrivate::MlDsa87(_) => MlDsaParams::MlDsa87,
    }
}

fn ml_dsa_public_params(k: &MlDsaPublic) -> MlDsaParams {
    match k {
        MlDsaPublic::MlDsa44(_) => MlDsaParams::MlDsa44,
        MlDsaPublic::MlDsa65(_) => MlDsaParams::MlDsa65,
        MlDsaPublic::MlDsa87(_) => MlDsaParams::MlDsa87,
    }
}

fn ml_dsa_public<P: ml_dsa::MlDsaParams>(
    public: &[u8],
) -> Result<ml_dsa::VerifyingKey<P>, CryptoError> {
    let enc = ml_dsa::EncodedVerifyingKey::<P>::try_from(public)
        .map_err(|_| CryptoError::InvalidKey("ML-DSA public key has the wrong length"))?;
    Ok(ml_dsa::VerifyingKey::decode(&enc))
}

/// Largest accepted RSA modulus, matching [`RsaPublicKey::MAX_SIZE`].
const MAX_RSA_BYTES: usize = RsaPublicKey::MAX_SIZE / 8;

/// Drops leading zero bytes. `rsa` sizes a `BoxedUint` by its input length,
/// so padded input would change the integer's precision and break signing
/// and verification.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    bytes.get(start..).unwrap_or_default()
}

/// A positive RSA integer from unsigned big-endian bytes.
fn rsa_uint(bytes: &[u8], if_zero: &'static str) -> Result<BoxedUint, CryptoError> {
    let bytes = strip_leading_zeros(bytes);
    if bytes.is_empty() {
        return Err(CryptoError::InvalidKey(if_zero));
    }
    if bytes.len() > MAX_RSA_BYTES {
        return Err(CryptoError::InvalidKey(
            "RSA integer is larger than 8192 bits",
        ));
    }
    Ok(BoxedUint::from_be_slice_vartime(bytes))
}

/// Minimal unsigned big-endian bytes (no leading zeros).
fn uint_to_bytes(n: &BoxedUint) -> Vec<u8> {
    strip_leading_zeros(&n.to_be_bytes()).to_vec()
}

fn rsa_private_key(m: &RsaPrivateMaterial) -> Result<RsaPrivateKey, CryptoError> {
    let (n_bytes, d_bytes) = (strip_leading_zeros(&m.n), strip_leading_zeros(&m.d));
    // Keeps every value within the modulus's precision.
    if d_bytes.len() > n_bytes.len() || (d_bytes.len() == n_bytes.len() && d_bytes >= n_bytes) {
        return Err(CryptoError::InvalidKey("RSA d is not smaller than n"));
    }
    let primes = match (&m.p, &m.q) {
        (Some(p), Some(q)) => vec![
            rsa_uint(p, "RSA p is zero or empty")?,
            rsa_uint(q, "RSA q is zero or empty")?,
        ],
        (None, None) if m.dp.is_none() && m.dq.is_none() && m.qi.is_none() => Vec::new(),
        _ => {
            return Err(CryptoError::InvalidKey(
                "RSA p and q must both be given (with any of dp, dq, qi) or all omitted",
            ));
        }
    };
    let key = RsaPrivateKey::from_components(
        rsa_uint(&m.n, "RSA n is zero or empty")?,
        rsa_uint(&m.e, "RSA e is zero or empty")?,
        rsa_uint(&m.d, "RSA d is zero or empty")?,
        primes,
    )
    .map_err(|_| CryptoError::InvalidKey("inconsistent RSA private key"))?;
    let crt = [
        (&m.dp, key.dp().map(uint_to_bytes)),
        (&m.dq, key.dq().map(uint_to_bytes)),
        (&m.qi, key.crt_coefficient().as_ref().map(uint_to_bytes)),
    ];
    for (given, computed) in crt {
        let Some(computed) = computed else {
            return Err(CryptoError::InvalidKey("inconsistent RSA private key"));
        };
        if let Some(given) = given
            && strip_leading_zeros(given) != computed.as_slice()
        {
            return Err(CryptoError::InvalidKey(
                "RSA CRT values do not match the primes",
            ));
        }
    }
    Ok(key)
}

/// What kind of key to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeySpec {
    /// EC P-256.
    P256,
    /// EC P-384.
    P384,
    /// EC P-521.
    P521,
    /// Ed25519.
    Ed25519,
    /// RSA with a modulus of 2048, 3072, or 4096 bits (e = 65537).
    Rsa {
        /// Modulus size.
        bits: u32,
    },
    /// ML-DSA.
    MlDsa(MlDsaParams),
}

impl KeySpec {
    /// A key type suitable for `alg` (RSA algorithms get 2048 bits).
    pub fn for_alg(alg: Alg) -> KeySpec {
        match alg {
            Alg::ES256 => KeySpec::P256,
            Alg::ES384 => KeySpec::P384,
            Alg::ES512 => KeySpec::P521,
            Alg::EdDSA | Alg::Ed25519 => KeySpec::Ed25519,
            Alg::RS256 | Alg::RS384 | Alg::RS512 | Alg::PS256 | Alg::PS384 | Alg::PS512 => {
                KeySpec::Rsa { bits: 2048 }
            }
            Alg::MlDsa44 => KeySpec::MlDsa(MlDsaParams::MlDsa44),
            Alg::MlDsa65 => KeySpec::MlDsa(MlDsaParams::MlDsa65),
            Alg::MlDsa87 => KeySpec::MlDsa(MlDsaParams::MlDsa87),
        }
    }
}

/// Generates a fresh key using `rng`.
///
/// Ed25519 and ML-DSA keys consume exactly 32 bytes (the secret seed). RSA
/// accepts only 2048, 3072, or 4096 bits and is slow in debug builds.
///
/// ```
/// use tokenator_crypto::{KeySpec, MlDsaParams, generate, rand_core::SeedableRng};
///
/// // Any rand_core 0.10 CryptoRng works; a seeded one gives reproducible keys.
/// let mut rng = rand_chacha::ChaCha20Rng::from_seed([1; 32]);
/// let key = generate(KeySpec::MlDsa(MlDsaParams::MlDsa65), &mut rng)?;
/// assert_eq!(key.params().ml_dsa, Some(MlDsaParams::MlDsa65));
/// # Ok::<(), tokenator_crypto::CryptoError>(())
/// ```
pub fn generate(spec: KeySpec, rng: &mut dyn CryptoRng) -> Result<PrivateKey, CryptoError> {
    let inner = match spec {
        KeySpec::P256 => PrivateInner::Ec(EcSigningKey::P256(
            p256::ecdsa::SigningKey::generate_from_rng(rng),
        )),
        KeySpec::P384 => PrivateInner::Ec(EcSigningKey::P384(
            p384::ecdsa::SigningKey::generate_from_rng(rng),
        )),
        KeySpec::P521 => PrivateInner::Ec(EcSigningKey::P521(Box::new(
            p521::ecdsa::SigningKey::generate_from_rng(rng),
        ))),
        KeySpec::Ed25519 => {
            PrivateInner::Ed25519(Box::new(ed25519_dalek::SigningKey::generate(rng)))
        }
        KeySpec::Rsa { bits } => {
            check_rsa_bits(bits)?;
            let key = RsaPrivateKey::new(rng, bits as usize)
                .map_err(|_| CryptoError::UnsupportedKeySpec("RSA key generation failed"))?;
            PrivateInner::Rsa(Box::new(key))
        }
        KeySpec::MlDsa(params) => {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let key = ml_dsa_from_seed(params, &seed);
            seed.fill(0);
            key
        }
    };
    Ok(PrivateKey { inner })
}

/// Generates a key deterministically from a 32-byte seed.
///
/// - Ed25519: the seed *is* the RFC 8032 secret key.
/// - ML-DSA: the seed *is* the FIPS 204 `xi` (so it matches RFC 9964 `priv`).
/// - EC and RSA: the seed keys a ChaCha20 RNG that drives normal generation.
///   EC/RSA output is reproducible for a given dependency set but is not a
///   cross-implementation standard.
pub fn generate_from_seed(spec: KeySpec, seed: &[u8; 32]) -> Result<PrivateKey, CryptoError> {
    let inner = match spec {
        KeySpec::Ed25519 => {
            PrivateInner::Ed25519(Box::new(ed25519_dalek::SigningKey::from_bytes(seed)))
        }
        KeySpec::MlDsa(params) => ml_dsa_from_seed(params, seed),
        KeySpec::P256 | KeySpec::P384 | KeySpec::P521 | KeySpec::Rsa { .. } => {
            return generate(spec, &mut ChaCha20Rng::from_seed(*seed));
        }
    };
    Ok(PrivateKey { inner })
}

fn ml_dsa_from_seed(params: MlDsaParams, seed: &[u8; 32]) -> PrivateInner {
    PrivateInner::MlDsa(match params {
        MlDsaParams::MlDsa44 => MlDsaPrivate::MlDsa44(Box::new(MlDsaKey::from_seed(seed))),
        MlDsaParams::MlDsa65 => MlDsaPrivate::MlDsa65(Box::new(MlDsaKey::from_seed(seed))),
        MlDsaParams::MlDsa87 => MlDsaPrivate::MlDsa87(Box::new(MlDsaKey::from_seed(seed))),
    })
}

fn check_rsa_bits(bits: u32) -> Result<(), CryptoError> {
    match bits {
        2048 | 3072 | 4096 => Ok(()),
        _ => Err(CryptoError::UnsupportedKeySpec(
            "RSA keys can be generated with 2048, 3072, or 4096 bits",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_range_expanded_ml_dsa_keys_are_rejected_without_panicking() {
        for params in [
            MlDsaParams::MlDsa44,
            MlDsaParams::MlDsa65,
            MlDsaParams::MlDsa87,
        ] {
            let key = generate_from_seed(KeySpec::MlDsa(params), &[3; 32]).unwrap();
            let PrivateKeyMaterial::MlDsa {
                expanded: Some(good),
                ..
            } = key.to_material()
            else {
                panic!("{params:?}");
            };
            assert!(ml_dsa_secret_vectors_in_range(params, &good), "{params:?}");
            // First s1 byte (offset 128) and last s2 byte.
            let s_end = good.len() - 416 * (params.public_key_len() - 32) / 320;
            for offset in [128, s_end - 1] {
                let mut bad = good.clone();
                bad[offset] = 0xff;
                let r = PrivateKey::from_material(&PrivateKeyMaterial::MlDsa {
                    params,
                    seed: None,
                    expanded: Some(bad),
                });
                assert!(
                    matches!(r, Err(CryptoError::InvalidKey(_))),
                    "{params:?} offset {offset}"
                );
            }
        }
    }
}
