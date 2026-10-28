//! Format-neutral key material, parsed keys, and key generation.

// Skeleton: bodies are filled in by the implementation.
#![allow(unused_variables, clippy::unimplemented)]

use core::fmt;

use rand_core::CryptoRng;

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
    _todo: (),
}

impl PrivateKey {
    /// Validates and parses raw material.
    pub fn from_material(material: &PrivateKeyMaterial) -> Result<Self, CryptoError> {
        unimplemented!()
    }

    /// The raw components (see [`PrivateKeyMaterial`] for what is filled in).
    pub fn to_material(&self) -> PrivateKeyMaterial {
        unimplemented!()
    }

    /// The matching public key.
    pub fn public_key(&self) -> PublicKey {
        unimplemented!()
    }

    /// Format-neutral description (no declared alg).
    pub fn params(&self) -> KeyParams {
        unimplemented!()
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unimplemented!()
    }
}

/// A validated public key, ready to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    _todo: (),
}

impl PublicKey {
    /// Validates and parses raw material (EC points must be on the curve).
    pub fn from_material(material: &PublicKeyMaterial) -> Result<Self, CryptoError> {
        unimplemented!()
    }

    /// The raw components.
    pub fn to_material(&self) -> PublicKeyMaterial {
        unimplemented!()
    }

    /// Format-neutral description (no declared alg).
    pub fn params(&self) -> KeyParams {
        unimplemented!()
    }
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
        unimplemented!()
    }
}

/// Generates a fresh key using `rng`.
pub fn generate(spec: KeySpec, rng: &mut dyn CryptoRng) -> Result<PrivateKey, CryptoError> {
    unimplemented!()
}

/// Generates a key deterministically from a 32-byte seed.
///
/// - Ed25519: the seed *is* the RFC 8032 secret key.
/// - ML-DSA: the seed *is* the FIPS 204 `xi` (so it matches RFC 9964 `priv`).
/// - EC and RSA: the seed keys a ChaCha20 RNG that drives normal generation.
///   EC/RSA output is reproducible for a given dependency set but is not a
///   cross-implementation standard.
pub fn generate_from_seed(spec: KeySpec, seed: &[u8; 32]) -> Result<PrivateKey, CryptoError> {
    unimplemented!()
}
