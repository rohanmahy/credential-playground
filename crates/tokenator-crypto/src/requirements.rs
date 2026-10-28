//! The alg/key requirements table, consumed by the linter and by validation.

// Skeleton: bodies are filled in by the implementation.
#![allow(unused_variables, clippy::unimplemented)]

use crate::{Alg, Curve, KeyType, MlDsaParams};

/// What a key must look like to be used with an [`Alg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRequirements {
    /// Required key type.
    pub kty: KeyType,
    /// Required JWK `kty` (same as `kty.jwk_kty()`).
    pub jwk_kty: &'static str,
    /// Required COSE `kty` (same as `kty.cose_kty()`).
    pub cose_kty: i64,
    /// Required curve for EC and OKP keys; gives both JWK name and COSE label.
    pub crv: Option<Curve>,
    /// Required ML-DSA parameter set for AKP keys.
    pub akp_param_set: Option<MlDsaParams>,
    /// Minimum RSA modulus size in bits.
    pub min_rsa_bits: Option<u32>,
}

/// The `alg` a JWK or COSE_Key declares about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclaredAlg {
    /// A supported algorithm.
    Known(Alg),
    /// A JOSE name this crate does not support (e.g. `HS256`).
    UnknownJose(String),
    /// A COSE label this crate does not support (e.g. `-9`).
    UnknownCose(i64),
}

/// A format-neutral description of a key, without key material.
///
/// `tokenator-keys` builds one from a JWK or COSE_Key; [`PrivateKey::params`]
/// and [`PublicKey::params`] build one from material (with no declared alg).
///
/// [`PrivateKey::params`]: crate::PrivateKey::params
/// [`PublicKey::params`]: crate::PublicKey::params
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyParams {
    /// Key type.
    pub kty: KeyType,
    /// Curve, for EC and OKP keys.
    pub crv: Option<Curve>,
    /// RSA modulus size in bits.
    pub rsa_bits: Option<u32>,
    /// ML-DSA parameter set, for AKP keys.
    pub ml_dsa: Option<MlDsaParams>,
    /// The key's own `alg` field, if any.
    pub declared_alg: Option<DeclaredAlg>,
}

impl KeyParams {
    /// An EC (P-256/384/521) or OKP (Ed25519) key on `crv`.
    pub fn curve(crv: Curve) -> Self {
        unimplemented!()
    }

    /// An RSA key with a modulus of `bits` bits.
    pub fn rsa(bits: u32) -> Self {
        unimplemented!()
    }

    /// An AKP key for the ML-DSA parameter set `params`.
    pub fn ml_dsa(params: MlDsaParams) -> Self {
        unimplemented!()
    }

    /// Sets the declared `alg`.
    pub fn with_declared_alg(self, alg: DeclaredAlg) -> Self {
        unimplemented!()
    }
}

/// One reason a key does not fit an algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyMismatch {
    /// Wrong key type. When this is reported, curve, size, and parameter-set
    /// checks are skipped.
    KeyType {
        /// Required.
        expected: KeyType,
        /// Present.
        found: KeyType,
    },
    /// Wrong or missing curve.
    Curve {
        /// Required.
        expected: Curve,
        /// Present.
        found: Option<Curve>,
    },
    /// RSA modulus below the minimum size.
    RsaTooSmall {
        /// Required minimum.
        min_bits: u32,
        /// Present.
        found_bits: u32,
    },
    /// Wrong or missing ML-DSA parameter set.
    MlDsaParamSet {
        /// Required.
        expected: MlDsaParams,
        /// Present.
        found: Option<MlDsaParams>,
    },
    /// The key's declared `alg` differs from the algorithm in use.
    DeclaredAlg {
        /// The algorithm in use (e.g. the header `alg`).
        alg: Alg,
        /// What the key declares.
        declared: DeclaredAlg,
    },
}

/// The key requirements of `alg`.
pub fn requirements(alg: Alg) -> KeyRequirements {
    unimplemented!()
}

/// All findings for using a key described by `params` with `alg`; empty when
/// the key fits. Order: key type, then curve / size / parameter set, then
/// declared alg.
pub fn check_key(alg: Alg, params: &KeyParams) -> Vec<KeyMismatch> {
    unimplemented!()
}

/// The algorithms (in [`Alg::ALL`] order) for which [`check_key`] reports no
/// findings.
pub fn algs_for_key(params: &KeyParams) -> Vec<Alg> {
    unimplemented!()
}
