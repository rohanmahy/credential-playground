//! Key model, PEM/JWK/COSE_Key conversion, thumbprints, key generation.
//!
//! A [`Key`] is validated key material from `tokenator-crypto` (private or
//! public) plus metadata: role, kid, declared alg, `use`, `key_ops`, and
//! any unrecognized parameters. This crate owns the formats and the
//! metadata; all cryptography (validation, public key derivation,
//! generation, hashing) is delegated to `tokenator-crypto`.
//!
//! Formats: PEM (SPKI, PKCS#8, SEC1, PKCS#1, and the RFC 9881 ML-DSA private
//! key forms), JWK, JWK Set, COSE_Key, and COSE_KeySet. Key types: EC
//! P-256/384/521, Ed25519 (OKP), RSA, and ML-DSA-44/65/87 (AKP, RFC 9964).
//!
//! The crate does no I/O; randomness for [`generate`] is passed in.

// Skeleton: bodies are `unimplemented!()` until the implementation lands.
#![allow(unused_variables, dead_code)]

mod cwk;
mod error;
mod format;
mod jwk;
mod key;
mod ops;

pub use cwk::{CoseKey, cose_thumbprint, from_cwk, params_from_cwk, to_cwk};
pub use error::KeyError;
pub use format::{
    KeyFormat, MlDsaPrivateForm, PemEncoding, export, export_set, import, import_each,
};
pub use jwk::{Jwk, from_jwk, jwk_thumbprint, params_from_jwk, to_jwk};
pub use key::{Extra, Key, KeyOp, Kid, Label, Role, Visibility};
pub use ops::{
    KidSource, ThumbprintKind, WELL_KNOWN_TEST_SEED, assign_kid, cose_thumbprint_uri, generate,
    jwk_thumbprint_uri, params, thumbprint, to_public,
};
/// Re-exported so callers name the same types as this crate's API.
pub use tokenator_crypto::{DeclaredAlg, HashAlg, KeyParams, KeySpec};
