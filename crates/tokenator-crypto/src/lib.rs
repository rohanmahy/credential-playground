//! Signing, verification, digests, and algorithm/key requirements.
//!
//! This is the only crate in the workspace that touches key material. It is
//! format-neutral: JWK, COSE_Key, and PEM live in `tokenator-keys`, which
//! converts to and from [`PrivateKeyMaterial`] / [`PublicKeyMaterial`].
//!
//! The crate does no I/O and never reaches for an implicit RNG: every
//! randomized operation takes a `&mut dyn CryptoRng`, so tests (and the
//! playground's "seeded" mode) are reproducible. JOSE/COSE ECDSA signatures
//! are the fixed-width `r || s` form, never DER.
//!
//! ```no_run
//! use tokenator_crypto::{Alg, KeySpec, generate_from_seed, sign_deterministic, verify};
//!
//! let key = generate_from_seed(KeySpec::P256, &[7u8; 32])?;
//! let sig = sign_deterministic(Alg::ES256, &key, b"hello")?;
//! assert_eq!(sig.len(), 64);
//! verify(Alg::ES256, &key.public_key(), b"hello", &sig)?;
//! # Ok::<(), tokenator_crypto::CryptoError>(())
//! ```

mod alg;
mod error;
mod key;
mod ops;
mod requirements;

pub use alg::{
    Alg, Curve, HashAlg, KeyType, MlDsaParams, alg_from_cose, alg_from_jose, alg_to_cose,
    alg_to_jose,
};
pub use error::CryptoError;
pub use key::{
    KeySpec, PrivateKey, PrivateKeyMaterial, PublicKey, PublicKeyMaterial, RsaPrivateMaterial,
    generate, generate_from_seed,
};
pub use ops::{digest, sign, sign_deterministic, verify};
/// Re-exported so callers name the same `CryptoRng` trait version as this crate.
pub use rand_core;
pub use requirements::{
    DeclaredAlg, KeyMismatch, KeyParams, KeyRequirements, algs_for_key, check_key, requirements,
};
