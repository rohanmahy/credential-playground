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
//! # Signing and verifying
//!
//! ```
//! use tokenator_crypto::{Alg, KeySpec, generate_from_seed, sign_deterministic, verify};
//!
//! let key = generate_from_seed(KeySpec::P256, &[7u8; 32])?;
//! let sig = sign_deterministic(Alg::ES256, &key, b"hello")?;
//! assert_eq!(sig.len(), 64);
//! verify(Alg::ES256, &key.public_key(), b"hello", &sig)?;
//! # Ok::<(), tokenator_crypto::CryptoError>(())
//! ```
//!
//! # Checking a foreign key against a header `alg`
//!
//! A verifier gets a JOSE `alg` and a key from elsewhere (here the RFC 8037
//! Ed25519 JWK, already base64url-decoded by `tokenator-keys`). Look up the
//! algorithm, report key findings the way the linter does, and verify.
//!
//! ```
//! use tokenator_crypto::{
//!     CryptoError, DeclaredAlg, KeyMismatch, PublicKey, PublicKeyMaterial, alg_from_jose,
//!     check_key, verify,
//! };
//!
//! let x = [
//!     0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
//!     0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
//!     0x51, 0x1a,
//! ];
//! let key = PublicKey::from_material(&PublicKeyMaterial::Ed25519 { x: x.to_vec() })?;
//!
//! // The token says "Ed25519" (RFC 9864) but the JWK declares the older "EdDSA".
//! let alg = alg_from_jose("Ed25519").expect("supported");
//! let params = key
//!     .params()
//!     .with_declared_alg(DeclaredAlg::Known(alg_from_jose("EdDSA").expect("supported")));
//! let findings = check_key(alg, &params);
//! assert!(matches!(findings.as_slice(), [KeyMismatch::DeclaredAlg { .. }]));
//!
//! // `verify` looks only at the key itself, so a declared-alg finding never
//! // blocks it. A key of the wrong type is refused, carrying the same findings.
//! let es256 = alg_from_jose("ES256").expect("supported");
//! match verify(es256, &key, b"msg", &[0; 64]) {
//!     Err(CryptoError::KeyNotSuitable { mismatches, .. }) => {
//!         assert_eq!(mismatches, check_key(es256, &key.params()));
//!     }
//!     other => panic!("{other:?}"),
//! }
//! # Ok::<(), CryptoError>(())
//! ```
//!
//! # Backends and caveats
//!
//! `p256`/`p384`/`p521` (via `ecdsa`), `ed25519-dalek`, `rsa`, `ml-dsa`, and
//! `sha2`, all pure Rust, with no `getrandom` so the crate builds for
//! `wasm32-unknown-unknown`. The `rsa` crate has a known timing side channel
//! (the Marvin attack, RUSTSEC-2023-0071); see [`sign`] before signing with
//! RSA keys that matter.

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
