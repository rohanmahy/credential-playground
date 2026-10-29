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
//!
//! # Converting a JWK to PEM
//!
//! ```
//! use tokenator_keys::{KeyFormat, PemEncoding, Visibility, export, import};
//!
//! // RFC 8037 Appendix A.2 (format detected from the input).
//! let jwk = br#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
//! let keys = import(jwk, None)?;
//! let pem = export(&keys[0], KeyFormat::Pem(PemEncoding::Spki), Visibility::Public)?;
//! assert!(pem.starts_with(b"-----BEGIN PUBLIC KEY-----\n"));
//! # Ok::<(), tokenator_keys::KeyError>(())
//! ```
//!
//! # A seeded ML-DSA key, its kid, and both families
//!
//! With [`WELL_KNOWN_TEST_SEED`], generation reproduces the RFC 9964
//! Appendix A key. The JOSE convention is a text kid made from the JWK
//! thumbprint; the kid survives the trip through a COSE_Key as bytes.
//!
//! ```
//! use tokenator_crypto::rand_core::SeedableRng;
//! use tokenator_keys::{
//!     HashAlg, KeyFormat, KeySpec, Kid, KidSource, Role, Visibility, WELL_KNOWN_TEST_SEED,
//!     assign_kid, export, generate, import,
//! };
//! use tokenator_crypto::MlDsaParams;
//!
//! let mut rng = rand_chacha::ChaCha20Rng::from_seed([0; 32]); // unused with a seed
//! let mut key = generate(
//!     KeySpec::MlDsa(MlDsaParams::MlDsa44),
//!     Some(Role::Issuer),
//!     Some(&WELL_KNOWN_TEST_SEED),
//!     &mut rng,
//! )?;
//! assign_kid(&mut key, KidSource::JwkThumbprint(HashAlg::Sha256));
//! let Some(Kid::Text(kid)) = key.kid.clone() else { unreachable!() };
//! assert_eq!(kid, "T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o"); // RFC 9964 A.1
//!
//! let cbor = export(&key, KeyFormat::CoseKey, Visibility::Private)?;
//! let back = import(&cbor, None)?.remove(0);
//! assert!(back.same_material(&key));
//! assert_eq!(back.kid, Some(Kid::Bytes(kid.into_bytes())));
//! assert_eq!(back.role, None, "roles are never serialized");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod cwk;
mod error;
mod format;
mod jwk;
mod key;
mod material;
mod ops;
mod pem;

pub use cwk::{CoseKey, cose_thumbprint, from_cwk, params_from_cwk, to_cwk};
pub use error::KeyError;
pub use format::{
    KeyFormat, MlDsaPrivateForm, PemEncoding, export, export_set, import, import_certificate,
    import_each,
};
pub use jwk::{Jwk, from_jwk, jwk_thumbprint, params_from_jwk, to_jwk};
pub use key::{Extra, Key, KeyOp, Kid, Label, Role, Visibility};
pub use ops::{
    KidSource, ThumbprintKind, WELL_KNOWN_TEST_SEED, assign_kid, cose_thumbprint_uri, generate,
    jwk_thumbprint_uri, params, thumbprint, to_public,
};
/// Re-exported so callers name the same types as this crate's API.
pub use tokenator_crypto::{DeclaredAlg, HashAlg, KeyParams, KeySpec};
