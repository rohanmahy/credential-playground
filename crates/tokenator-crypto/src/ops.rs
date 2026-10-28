//! Sign, verify, and digest.

// Skeleton: bodies are filled in by the implementation.
#![allow(unused_variables, clippy::unimplemented)]

use rand_core::CryptoRng;

use crate::{Alg, CryptoError, HashAlg, PrivateKey, PublicKey};

/// Signs `msg` with `key` under `alg`, drawing all randomness from `rng`.
///
/// - ECDSA: RFC 6979 nonces hedged with fresh bytes from `rng` (RFC 6979 §3.6),
///   output `r || s`.
/// - ML-DSA: hedged signing with `rnd` = the next 32 bytes from `rng`, empty
///   context.
/// - PSS: salt (hash length) from `rng`.
/// - Ed25519 and RSASSA-PKCS1-v1_5 are deterministic and ignore `rng`.
///
/// A fixed-seed `rng` therefore gives reproducible signatures.
pub fn sign(
    alg: Alg,
    key: &PrivateKey,
    msg: &[u8],
    rng: &mut dyn CryptoRng,
) -> Result<Vec<u8>, CryptoError> {
    unimplemented!()
}

/// Signs without randomness: pure RFC 6979 ECDSA, the FIPS 204 deterministic
/// ML-DSA variant (`rnd` = 0), Ed25519, and PKCS#1 v1.5. Fails with
/// [`CryptoError::RandomnessRequired`] for PSS.
pub fn sign_deterministic(alg: Alg, key: &PrivateKey, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
    unimplemented!()
}

/// Verifies `sig` over `msg`. ECDSA signatures must be raw `r || s`.
pub fn verify(alg: Alg, key: &PublicKey, msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
    unimplemented!()
}

/// Hashes `data`.
pub fn digest(h: HashAlg, data: &[u8]) -> Vec<u8> {
    unimplemented!()
}
