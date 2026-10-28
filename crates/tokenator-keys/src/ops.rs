//! Operations on keys: public derivation, params, thumbprints, generation,
//! and kid assignment.

use tokenator_crypto::rand_core::CryptoRng;
use tokenator_crypto::{HashAlg, KeyParams, KeySpec};

use crate::{Key, KeyError, Role};

/// The public half of `key`, as a new key with the same metadata (role,
/// kid, alg, use, key_ops, extras) and [`Key::derived`] set. A public key
/// is returned unchanged.
pub fn to_public(key: &Key) -> Key {
    unimplemented!()
}

/// The key's format-neutral description for `tokenator_crypto::check_key`:
/// type, curve, RSA size, and ML-DSA set from the material, plus the
/// declared [`Key::alg`].
pub fn params(key: &Key) -> KeyParams {
    unimplemented!()
}

/// Which thumbprint to compute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThumbprintKind {
    /// RFC 7638 JWK thumbprint.
    Jwk,
    /// RFC 9679 COSE Key thumbprint.
    Cose,
}

/// The thumbprint of `key`'s public part (raw hash output).
///
/// Metadata never affects it, except that for AKP keys the `alg` member is
/// the ML-DSA parameter set of the material.
pub fn thumbprint(key: &Key, kind: ThumbprintKind, hash: HashAlg) -> Vec<u8> {
    unimplemented!()
}

/// The RFC 9278 JWK thumbprint URI,
/// `urn:ietf:params:oauth:jwk-thumbprint:<hash name>:<base64url>`, with the
/// hash name from [`HashAlg::name`] (e.g. `sha-256`).
pub fn jwk_thumbprint_uri(key: &Key, hash: HashAlg) -> String {
    unimplemented!()
}

/// The RFC 9679 §5.7 COSE Key thumbprint URI,
/// `urn:ietf:params:oauth:ckt:<hash name>:<base64url>`.
pub fn cose_thumbprint_uri(key: &Key, hash: HashAlg) -> String {
    unimplemented!()
}

/// The fixed, well-known test seed offered by the key panel (SPEC §4.2):
/// 32 zero bytes. With it, ML-DSA generation reproduces the RFC 9964
/// Appendix A keys.
pub const WELL_KNOWN_TEST_SEED: [u8; 32] = [0; 32];

/// Generates a key through `tokenator-crypto`.
///
/// With a seed, generation is deterministic (`generate_from_seed`) and
/// `rng` is not used. A 32-byte seed is used as is; any other length
/// (including empty) is first hashed with SHA-256. For Ed25519 the 32-byte
/// seed is the RFC 8032 secret key and for ML-DSA it is the FIPS 204 seed
/// (RFC 9964 `priv`). Without a seed, `rng` supplies the randomness. The
/// new key has `role` and no other metadata.
pub fn generate(
    spec: KeySpec,
    role: Option<Role>,
    seed: Option<&[u8]>,
    rng: &mut dyn CryptoRng,
) -> Result<Key, KeyError> {
    unimplemented!()
}

/// Where [`assign_kid`] gets the kid from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KidSource {
    /// The base64url (unpadded) JWK thumbprint, as [`Kid::Text`](crate::Kid::Text)
    /// (the RFC 9964 Appendix A convention).
    JwkThumbprint(HashAlg),
    /// The raw COSE Key thumbprint, as [`Kid::Bytes`](crate::Kid::Bytes)
    /// (the RFC 9679 §6 / RFC 9964 Appendix A convention).
    CoseThumbprint(HashAlg),
    /// A user-supplied text kid.
    Text(String),
    /// A user-supplied binary kid.
    Bytes(Vec<u8>),
}

/// Sets `key.kid` from `source`, replacing any existing kid.
pub fn assign_kid(key: &mut Key, source: KidSource) {
    unimplemented!()
}
