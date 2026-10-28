//! Sign, verify, and digest.

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, SeedableRng};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey};
use sha2::digest::FixedOutputReset;
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::{RandomizedSigner, Signer, Verifier};

use crate::key::{
    EcSigningKey, EcVerifyingKey, MlDsaKey, MlDsaPrivate, MlDsaPublic, PrivateInner, PublicInner,
    with_ec, with_ml_dsa,
};
use crate::{Alg, CryptoError, HashAlg, KeyMismatch, KeyParams, PrivateKey, PublicKey, check_key};

/// Signs `msg` with `key` under `alg`, drawing all randomness from `rng`.
///
/// - ECDSA: RFC 6979 nonces hedged with fresh bytes from `rng` (RFC 6979 §3.6),
///   output `r || s`.
/// - ML-DSA: hedged signing with `rnd` = the next 32 bytes from `rng`, empty
///   context.
/// - PSS: salt (hash length) from `rng`.
/// - Ed25519 and RSASSA-PKCS1-v1_5 are deterministic and ignore `rng` (RSA
///   uses it only to blind the private-key operation, which does not change
///   the output).
///
/// A fixed-seed `rng` therefore gives reproducible signatures.
///
/// Fails with [`CryptoError::KeyNotSuitable`] when the key's type, curve, or
/// ML-DSA parameter set does not fit `alg`. Undersized RSA keys are allowed
/// here (so weak-key tokens can be produced) and reported by
/// [`check_key`](crate::check_key) instead.
///
/// # RSA timing side channel
///
/// The pure-Rust `rsa` crate is affected by the Marvin attack
/// ([RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071)):
/// its private-key operation is not constant-time, so an attacker who can
/// time many signing operations may recover the key. Private-key operations
/// here are always blinded (with `rng`, or for [`sign_deterministic`] with an
/// RNG derived from the key and message), which reduces but does not remove
/// the leak. Do not use this crate to sign with valuable RSA keys in a
/// setting where an attacker can measure signing time.
///
/// ```
/// use tokenator_crypto::{Alg, KeySpec, generate_from_seed, rand_core::SeedableRng, sign, verify};
///
/// let key = generate_from_seed(KeySpec::for_alg(Alg::MlDsa44), &[9; 32])?;
/// let mut rng = rand_chacha::ChaCha20Rng::from_seed([0; 32]);
/// let input = b"eyJhbGciOiJNTC1EU0EtNDQifQ.eyJzdWIiOiJ0b2tlbmF0b3IifQ";
/// let sig = sign(Alg::MlDsa44, &key, input, &mut rng)?;
/// assert_eq!(Some(sig.len()), Alg::MlDsa44.fixed_signature_len());
/// verify(Alg::MlDsa44, &key.public_key(), input, &sig)?;
///
/// // A P-256 key cannot be used with ML-DSA-44.
/// let p256 = generate_from_seed(KeySpec::P256, &[9; 32])?;
/// assert!(matches!(
///     sign(Alg::MlDsa44, &p256, input, &mut rng),
///     Err(tokenator_crypto::CryptoError::KeyNotSuitable { .. })
/// ));
/// # Ok::<(), tokenator_crypto::CryptoError>(())
/// ```
pub fn sign(
    alg: Alg,
    key: &PrivateKey,
    msg: &[u8],
    rng: &mut dyn CryptoRng,
) -> Result<Vec<u8>, CryptoError> {
    sign_with(alg, key, msg, Some(rng))
}

/// Signs without randomness: pure RFC 6979 ECDSA, the FIPS 204 deterministic
/// ML-DSA variant (`rnd` = 0), Ed25519, and PKCS#1 v1.5. Fails with
/// [`CryptoError::RandomnessRequired`] for PSS.
///
/// See [`sign`] for the RSA timing side channel.
pub fn sign_deterministic(alg: Alg, key: &PrivateKey, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
    sign_with(alg, key, msg, None)
}

/// Verifies `sig` over `msg`. ECDSA signatures must be raw `r || s`.
///
/// Fails with [`CryptoError::KeyNotSuitable`] when the key does not fit
/// `alg`, and with [`CryptoError::InvalidSignature`] for any malformed or
/// non-verifying signature. PSS requires a salt as long as the hash.
pub fn verify(alg: Alg, key: &PublicKey, msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
    ensure_suitable(alg, &key.params())?;
    let bad = |_| CryptoError::InvalidSignature;
    match &key.inner {
        PublicInner::Ec(k) => with_ec!(k, EcVerifyingKey, k => {
            let sig = ecdsa::Signature::from_slice(sig).map_err(bad)?;
            k.verify(msg, &sig).map_err(bad)
        }),
        PublicInner::Ed25519(k) => {
            let sig = ed25519_dalek::Signature::from_slice(sig).map_err(bad)?;
            k.verify_strict(msg, &sig).map_err(bad)
        }
        PublicInner::Rsa(k) => rsa_verify(alg, k, msg, sig),
        PublicInner::MlDsa(k) => with_ml_dsa!(k, MlDsaPublic, k => {
            let sig = ml_dsa::Signature::try_from(sig).map_err(bad)?;
            if k.verify_with_context(msg, &[], &sig) {
                Ok(())
            } else {
                Err(CryptoError::InvalidSignature)
            }
        }),
    }
}

/// Hashes `data`.
///
/// ```
/// use tokenator_crypto::{HashAlg, digest};
///
/// assert_eq!(digest(HashAlg::Sha384, b"abc").len(), HashAlg::Sha384.output_len());
/// ```
pub fn digest(h: HashAlg, data: &[u8]) -> Vec<u8> {
    match h {
        HashAlg::Sha256 => Sha256::digest(data).to_vec(),
        HashAlg::Sha384 => Sha384::digest(data).to_vec(),
        HashAlg::Sha512 => Sha512::digest(data).to_vec(),
    }
}

/// Rejects keys whose type, curve, or parameter set does not fit `alg`. An
/// undersized RSA key is only a lint finding.
fn ensure_suitable(alg: Alg, params: &KeyParams) -> Result<(), CryptoError> {
    let mismatches = check_key(alg, params);
    if mismatches
        .iter()
        .all(|m| matches!(m, KeyMismatch::RsaTooSmall { .. }))
    {
        Ok(())
    } else {
        Err(CryptoError::KeyNotSuitable { alg, mismatches })
    }
}

fn sign_with(
    alg: Alg,
    key: &PrivateKey,
    msg: &[u8],
    rng: Option<&mut dyn CryptoRng>,
) -> Result<Vec<u8>, CryptoError> {
    ensure_suitable(alg, &key.params())?;
    // ensure_suitable has matched the key to `alg`, so only the key decides
    // the backend below.
    match &key.inner {
        PrivateInner::Ec(k) => with_ec!(k, EcSigningKey, k => {
            let sig: ecdsa::Signature<_> = match rng {
                Some(rng) => k.try_sign_with_rng(rng, msg),
                None => k.try_sign(msg),
            }
            .map_err(|_| CryptoError::InvalidKey("ECDSA signing failed"))?;
            Ok(sig.to_vec())
        }),
        PrivateInner::Ed25519(k) => {
            let sig: ed25519_dalek::Signature = k
                .try_sign(msg)
                .map_err(|_| CryptoError::InvalidKey("Ed25519 signing failed"))?;
            Ok(sig.to_bytes().to_vec())
        }
        PrivateInner::Rsa(k) => rsa_sign(alg, k, msg, rng),
        PrivateInner::MlDsa(k) => with_ml_dsa!(k, MlDsaPrivate, k => ml_dsa_sign(k, msg, rng)),
    }
}

fn ml_dsa_sign<P: ml_dsa::MlDsaParams>(
    key: &MlDsaKey<P>,
    msg: &[u8],
    rng: Option<&mut dyn CryptoRng>,
) -> Result<Vec<u8>, CryptoError> {
    // JOSE and COSE use pure ML-DSA with an empty context (RFC 9964).
    let sig = match rng {
        Some(rng) => key.expanded().sign_randomized(msg, &[], rng),
        None => key.expanded().sign_deterministic(msg, &[]),
    }
    .map_err(|_| CryptoError::InvalidKey("ML-DSA signing failed"))?;
    Ok(sig.encode().to_vec())
}

#[derive(Clone, Copy)]
enum RsaPadding {
    Pkcs1v15,
    Pss,
}

fn rsa_scheme(alg: Alg) -> Result<(HashAlg, RsaPadding), CryptoError> {
    Ok(match alg {
        Alg::RS256 => (HashAlg::Sha256, RsaPadding::Pkcs1v15),
        Alg::RS384 => (HashAlg::Sha384, RsaPadding::Pkcs1v15),
        Alg::RS512 => (HashAlg::Sha512, RsaPadding::Pkcs1v15),
        Alg::PS256 => (HashAlg::Sha256, RsaPadding::Pss),
        Alg::PS384 => (HashAlg::Sha384, RsaPadding::Pss),
        Alg::PS512 => (HashAlg::Sha512, RsaPadding::Pss),
        // Unreachable after ensure_suitable; reported the same way.
        _ => {
            return Err(CryptoError::KeyNotSuitable {
                alg,
                mismatches: check_key(alg, &KeyParams::rsa(0)),
            });
        }
    })
}

fn pkcs1v15(hash: HashAlg) -> Pkcs1v15Sign {
    match hash {
        HashAlg::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
        HashAlg::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
        HashAlg::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
    }
}

/// PSS with MGF1 over the same hash and a salt as long as the hash (RFC 7518
/// §3.5). `blinded` only blinds the private-key operation; the output is an
/// ordinary PSS signature.
fn pss<D: Digest + FixedOutputReset>() -> Pss<D> {
    Pss {
        blinded: true,
        ..Pss::new()
    }
}

fn rsa_sign(
    alg: Alg,
    key: &RsaPrivateKey,
    msg: &[u8],
    rng: Option<&mut dyn CryptoRng>,
) -> Result<Vec<u8>, CryptoError> {
    let (hash, padding) = rsa_scheme(alg)?;
    let hashed = digest(hash, msg);
    let result = match (padding, rng) {
        (RsaPadding::Pss, None) => return Err(CryptoError::RandomnessRequired(alg)),
        (RsaPadding::Pss, Some(rng)) => match hash {
            HashAlg::Sha256 => key.sign_with_rng(rng, pss::<Sha256>(), &hashed),
            HashAlg::Sha384 => key.sign_with_rng(rng, pss::<Sha384>(), &hashed),
            HashAlg::Sha512 => key.sign_with_rng(rng, pss::<Sha512>(), &hashed),
        },
        (RsaPadding::Pkcs1v15, Some(rng)) => key.sign_with_rng(rng, pkcs1v15(hash), &hashed),
        (RsaPadding::Pkcs1v15, None) => {
            let mut blinding = deterministic_blinding_rng(key, &hashed);
            key.sign_with_rng(&mut blinding, pkcs1v15(hash), &hashed)
        }
    };
    // The only realistic failure is a modulus too small for the encoded digest.
    result.map_err(|_| CryptoError::InvalidKey("RSA key is too small for this algorithm"))
}

/// An RNG for blinding the RSA private-key operation without caller
/// randomness. It is keyed by the private exponent, so it is unpredictable
/// to anyone without the key (the same idea as RFC 6979 nonces); blinding
/// never changes a PKCS#1 v1.5 signature.
fn deterministic_blinding_rng(key: &RsaPrivateKey, hashed: &[u8]) -> ChaCha20Rng {
    let mut h = Sha256::new();
    h.update(b"tokenator-crypto RSA blinding v1");
    h.update(key.d().to_be_bytes());
    h.update(hashed);
    ChaCha20Rng::from_seed(h.finalize().into())
}

fn rsa_verify(alg: Alg, key: &RsaPublicKey, msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
    let (hash, padding) = rsa_scheme(alg)?;
    // Signatures are exactly as long as the modulus (RFC 8017 §8.1.2, §8.2.2).
    if sig.len() != key.size() {
        return Err(CryptoError::InvalidSignature);
    }
    let hashed = digest(hash, msg);
    let result = match (padding, hash) {
        (RsaPadding::Pkcs1v15, _) => key.verify(pkcs1v15(hash), &hashed, sig),
        // `Pss::new` fixes the salt length to the hash length, which verify enforces.
        (RsaPadding::Pss, HashAlg::Sha256) => key.verify(Pss::<Sha256>::new(), &hashed, sig),
        (RsaPadding::Pss, HashAlg::Sha384) => key.verify(Pss::<Sha384>::new(), &hashed, sig),
        (RsaPadding::Pss, HashAlg::Sha512) => key.verify(Pss::<Sha512>::new(), &hashed, sig),
    };
    result.map_err(|_| CryptoError::InvalidSignature)
}
