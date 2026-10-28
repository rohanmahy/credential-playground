use core::fmt;

use crate::{Alg, KeyMismatch};

/// Errors from key construction, signing, and verification.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// Key material is malformed: wrong length, not on the curve, zero or
    /// out-of-range scalar, inconsistent RSA components, seed and expanded
    /// ML-DSA key that disagree, and so on.
    InvalidKey(&'static str),
    /// The key cannot be used with `alg` at all (wrong key type, curve, or
    /// ML-DSA parameter set). Undersized RSA keys are *not* rejected here;
    /// they are reported by [`check_key`](crate::check_key) instead.
    KeyNotSuitable {
        /// The algorithm that was requested.
        alg: Alg,
        /// Why the key does not fit.
        mismatches: Vec<KeyMismatch>,
    },
    /// The signature did not verify (including a wrong length or a DER
    /// encoding where raw `r || s` is required).
    InvalidSignature,
    /// [`sign_deterministic`](crate::sign_deterministic) was called for an
    /// algorithm that needs randomness (RSASSA-PSS needs a random salt).
    RandomnessRequired(Alg),
    /// Key generation was asked for an unsupported size.
    UnsupportedKeySpec(&'static str),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey(why) => write!(f, "invalid key: {why}"),
            Self::KeyNotSuitable { alg, mismatches } => {
                write!(f, "key is not suitable for {alg:?}: {mismatches:?}")
            }
            Self::InvalidSignature => f.write_str("signature verification failed"),
            Self::RandomnessRequired(alg) => write!(f, "{alg:?} requires randomness"),
            Self::UnsupportedKeySpec(why) => write!(f, "unsupported key spec: {why}"),
        }
    }
}

impl std::error::Error for CryptoError {}
