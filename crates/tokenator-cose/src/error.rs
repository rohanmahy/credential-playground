//! Errors.

use core::fmt;

use tokenator_cbor::{DecodeError, EncodeError};
use tokenator_crypto::{Alg, CryptoError, DeclaredAlg, KeyMismatch};
use tokenator_keys::{KeyError, Label};

use crate::Part;

/// Errors from parsing, signing, verifying, and building COSE objects.
///
/// Parsers never panic: every malformed input ends up as one of these, or as
/// a [`Diagnostic`](crate::Diagnostic) on a partial result.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum CoseError {
    /// The input is not well-formed CBOR (including trailing bytes).
    Cbor(DecodeError),
    /// An item cannot be encoded (it holds a `simple(24..=31)`).
    Encode(EncodeError),
    /// Well-formed CBOR that is not a COSE_Sign1: not an array under its tags.
    NotSign1,
    /// A COSE structure this crate does not handle: COSE_Encrypt0 (16),
    /// COSE_Mac0 (17), COSE_Encrypt (96), COSE_Mac (97), COSE_Sign (98).
    UnsupportedStructure {
        /// The COSE tag.
        tag: u64,
    },
    /// A part needed for the operation is missing or has the wrong type.
    MalformedPart(Part),
    /// No `alg` header parameter.
    MissingAlg,
    /// An `alg` this crate cannot sign or verify with.
    UnsupportedAlg(DeclaredAlg),
    /// Signing needs a private key.
    NoPrivateKey,
    /// The key cannot be used with `alg` (wrong type, curve, or parameter set).
    KeyNotSuitable {
        /// The algorithm that was requested.
        alg: Alg,
        /// Why the key does not fit.
        mismatches: Vec<KeyMismatch>,
    },
    /// The signature did not verify.
    InvalidSignature,
    /// The payload is detached (`nil`) and none was supplied.
    DetachedPayload,
    /// No key was available for the check.
    NoKey,
    /// Any other error from `tokenator-crypto` (e.g. PSS without randomness).
    Crypto(CryptoError),
    /// A key could not be parsed or converted.
    Key(KeyError),
    /// The token is not an SD-KBT (no `kcwt` header parameter).
    NotKbt,
    /// The `cnf` claim is missing or unusable.
    Cnf(&'static str),
    /// The pre-issuance claims set cannot be redacted.
    Redaction(RedactionError),
    /// A [`SaltSource`](crate::sd::SaltSource) could not supply a salt.
    SaltExhausted,
    /// A disclosure index is out of range.
    DisclosureIndex(usize),
    /// A tamper or edit operation does not apply to this input (e.g. flipping
    /// a bit past the end).
    NotApplicable(&'static str),
}

/// Why a pre-issuance claims set (draft-ietf-spice-sd-cwt-08 §5.3, §11) was
/// rejected by [`redact`](crate::sd::redact).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RedactionError {
    /// The claims set is not a map.
    NotAMap,
    /// A map holds both `k` and `58(k)`, or the same key twice (§5.4, §11.1).
    DuplicateKey(Label),
    /// A map key wrapped in more than one tag, e.g. `58(58(1))` (§5.3).
    NestedTag,
    /// A to-be-redacted tag whose content is not an int or a text string of
    /// 1..=255 bytes, used as a map key.
    InvalidRedactedKey,
    /// A map key that is neither int, text, nor tag 58 / 62.
    InvalidMapKey,
    /// Tag 58 or 62 used as a map *value*; it only marks keys and elements.
    TagOnMapValue(u64),
    /// A to-be-decoy tag whose content is not an unsigned integer > 0, or a
    /// decoy map entry whose value is not `null` (§11.2).
    InvalidDecoy,
    /// The same decoy number used twice in the claims set (§11.2).
    DuplicateDecoy(u64),
}

impl fmt::Display for CoseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CoseError {}

impl From<DecodeError> for CoseError {
    fn from(e: DecodeError) -> Self {
        CoseError::Cbor(e)
    }
}

impl From<EncodeError> for CoseError {
    fn from(e: EncodeError) -> Self {
        CoseError::Encode(e)
    }
}

impl From<CryptoError> for CoseError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::InvalidSignature => CoseError::InvalidSignature,
            CryptoError::KeyNotSuitable { alg, mismatches } => {
                CoseError::KeyNotSuitable { alg, mismatches }
            }
            other => CoseError::Crypto(other),
        }
    }
}

impl From<KeyError> for CoseError {
    fn from(e: KeyError) -> Self {
        CoseError::Key(e)
    }
}

impl From<RedactionError> for CoseError {
    fn from(e: RedactionError) -> Self {
        CoseError::Redaction(e)
    }
}
