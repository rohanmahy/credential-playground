//! [`JoseError`].

use core::fmt;

use tokenator_crypto::CryptoError;
use tokenator_keys::KeyError;

use crate::parse::{ParseError, PartError, PartRef};

/// Errors from building and manipulating tokens.
///
/// Parsing reports per-part problems as diagnostics and verification
/// returns structured results; this type is for operations that cannot
/// produce an output at all.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JoseError {
    /// The input token could not be parsed.
    Parse(ParseError),
    /// A part the operation needs could not be decoded.
    Part {
        /// Which part.
        part: PartRef,
        /// Why.
        error: PartError,
    },
    /// The operation needs a JSON object (header or payload) and got
    /// something else.
    NotAnObject(PartRef),
    /// Signing needs a private key.
    NoPrivateKey,
    /// Signing failed (e.g. the key does not fit the algorithm).
    Crypto(CryptoError),
    /// A key could not be used (e.g. a `cnf` JWK that does not import).
    Key(KeyError),
    /// The protected header has no usable `alg` for signing: missing, not
    /// a string, `none`, or unsupported (the value, if a string).
    UnusableAlg(Option<String>),
    /// A JSON pointer that does not name a member or element of the claims.
    NoSuchClaim(String),
    /// A pointer that cannot be made selectively disclosable: the root, or
    /// anything named `_sd`, `_sd_alg`, or `...`.
    InvalidSdPath(String),
    /// A decoy target that is not an object or array.
    InvalidDecoyTarget(String),
    /// A generated member would collide with one in the input (`cnf`,
    /// `_sd_alg`, or `_sd`), at this pointer.
    ClaimConflict(String),
    /// [`SaltSource::Fixed`](crate::SaltSource::Fixed) ran out of salts.
    SaltsExhausted,
    /// A disclosure index out of range.
    NoSuchDisclosure(usize),
    /// A signature index out of range.
    NoSuchSignature(usize),
    /// A bit, byte, or length out of range for the part or token.
    OutOfRange,
    /// The operation needs the payload's `_sd_alg` hash, which is not
    /// supported (the value, or `None` if not a string).
    UnsupportedSdAlg(Option<String>),
    /// The operation needs an SD-JWT.
    NotSdJwt,
    /// The operation needs compact serialization.
    NotCompact,
    /// A JSON serialization without a protected header cannot become compact.
    NoProtectedHeader,
    /// A general JSON serialization with several signatures cannot become
    /// compact or flattened.
    MultipleSignatures,
}

impl fmt::Display for JoseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for JoseError {}

impl From<CryptoError> for JoseError {
    fn from(e: CryptoError) -> Self {
        JoseError::Crypto(e)
    }
}

impl From<KeyError> for JoseError {
    fn from(e: KeyError) -> Self {
        JoseError::Key(e)
    }
}

impl From<ParseError> for JoseError {
    fn from(e: ParseError) -> Self {
        JoseError::Parse(e)
    }
}
