//! Verification primitives. The core composes them into the user-facing
//! validation report.

use tokenator_crypto::{Alg, CryptoError};
use tokenator_json::Node;
use tokenator_keys::{Key, KeyError};

use crate::b64::B64Error;
use crate::parse::{Jws, SdJwt};

/// Why a signature did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyError {
    /// No signature with that index.
    NoSuchSignature(usize),
    /// No key to verify with (e.g. a KB-JWT whose `cnf` gave none).
    NoKey,
    /// The protected header (or, without one, the unprotected header) does
    /// not decode or is not a JSON object.
    HeaderUnreadable,
    /// No `alg` in the protected or unprotected header.
    MissingAlg,
    /// `alg` is not a string.
    AlgNotString,
    /// `alg` is `none` (RFC 7518 §3.6). Never accepted.
    AlgNone,
    /// `alg` is a string this crate does not support (e.g. `HS256`).
    UnsupportedAlg(String),
    /// The signature's base64url does not decode.
    SignatureUnreadable(B64Error),
    /// `tokenator-crypto` refused: [`CryptoError::InvalidSignature`] for a
    /// bad signature, [`CryptoError::KeyNotSuitable`] for a key that does
    /// not fit `alg`.
    Crypto(CryptoError),
}

/// Verifies signature `index` of `jws` with `key` (public or private).
///
/// `alg` comes from the protected header, or else from the unprotected
/// header (JSON serialization). The signing input is the original encoded
/// text, so any change to the header or payload bytes fails. Returns the
/// algorithm used.
pub fn verify_signature(jws: &Jws<'_>, index: usize, key: &Key) -> Result<Alg, VerifyError> {
    unimplemented!()
}

/// The status of one time claim (NumericDate seconds; fractions allowed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeStatus {
    /// The claim is absent.
    Absent,
    /// Present and acceptable.
    Valid,
    /// `exp`: `now >= exp + skew`.
    Expired,
    /// `nbf`: `now + skew < nbf`.
    NotYetValid,
    /// `iat`: `iat > now + skew`.
    InFuture,
    /// `iat` with a maximum age: `now > iat + max_age + skew`.
    TooOld,
    /// Present but not a JSON number.
    NotANumber,
}

/// `exp`, `nbf`, and `iat` of a claim set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeReport {
    /// `exp` (RFC 7519 §4.1.4).
    pub exp: TimeStatus,
    /// `nbf` (RFC 7519 §4.1.5).
    pub nbf: TimeStatus,
    /// `iat` (RFC 7519 §4.1.6): only checked for being in the future.
    pub iat: TimeStatus,
}

/// Checks the time claims of `claims` (a top-level object) against the
/// injected clock `now` with `skew` seconds of tolerance.
pub fn check_time_claims(claims: &Node<'_>, now: i64, skew: u64) -> TimeReport {
    unimplemented!()
}

/// What the verifier expects of a KB-JWT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KbExpectations<'e> {
    /// Expected `aud`; `None` reports the value unchecked.
    pub aud: Option<&'e str>,
    /// Expected `nonce`; `None` reports the value unchecked.
    pub nonce: Option<&'e str>,
    /// The clock.
    pub now: i64,
    /// Allowed skew in seconds.
    pub skew: u64,
    /// Maximum age of `iat` in seconds; `None` only checks for the future.
    pub max_age: Option<u64>,
}

/// The outcome of comparing one string-valued item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueCheck {
    /// Equal to the expected value.
    Match,
    /// Different from the expected value.
    Mismatch {
        /// What was expected.
        expected: String,
        /// What was found.
        found: String,
    },
    /// Present, but nothing was expected.
    Unchecked(String),
    /// Absent.
    Missing,
    /// Present but not a string.
    NotAString,
}

/// Where the holder key for the KB-JWT came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HolderKey {
    /// `cnf.jwk` of the issuer payload (an untrusted embedded key).
    CnfJwk,
    /// `cnf.kid`, matched by the candidate at this index (its kid as a
    /// JOSE string equals the `cnf.kid` string).
    CnfKid {
        /// The kid.
        kid: String,
        /// Index into the candidates.
        candidate: usize,
    },
    /// `cnf.kid` that no candidate matches.
    CnfKidUnmatched(String),
    /// `cnf.jwk` that does not import.
    CnfJwkInvalid(KeyError),
    /// No `cnf`, or `cnf` without `jwk` or `kid` (e.g. only `jku` or
    /// `jkt`, reported by member name).
    NoCnf(Vec<String>),
}

/// The checks on a KB-JWT (RFC 9901 §7.3 step 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KbReport {
    /// The key the signature was checked with.
    pub holder_key: HolderKey,
    /// Signature check; [`VerifyError::NoKey`] if there was no key.
    pub signature: Result<Alg, VerifyError>,
    /// Header `typ` against `kb+jwt`.
    pub typ: ValueCheck,
    /// `sd_hash` against the hash (with the issuer payload's `_sd_alg`) of
    /// [`SdJwt::sd_hash_input`]. `Mismatch.expected` is the computed value.
    pub sd_hash: ValueCheck,
    /// `aud`.
    pub aud: ValueCheck,
    /// `nonce`.
    pub nonce: ValueCheck,
    /// `iat` freshness: [`TimeStatus::InFuture`], [`TimeStatus::TooOld`],
    /// [`TimeStatus::Absent`] (it is required), ...
    pub iat: TimeStatus,
}

/// Checks the KB-JWT of `sd`, or returns `None` if it has none.
///
/// The holder key is `cnf.jwk` from the issuer payload, or the candidate
/// whose kid equals `cnf.kid`. Candidates are not consulted when `cnf.jwk`
/// is present.
pub fn check_kb_jwt(
    sd: &SdJwt<'_>,
    candidates: &[Key],
    expect: &KbExpectations<'_>,
) -> Option<KbReport> {
    unimplemented!()
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for VerifyError {}
