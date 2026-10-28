//! CWT claims (RFC 8392): lookup, time claims, and `cnf` (RFC 8747).
#![allow(clippy::unimplemented)]

use std::borrow::Cow;

use tokenator_cbor::Item;
use tokenator_keys::{CoseKey, Key, Label};

use crate::CoseError;

/// The value of claim `key` in a claims map (the first entry with that key;
/// keys compare by value, so `0x18 0x01` finds claim 1).
pub fn claim<'i, 'a>(claims: &'i Item<'a>, key: &Label) -> Option<&'i Item<'a>> {
    let _ = (claims, key);
    unimplemented!()
}

/// An RFC 8392 NumericDate.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NumericDate {
    /// An integer number of seconds.
    Int(i64),
    /// A floating-point number of seconds.
    Float(f64),
}

impl NumericDate {
    /// The value as `f64` seconds.
    pub fn as_f64(self) -> f64 {
        unimplemented!()
    }
}

/// Why a time claim is not a usable NumericDate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeError {
    /// Not an integer or float (text, bytes, a tagged date, ...).
    WrongType,
    /// NaN or ±infinity (sd-cwt-08 §5.2).
    NotFinite,
    /// An integer outside `i64`, or a float beyond ±2^53 (sd-cwt-08 §5.2).
    OutOfRange,
}

/// Reads a NumericDate: an untagged int or float (RFC 8392 §2).
pub fn numeric_date(item: &Item<'_>) -> Result<NumericDate, TimeError> {
    let _ = item;
    unimplemented!()
}

/// The clock for time checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeOptions {
    /// Current time, in seconds since the epoch.
    pub now: i64,
    /// Allowed clock skew in seconds (SPEC default 60).
    pub skew: u64,
}

/// The outcome of one time claim check.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TimeStatus {
    /// Within bounds.
    Ok(NumericDate),
    /// `exp`: `now >= exp + skew`.
    Expired(NumericDate),
    /// `nbf`: `now + skew < nbf`.
    NotYetValid(NumericDate),
    /// `iat`: `iat > now + skew`.
    IssuedInFuture(NumericDate),
    /// Not a usable NumericDate.
    Invalid(TimeError),
}

/// Results for `exp`, `nbf`, and `iat`; `None` when the claim is absent.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TimeReport {
    /// `exp` (4).
    pub exp: Option<TimeStatus>,
    /// `nbf` (5).
    pub nbf: Option<TimeStatus>,
    /// `iat` (6).
    pub iat: Option<TimeStatus>,
}

impl TimeReport {
    /// True when every present claim is [`TimeStatus::Ok`].
    pub fn is_ok(&self) -> bool {
        unimplemented!()
    }
}

/// Checks `exp`, `nbf`, and `iat` in a claims map against the clock.
pub fn check_times(claims: &Item<'_>, opts: &TimeOptions) -> TimeReport {
    let _ = (claims, opts);
    unimplemented!()
}

/// A confirmation method from a `cnf` claim (RFC 8747 §3).
#[derive(Debug, Clone, PartialEq)]
pub enum Cnf<'a> {
    /// `1`: a COSE_Key.
    CoseKey(CoseKey),
    /// `2`: an Encrypted_COSE_Key (kept, not decrypted).
    EncryptedCoseKey(Item<'a>),
    /// `3`: a key identifier.
    Kid(Cow<'a, [u8]>),
    /// `5`: a COSE Key Thumbprint (RFC 9679, SHA-256).
    Thumbprint(Cow<'a, [u8]>),
    /// Any other method.
    Other(Label, Item<'a>),
}

/// Parses the value of a `cnf` claim: a map with exactly one method.
/// Fails with [`CoseError::Cnf`] when it is not a map, is empty, has more
/// than one entry, or a known method has the wrong type.
pub fn parse_cnf<'a>(cnf: &Item<'a>) -> Result<Cnf<'a>, CoseError> {
    let _ = cnf;
    unimplemented!()
}

/// The key a confirmation method names.
///
/// A COSE_Key is converted with `tokenator_keys::from_cwk` (and need not be
/// in `candidates`). A kid matches a candidate whose `kid` has the same
/// bytes; a thumbprint matches a candidate whose SHA-256 COSE thumbprint is
/// equal. Returns `Ok(None)` when nothing matches.
pub fn resolve_cnf(cnf: &Cnf<'_>, candidates: &[Key]) -> Result<Option<Key>, CoseError> {
    let _ = (cnf, candidates);
    unimplemented!()
}
