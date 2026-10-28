//! CWT claims (RFC 8392): lookup, time claims, and `cnf` (RFC 8747).
use std::borrow::Cow;
use std::cmp::Ordering;

use tokenator_cbor::{Item, Value};
use tokenator_crypto::HashAlg;
use tokenator_keys::{CoseKey, Key, Label, ThumbprintKind, from_cwk, thumbprint};

use crate::CoseError;
use crate::codepoints::{
    CLAIM_EXP, CLAIM_IAT, CLAIM_NBF, CNF_CKT, CNF_COSE_KEY, CNF_ENCRYPTED_COSE_KEY, CNF_KID,
};
use crate::util::{entries, label_eq, label_of};

/// The value of claim `key` in a claims map (the first entry with that key;
/// keys compare by value, so `0x18 0x01` finds claim 1).
pub fn claim<'i, 'a>(claims: &'i Item<'a>, key: &Label) -> Option<&'i Item<'a>> {
    entries(claims)?
        .iter()
        .find(|(k, _)| label_eq(k, key))
        .map(|(_, v)| v)
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
        match self {
            NumericDate::Int(n) => n as f64,
            NumericDate::Float(f) => f,
        }
    }

    /// Compares the date with `t` seconds (exact for integers).
    pub(crate) fn cmp_secs(self, t: i128) -> Ordering {
        match self {
            NumericDate::Int(n) => i128::from(n).cmp(&t),
            NumericDate::Float(f) => f.partial_cmp(&(t as f64)).unwrap_or(Ordering::Equal),
        }
    }

    /// Compares two dates (exact when both are integers).
    pub(crate) fn cmp_date(self, other: NumericDate) -> Ordering {
        match (self, other) {
            (NumericDate::Int(a), NumericDate::Int(b)) => a.cmp(&b),
            (a, b) => a
                .as_f64()
                .partial_cmp(&b.as_f64())
                .unwrap_or(Ordering::Equal),
        }
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
    /// 2^53: the largest magnitude where every integer is a float.
    const MAX_FLOAT: f64 = 9_007_199_254_740_992.0;
    match item.value {
        Value::Uint(n) => i64::try_from(n)
            .map(NumericDate::Int)
            .map_err(|_| TimeError::OutOfRange),
        // -1 - n == !n
        Value::Nint(n) => i64::try_from(n)
            .map(|n| NumericDate::Int(!n))
            .map_err(|_| TimeError::OutOfRange),
        Value::Float(f, _) if !f.is_finite() => Err(TimeError::NotFinite),
        Value::Float(f, _) if f.abs() > MAX_FLOAT => Err(TimeError::OutOfRange),
        Value::Float(f, _) => Ok(NumericDate::Float(f)),
        _ => Err(TimeError::WrongType),
    }
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
        [self.exp, self.nbf, self.iat]
            .iter()
            .all(|s| matches!(s, None | Some(TimeStatus::Ok(_))))
    }
}

/// Checks `exp`, `nbf`, and `iat` in a claims map against the clock.
pub fn check_times(claims: &Item<'_>, opts: &TimeOptions) -> TimeReport {
    let now = i128::from(opts.now);
    let skew = i128::from(opts.skew);
    let exp = claim(claims, &Label::Int(CLAIM_EXP)).map(|v| match numeric_date(v) {
        Err(e) => TimeStatus::Invalid(e),
        // now >= exp + skew  <=>  exp <= now - skew
        Ok(d) if d.cmp_secs(now - skew) != Ordering::Greater => TimeStatus::Expired(d),
        Ok(d) => TimeStatus::Ok(d),
    });
    let after_now = |d: NumericDate| d.cmp_secs(now + skew) == Ordering::Greater;
    let nbf = claim(claims, &Label::Int(CLAIM_NBF)).map(|v| match numeric_date(v) {
        Err(e) => TimeStatus::Invalid(e),
        Ok(d) if after_now(d) => TimeStatus::NotYetValid(d),
        Ok(d) => TimeStatus::Ok(d),
    });
    let iat = claim(claims, &Label::Int(CLAIM_IAT)).map(|v| match numeric_date(v) {
        Err(e) => TimeStatus::Invalid(e),
        Ok(d) if after_now(d) => TimeStatus::IssuedInFuture(d),
        Ok(d) => TimeStatus::Ok(d),
    });
    TimeReport { exp, nbf, iat }
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
    let [(key, value)] = entries(cnf).ok_or(CoseError::Cnf("cnf is not a map"))? else {
        return Err(CoseError::Cnf(
            "cnf must have exactly one confirmation method",
        ));
    };
    let label = label_of(key).ok_or(CoseError::Cnf("cnf method is not an int or text"))?;
    Ok(match label {
        Label::Int(CNF_COSE_KEY) => Cnf::CoseKey(
            CoseKey::from_item(value).map_err(|_| CoseError::Cnf("COSE_Key is not a map"))?,
        ),
        Label::Int(CNF_ENCRYPTED_COSE_KEY) => match value.value {
            Value::Array(_) | Value::Tag(..) => Cnf::EncryptedCoseKey(value.clone()),
            _ => return Err(CoseError::Cnf("Encrypted_COSE_Key is not a COSE message")),
        },
        Label::Int(CNF_KID) => match &value.value {
            Value::Bytes(b) => Cnf::Kid(b.clone()),
            _ => return Err(CoseError::Cnf("kid is not a byte string")),
        },
        Label::Int(CNF_CKT) => match &value.value {
            Value::Bytes(b) => Cnf::Thumbprint(b.clone()),
            _ => return Err(CoseError::Cnf("ckt is not a byte string")),
        },
        other => Cnf::Other(other, value.clone()),
    })
}

/// The key a confirmation method names.
///
/// A COSE_Key is converted with `tokenator_keys::from_cwk` (and need not be
/// in `candidates`). A kid matches a candidate whose `kid` has the same
/// bytes; a thumbprint matches a candidate whose SHA-256 COSE thumbprint is
/// equal. Returns `Ok(None)` when nothing matches.
pub fn resolve_cnf(cnf: &Cnf<'_>, candidates: &[Key]) -> Result<Option<Key>, CoseError> {
    Ok(match cnf {
        Cnf::CoseKey(cwk) => Some(from_cwk(cwk)?),
        Cnf::Kid(kid) => candidates
            .iter()
            .find(|k| k.kid.as_ref().is_some_and(|id| id.as_bytes() == &kid[..]))
            .cloned(),
        Cnf::Thumbprint(tp) => {
            // RFC 9679 thumbprints are SHA-256 here; accept the longer SHA-2
            // outputs by length as well.
            let hash = match tp.len() {
                48 => HashAlg::Sha384,
                64 => HashAlg::Sha512,
                _ => HashAlg::Sha256,
            };
            candidates
                .iter()
                .find(|k| thumbprint(k, ThumbprintKind::Cose, hash) == tp[..])
                .cloned()
        }
        Cnf::EncryptedCoseKey(_) | Cnf::Other(..) => None,
    })
}
