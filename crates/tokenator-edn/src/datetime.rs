//! Pure date/time conversions for the date/time chit (SPEC §4.3).
//!
//! An [`Instant`] converts between epoch seconds (integer or fractional),
//! milliseconds, RFC 3339 text, CBOR tags 0 and 1 (RFC 8949 §3.4), tags 100
//! and 1004 (RFC 8943, days since 1970-01-01 and `YYYY-MM-DD`), and their EDN
//! forms including `dt'…'` and `DT'…'`. There is no clock here: "now" comes
//! from the caller.
//!
//! Decisions: offsets are normalized to UTC; lowercase `t`/`z` are accepted;
//! a leap second (`:60`) maps to the following second; years are 0000–9999
//! for text forms; fraction digits beyond nanoseconds are truncated; float
//! epochs round to the nearest nanosecond.

use std::fmt;

use tokenator_cbor::Item;

/// Why a conversion failed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DateTimeError {
    /// Text that is not RFC 3339 `date-time` (or `full-date` where a date is
    /// expected).
    Syntax,
    /// Well-formed text naming a date or time that does not exist (month 13,
    /// February 30, hour 24, minute 60, offset beyond ±23:59).
    InvalidDate,
    /// Outside what the target form can hold (years outside 0000–9999,
    /// epochs beyond `i64` seconds).
    OutOfRange,
    /// A NaN or infinite epoch.
    NotFinite,
    /// An item that is not a date/time form this module understands.
    UnsupportedItem,
}

impl fmt::Display for DateTimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unimplemented!()
    }
}

impl std::error::Error for DateTimeError {}

/// Epoch seconds as CBOR would carry them.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum EpochValue {
    /// Whole seconds.
    Int(i64),
    /// Fractional seconds.
    Float(f64),
}

/// A representation the chit can show or insert.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DateForm {
    /// Bare epoch seconds (int, or float with a fraction): `1363896240`.
    Epoch,
    /// Tag 1 around epoch seconds: `1(1363896240)`.
    Tag1,
    /// Bare RFC 3339 text in UTC: `"2013-03-21T20:04:00Z"`.
    Rfc3339,
    /// Tag 0 around RFC 3339 text: `0("2013-03-21T20:04:00Z")`.
    Tag0,
    /// Tag 100 around days since 1970-01-01: `100(15785)`.
    Tag100,
    /// Tag 1004 around a full date: `1004("2013-03-21")`.
    Tag1004,
    /// `dt'…'`: the same item as [`DateForm::Epoch`].
    Dt,
    /// `DT'…'`: the same item as [`DateForm::Tag1`].
    DtTagged,
}

impl DateForm {
    /// Every form, in the order the chit lists them.
    pub const ALL: [DateForm; 8] = [
        DateForm::Epoch,
        DateForm::Tag1,
        DateForm::Rfc3339,
        DateForm::Tag0,
        DateForm::Tag100,
        DateForm::Tag1004,
        DateForm::Dt,
        DateForm::DtTagged,
    ];
}

/// One rendered form: its EDN text and its CBOR encoding.
#[derive(Clone, Debug, PartialEq)]
pub struct DateTimeForm {
    /// Which form.
    pub form: DateForm,
    /// EDN text (compact).
    pub edn: String,
    /// Preferred-serialization CBOR bytes.
    pub cbor: Vec<u8>,
}

/// A point in time: seconds since 1970-01-01T00:00:00Z plus nanoseconds.
///
/// `nanos` is always in `0..1_000_000_000` and counts forward from `secs`,
/// so -1.5 seconds is `secs: -2, nanos: 500_000_000`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant {
    secs: i64,
    nanos: u32,
}

impl Instant {
    /// From whole seconds and nanoseconds; `None` if `nanos >= 1e9`.
    pub fn new(secs: i64, nanos: u32) -> Option<Instant> {
        (nanos < 1_000_000_000).then_some(Instant { secs, nanos })
    }

    /// Whole seconds (floor).
    pub fn secs(&self) -> i64 {
        self.secs
    }

    /// Nanoseconds after [`Instant::secs`].
    pub fn nanos(&self) -> u32 {
        self.nanos
    }

    /// From epoch seconds. Floats round to the nearest nanosecond.
    pub fn from_epoch(value: EpochValue) -> Result<Instant, DateTimeError> {
        unimplemented!()
    }

    /// From epoch milliseconds.
    pub fn from_millis(millis: i64) -> Instant {
        unimplemented!()
    }

    /// Epoch milliseconds (floor), or `None` if it overflows `i64`.
    pub fn millis(&self) -> Option<i64> {
        unimplemented!()
    }

    /// Epoch seconds: [`EpochValue::Int`] when there is no fraction,
    /// otherwise the binary64 nearest to the exact decimal value.
    pub fn epoch(&self) -> EpochValue {
        unimplemented!()
    }

    /// Parses RFC 3339 `date-time` (any offset).
    pub fn parse_rfc3339(text: &str) -> Result<Instant, DateTimeError> {
        unimplemented!()
    }

    /// RFC 3339 in UTC with `Z`. Fractional seconds use as few digits as
    /// needed (none when `nanos` is 0): `2013-03-21T20:04:00.5Z`.
    pub fn to_rfc3339(&self) -> Result<String, DateTimeError> {
        unimplemented!()
    }

    /// RFC 3339 shifted to the given offset east of UTC, in minutes
    /// (`+02:00` for 120, `-05:30` for -330, `Z` never used: 0 is `+00:00`).
    /// The caller supplies the local offset; this module has no time zones.
    pub fn to_rfc3339_with_offset(&self, offset_minutes: i32) -> Result<String, DateTimeError> {
        unimplemented!()
    }

    /// Midnight UTC of `days` days after 1970-01-01 (tag 100).
    pub fn from_days(days: i64) -> Instant {
        unimplemented!()
    }

    /// Days since 1970-01-01 of the UTC date (floor; tag 100).
    pub fn days(&self) -> i64 {
        unimplemented!()
    }

    /// Parses RFC 3339 `full-date` (`YYYY-MM-DD`, tag 1004) as midnight UTC.
    pub fn parse_date(text: &str) -> Result<Instant, DateTimeError> {
        unimplemented!()
    }

    /// The UTC date as `YYYY-MM-DD` (tag 1004).
    pub fn to_date(&self) -> Result<String, DateTimeError> {
        unimplemented!()
    }

    /// Reads tag 0 (text), tag 1 (int or float), tag 100 (int), tag 1004
    /// (text), or an untagged int/float (epoch) or text (RFC 3339). Tag
    /// contents of the wrong type are [`DateTimeError::UnsupportedItem`].
    pub fn from_item(item: &Item<'_>) -> Result<Instant, DateTimeError> {
        unimplemented!()
    }

    /// Builds the item for `form` with preferred serialization.
    /// [`DateForm::Dt`] gives the same item as [`DateForm::Epoch`], and
    /// [`DateForm::DtTagged`] the same as [`DateForm::Tag1`].
    pub fn to_item(&self, form: DateForm) -> Result<Item<'static>, DateTimeError> {
        unimplemented!()
    }

    /// Compact EDN for `form`: `1(1363896240)`, `dt'2013-03-21T20:04:00Z'`,
    /// `DT'2013-03-21T20:04:00Z'`, `1004("2013-03-21")`, …
    pub fn to_edn(&self, form: DateForm) -> Result<String, DateTimeError> {
        unimplemented!()
    }

    /// Every form in [`DateForm::ALL`] order, skipping none: fails if any
    /// form cannot represent this instant.
    pub fn forms(&self) -> Result<Vec<DateTimeForm>, DateTimeError> {
        unimplemented!()
    }
}
