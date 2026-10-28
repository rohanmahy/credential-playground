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

use tokenator_cbor::{EncodeMode, Item, Value, encode};

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
        f.write_str(match self {
            DateTimeError::Syntax => "not an RFC 3339 date/time",
            DateTimeError::InvalidDate => "no such date or time",
            DateTimeError::OutOfRange => "date/time out of range",
            DateTimeError::NotFinite => "epoch is NaN or infinite",
            DateTimeError::UnsupportedItem => "not a date/time item",
        })
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
        let f = match value {
            EpochValue::Int(secs) => return Ok(Instant { secs, nanos: 0 }),
            EpochValue::Float(f) => f,
        };
        if !f.is_finite() {
            return Err(DateTimeError::NotFinite);
        }
        // i64 seconds; the bounds are exact binary64 values.
        if !(-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&f) {
            return Err(DateTimeError::OutOfRange);
        }
        let floor = f.floor();
        // `f - floor` is exact; only the scaling rounds.
        let nanos = ((f - floor) * 1e9).round();
        let mut secs = floor as i64;
        let mut nanos = nanos as u32;
        if nanos >= NANOS {
            nanos -= NANOS;
            secs = secs.checked_add(1).ok_or(DateTimeError::OutOfRange)?;
        }
        Ok(Instant { secs, nanos })
    }

    /// From epoch milliseconds.
    pub fn from_millis(millis: i64) -> Instant {
        Instant {
            secs: millis.div_euclid(1000),
            nanos: millis.rem_euclid(1000).unsigned_abs() as u32 * 1_000_000,
        }
    }

    /// Epoch milliseconds (floor), or `None` if it overflows `i64`.
    pub fn millis(&self) -> Option<i64> {
        self.secs
            .checked_mul(1000)?
            .checked_add(i64::from(self.nanos / 1_000_000))
    }

    /// Epoch seconds: [`EpochValue::Int`] when there is no fraction,
    /// otherwise the binary64 nearest to the exact decimal value.
    pub fn epoch(&self) -> EpochValue {
        if self.nanos == 0 {
            EpochValue::Int(self.secs)
        } else {
            EpochValue::Float(self.to_f64())
        }
    }

    /// Parses RFC 3339 `date-time` (any offset).
    pub fn parse_rfc3339(text: &str) -> Result<Instant, DateTimeError> {
        let b = text.as_bytes();
        let date = b.get(..10).ok_or(DateTimeError::Syntax)?;
        let days = parse_full_date(date)?;
        if !matches!(b.get(10), Some(b'T' | b't')) {
            return Err(DateTimeError::Syntax);
        }
        let time = b.get(11..19).ok_or(DateTimeError::Syntax)?;
        let (hour, minute, second) = match time {
            [h1, h2, b':', m1, m2, b':', s1, s2] => {
                (digits2(*h1, *h2)?, digits2(*m1, *m2)?, digits2(*s1, *s2)?)
            }
            _ => return Err(DateTimeError::Syntax),
        };
        let mut rest = b.get(19..).unwrap_or_default();
        let mut nanos = 0u32;
        if let [b'.', tail @ ..] = rest {
            let n = tail.iter().take_while(|c| c.is_ascii_digit()).count();
            if n == 0 {
                return Err(DateTimeError::Syntax);
            }
            let mut scale = NANOS;
            for &d in tail.iter().take(n.min(9)) {
                scale /= 10;
                nanos += u32::from(d - b'0') * scale;
            }
            rest = tail.get(n..).unwrap_or_default();
        }
        let offset = match rest {
            [b'Z' | b'z'] => 0,
            [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
                let (h, m) = (digits2(*h1, *h2)?, digits2(*m1, *m2)?);
                if h > 23 || m > 59 {
                    return Err(DateTimeError::InvalidDate);
                }
                let off = i64::from(h * 60 + m) * 60;
                if *sign == b'-' { -off } else { off }
            }
            _ => return Err(DateTimeError::Syntax),
        };
        let days = days?;
        if hour > 23 || minute > 59 || second > 60 {
            return Err(DateTimeError::InvalidDate);
        }
        let secs = days * 86_400 + i64::from(hour * 3600 + minute * 60 + second) - offset;
        Ok(Instant { secs, nanos })
    }

    /// RFC 3339 in UTC with `Z`. Fractional seconds use as few digits as
    /// needed (none when `nanos` is 0): `2013-03-21T20:04:00.5Z`.
    pub fn to_rfc3339(&self) -> Result<String, DateTimeError> {
        self.format(0, "Z")
    }

    /// RFC 3339 shifted to the given offset east of UTC, in minutes
    /// (`+02:00` for 120, `-05:30` for -330, `Z` never used: 0 is `+00:00`).
    /// The caller supplies the local offset; this module has no time zones.
    pub fn to_rfc3339_with_offset(&self, offset_minutes: i32) -> Result<String, DateTimeError> {
        if offset_minutes.unsigned_abs() > 23 * 60 + 59 {
            return Err(DateTimeError::InvalidDate);
        }
        let sign = if offset_minutes < 0 { '-' } else { '+' };
        let abs = offset_minutes.unsigned_abs();
        let suffix = format!("{sign}{:02}:{:02}", abs / 60, abs % 60);
        self.format(i64::from(offset_minutes) * 60, &suffix)
    }

    /// Midnight UTC of `days` days after 1970-01-01 (tag 100).
    pub fn from_days(days: i64) -> Instant {
        Instant {
            secs: days.saturating_mul(86_400),
            nanos: 0,
        }
    }

    /// Days since 1970-01-01 of the UTC date (floor; tag 100).
    pub fn days(&self) -> i64 {
        self.secs.div_euclid(86_400)
    }

    /// Parses RFC 3339 `full-date` (`YYYY-MM-DD`, tag 1004) as midnight UTC.
    pub fn parse_date(text: &str) -> Result<Instant, DateTimeError> {
        let days = parse_full_date(text.as_bytes())??;
        Ok(Instant::from_days(days))
    }

    /// The UTC date as `YYYY-MM-DD` (tag 1004).
    pub fn to_date(&self) -> Result<String, DateTimeError> {
        let (y, m, d) = civil_from_days(self.days());
        if !(0..=9999).contains(&y) {
            return Err(DateTimeError::OutOfRange);
        }
        Ok(format!("{y:04}-{m:02}-{d:02}"))
    }

    /// Reads tag 0 (text), tag 1 (int or float), tag 100 (int), tag 1004
    /// (text), or an untagged int/float (epoch) or text (RFC 3339). Tag
    /// contents of the wrong type are [`DateTimeError::UnsupportedItem`].
    pub fn from_item(item: &Item<'_>) -> Result<Instant, DateTimeError> {
        let epoch = |item: &Item<'_>| match &item.value {
            Value::Uint(n) => i64::try_from(*n)
                .map(EpochValue::Int)
                .map_err(|_| DateTimeError::OutOfRange),
            Value::Nint(n) => i64::try_from(*n)
                .map(|n| EpochValue::Int(-1 - n))
                .map_err(|_| DateTimeError::OutOfRange),
            Value::Float(f, _) => Ok(EpochValue::Float(*f)),
            _ => Err(DateTimeError::UnsupportedItem),
        };
        let text = |item: &Item<'_>| match &item.value {
            Value::Text(t) => Ok(t.to_string()),
            _ => Err(DateTimeError::UnsupportedItem),
        };
        match &item.value {
            Value::Tag(0, inner) => Instant::parse_rfc3339(&text(inner)?),
            Value::Tag(1, inner) => Instant::from_epoch(epoch(inner)?),
            Value::Tag(100, inner) => match epoch(inner)? {
                EpochValue::Int(days) => Ok(Instant::from_days(days)),
                EpochValue::Float(_) => Err(DateTimeError::UnsupportedItem),
            },
            Value::Tag(1004, inner) => Instant::parse_date(&text(inner)?),
            Value::Text(t) => Instant::parse_rfc3339(t),
            Value::Uint(_) | Value::Nint(_) | Value::Float(..) => Instant::from_epoch(epoch(item)?),
            _ => Err(DateTimeError::UnsupportedItem),
        }
    }

    /// Builds the item for `form` with preferred serialization.
    /// [`DateForm::Dt`] gives the same item as [`DateForm::Epoch`], and
    /// [`DateForm::DtTagged`] the same as [`DateForm::Tag1`].
    pub fn to_item(&self, form: DateForm) -> Result<Item<'static>, DateTimeError> {
        let epoch = || match self.epoch() {
            EpochValue::Int(n) => Item::int(n),
            EpochValue::Float(f) => Item::float(f),
        };
        Ok(match form {
            DateForm::Epoch | DateForm::Dt => epoch(),
            DateForm::Tag1 | DateForm::DtTagged => Item::tag(1, epoch()),
            DateForm::Rfc3339 => Item::text(self.to_rfc3339()?),
            DateForm::Tag0 => Item::tag(0, Item::text(self.to_rfc3339()?)),
            DateForm::Tag100 => Item::tag(100, Item::int(self.days())),
            DateForm::Tag1004 => Item::tag(1004, Item::text(self.to_date()?)),
        })
    }

    /// Compact EDN for `form`: `1(1363896240)`, `dt'2013-03-21T20:04:00Z'`,
    /// `DT'2013-03-21T20:04:00Z'`, `1004("2013-03-21")`, …
    pub fn to_edn(&self, form: DateForm) -> Result<String, DateTimeError> {
        Ok(match form {
            DateForm::Dt => format!("dt'{}'", self.to_rfc3339()?),
            DateForm::DtTagged => format!("DT'{}'", self.to_rfc3339()?),
            _ => crate::print(&self.to_item(form)?, &crate::PrintOptions::new()).text,
        })
    }

    /// Every form in [`DateForm::ALL`] order, skipping none: fails if any
    /// form cannot represent this instant.
    pub fn forms(&self) -> Result<Vec<DateTimeForm>, DateTimeError> {
        DateForm::ALL
            .iter()
            .map(|&form| {
                Ok(DateTimeForm {
                    form,
                    edn: self.to_edn(form)?,
                    cbor: encode(&self.to_item(form)?, EncodeMode::Preserve),
                })
            })
            .collect()
    }
}

const NANOS: u32 = 1_000_000_000;

impl Instant {
    /// The binary64 nearest to `secs + nanos / 1e9`.
    pub(crate) fn to_f64(self) -> f64 {
        let total = i128::from(self.secs) * i128::from(NANOS) + i128::from(self.nanos);
        let sign = if total < 0 { "-" } else { "" };
        let abs = total.unsigned_abs();
        let n = u128::from(NANOS);
        // Decimal parsing is correctly rounded.
        format!("{sign}{}.{:09}", abs / n, abs % n)
            .parse()
            .unwrap_or(f64::NAN)
    }

    /// RFC 3339 text of this instant shifted by `shift` seconds, with
    /// `suffix` as the offset.
    fn format(&self, shift: i64, suffix: &str) -> Result<String, DateTimeError> {
        let secs = self
            .secs
            .checked_add(shift)
            .ok_or(DateTimeError::OutOfRange)?;
        let (y, mo, d) = civil_from_days(secs.div_euclid(86_400));
        if !(0..=9999).contains(&y) {
            return Err(DateTimeError::OutOfRange);
        }
        let tod = secs.rem_euclid(86_400);
        let mut out = format!(
            "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}",
            tod / 3600,
            tod / 60 % 60,
            tod % 60
        );
        if self.nanos > 0 {
            let frac = format!("{:09}", self.nanos);
            out.push('.');
            out.push_str(frac.trim_end_matches('0'));
        }
        out.push_str(suffix);
        Ok(out)
    }
}

/// Two ASCII digits as a number.
fn digits2(a: u8, b: u8) -> Result<u32, DateTimeError> {
    if a.is_ascii_digit() && b.is_ascii_digit() {
        Ok(u32::from(a - b'0') * 10 + u32::from(b - b'0'))
    } else {
        Err(DateTimeError::Syntax)
    }
}

/// `YYYY-MM-DD` as days since 1970-01-01. The outer error is a syntax error;
/// the inner one (reported after the rest of the syntax is checked) is an
/// invalid date.
fn parse_full_date(b: &[u8]) -> Result<Result<i64, DateTimeError>, DateTimeError> {
    let [y1, y2, y3, y4, b'-', m1, m2, b'-', d1, d2] = b else {
        return Err(DateTimeError::Syntax);
    };
    let year = digits2(*y1, *y2)? * 100 + digits2(*y3, *y4)?;
    let (month, day) = (digits2(*m1, *m2)?, digits2(*d1, *d2)?);
    let year = i64::from(year);
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return Ok(Err(DateTimeError::InvalidDate));
    }
    Ok(Ok(days_from_civil(year, month, day)))
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's
/// algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The proleptic Gregorian date of a day number (inverse of
/// [`days_from_civil`]).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}
