//! The date/time chit and inline time hints (SPEC §4.3).
//!
//! Conversions come from `tokenator_edn::datetime`; the relative strings
//! ("in 3 h 12 m", "2 d ago") are formatted here (#32).

use tokenator_cbor::Item;
use tokenator_edn::datetime::{DateForm, DateTimeError, Instant};

use crate::dto::datetime::{
    DateFormKind, DateTimeFormView, DateTimeForms, DateTimeInput, DateTimeRequest,
};
use crate::dto::document::TimeHint;
use crate::dto::error::{EngineError, ErrorCode};
use crate::util::{err, hex, unhex};

/// `"now"`, `"in 3 h 12 m"`, or `"2 d ago"` for `t` relative to `now`:
/// the largest non-zero unit of d/h/m/s, plus the next unit when it is
/// non-zero.
pub(crate) fn relative(t: i64, now: i64) -> String {
    let diff = i128::from(now) - i128::from(t);
    if diff == 0 {
        return "now".to_owned();
    }
    let mut rest = diff.unsigned_abs();
    let mut parts = Vec::with_capacity(4);
    for (size, unit) in [(86_400u128, "d"), (3_600, "h"), (60, "m"), (1, "s")] {
        parts.push((rest / size, unit));
        rest %= size;
    }
    let first = parts.iter().position(|(n, _)| *n > 0).unwrap_or(3);
    let mut text = String::new();
    for (i, (n, unit)) in parts.iter().enumerate().skip(first).take(2) {
        if i > first && *n == 0 {
            break;
        }
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(&format!("{n} {unit}"));
    }
    if diff > 0 {
        format!("{text} ago")
    } else {
        format!("in {text}")
    }
}

/// The inline hint for an instant.
pub(crate) fn hint(instant: Instant, now: Option<i64>) -> Option<TimeHint> {
    Some(TimeHint {
        epoch: instant.secs(),
        rfc3339: instant.to_rfc3339().ok()?,
        relative: now.map(|n| relative(instant.secs(), n)),
    })
}

/// The hint for a CBOR time item (epoch number, tag 0/1/100/1004).
pub(crate) fn cbor_hint(item: &Item<'_>, now: Option<i64>) -> Option<TimeHint> {
    hint(Instant::from_item(item).ok()?, now)
}

/// The hint for a JSON NumericDate lexeme.
pub(crate) fn json_hint(lexeme: &str, now: Option<i64>) -> Option<TimeHint> {
    let secs = match lexeme.parse::<i64>() {
        Ok(n) => n,
        Err(_) => {
            let f: f64 = lexeme.parse().ok()?;
            if !f.is_finite() {
                return None;
            }
            // Floor, within i64 (the conversion saturates).
            #[allow(clippy::cast_possible_truncation)]
            let secs = f.floor() as i64;
            secs
        }
    };
    hint(Instant::new(secs, 0)?, now)
}

fn dt_error(e: &DateTimeError) -> EngineError {
    EngineError::new(ErrorCode::DateTime, e.to_string())
}

/// Parses decimal epoch seconds exactly: `-?digits(.digits)?`.
fn parse_epoch(text: &str) -> Result<Instant, EngineError> {
    let bad = || EngineError::new(ErrorCode::DateTime, format!("not epoch seconds: {text:?}"));
    let t = text.trim();
    let (neg, digits) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t),
    };
    let (int, frac) = digits.split_once('.').unwrap_or((digits, ""));
    let all_digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if int.is_empty()
        || !all_digits(int)
        || !all_digits(frac)
        || (digits.contains('.') && frac.is_empty())
    {
        return Err(bad());
    }
    let whole: i64 = int.parse().map_err(|_| bad())?;
    let mut nanos: u32 = 0;
    for (i, b) in frac.bytes().take(9).enumerate() {
        let place = 10u32.pow(8 - u32::try_from(i).unwrap_or(8));
        nanos += u32::from(b - b'0') * place;
    }
    let (secs, nanos) = match (neg, nanos) {
        (false, n) => (whole, n),
        (true, 0) => (whole.checked_neg().ok_or_else(bad)?, 0),
        (true, n) => (
            whole
                .checked_neg()
                .and_then(|w| w.checked_sub(1))
                .ok_or_else(bad)?,
            1_000_000_000 - n,
        ),
    };
    Instant::new(secs, nanos).ok_or_else(bad)
}

/// Epoch seconds as text, the fraction only when non-zero.
fn epoch_text(i: Instant) -> String {
    if i.nanos() == 0 {
        return i.secs().to_string();
    }
    let frac = format!("{:09}", i.nanos());
    let frac = frac.trim_end_matches('0');
    if i.secs() >= 0 {
        format!("{}.{frac}", i.secs())
    } else {
        // secs + nanos/1e9 with secs negative: -(|secs| - 1).(1e9 - nanos)
        let whole = i.secs() + 1;
        let rest = format!("{:09}", 1_000_000_000 - i.nanos());
        let rest = rest.trim_end_matches('0');
        if whole == 0 {
            format!("-0.{rest}")
        } else {
            format!("{whole}.{rest}")
        }
    }
}

fn form_kind(f: DateForm) -> DateFormKind {
    match f {
        DateForm::Epoch => DateFormKind::Epoch,
        DateForm::Tag1 => DateFormKind::Tag1,
        DateForm::Rfc3339 => DateFormKind::Rfc3339,
        DateForm::Tag0 => DateFormKind::Tag0,
        DateForm::Tag100 => DateFormKind::Tag100,
        DateForm::Tag1004 => DateFormKind::Tag1004,
        DateForm::Dt => DateFormKind::Dt,
        DateForm::DtTagged => DateFormKind::DtTagged,
    }
}

fn instant_of(input: &DateTimeInput) -> Result<Instant, EngineError> {
    match input {
        DateTimeInput::Epoch { text } => parse_epoch(text),
        DateTimeInput::Millis { millis } => Ok(Instant::from_millis(*millis)),
        DateTimeInput::Rfc3339 { text } => Instant::parse_rfc3339(text).map_err(|e| dt_error(&e)),
        DateTimeInput::Date { text } => Instant::parse_date(text).map_err(|e| dt_error(&e)),
        DateTimeInput::Days { days } => Ok(Instant::from_days(*days)),
        DateTimeInput::Edn { text } => {
            let item = tokenator_edn::parse(text)
                .map_err(|e| EngineError::new(ErrorCode::DateTime, e.to_string()))?;
            Instant::from_item(&item).map_err(|e| dt_error(&e))
        }
        DateTimeInput::CborHex { hex } => {
            let Some(bytes) = unhex(hex) else {
                return err(ErrorCode::InvalidInput, "not hex");
            };
            let item = tokenator_cbor::decode(&bytes)
                .map_err(|e| EngineError::new(ErrorCode::DateTime, format!("{e:?}")))?;
            Instant::from_item(&item).map_err(|e| dt_error(&e))
        }
    }
}

pub(crate) fn convert(req: &DateTimeRequest) -> Result<DateTimeForms, EngineError> {
    let i = instant_of(&req.input)?;
    let forms = i
        .forms()
        .map_err(|e| dt_error(&e))?
        .into_iter()
        .map(|f| DateTimeFormView {
            form: form_kind(f.form),
            edn: f.edn,
            cbor_hex: hex(&f.cbor),
        })
        .collect();
    Ok(DateTimeForms {
        epoch: epoch_text(i),
        millis: i.millis().ok_or_else(|| {
            EngineError::new(ErrorCode::DateTime, "out of range for milliseconds")
        })?,
        rfc3339_utc: i.to_rfc3339().map_err(|e| dt_error(&e))?,
        rfc3339_local: i
            .to_rfc3339_with_offset(req.local_offset_minutes)
            .map_err(|e| dt_error(&e))?,
        local_offset_minutes: req.local_offset_minutes,
        relative: req.now.map(|now| relative(i.secs(), now)),
        forms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_units() {
        assert_eq!(relative(0, 0), "now");
        assert_eq!(relative(0, 11_520), "3 h 12 m ago");
        assert_eq!(relative(11_520, 0), "in 3 h 12 m");
        assert_eq!(relative(0, 2 * 86_400 + 60), "2 d ago");
        assert_eq!(relative(0, 61), "1 m 1 s ago");
    }

    #[test]
    fn epochs_parse_exactly() {
        let i = parse_epoch("-1.5").unwrap();
        assert_eq!((i.secs(), i.nanos()), (-2, 500_000_000));
        assert_eq!(epoch_text(i), "-1.5");
        assert_eq!(epoch_text(parse_epoch("12.250").unwrap()), "12.25");
        assert_eq!(epoch_text(parse_epoch("-0.25").unwrap()), "-0.25");
        assert!(parse_epoch("1e30").is_err());
        assert!(parse_epoch("1.").is_err());
    }
}
