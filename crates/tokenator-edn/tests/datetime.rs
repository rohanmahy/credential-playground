//! Date/time conversions for the SPEC §4.3 chit: epoch seconds, RFC 3339,
//! tags 0, 1, 100, 1004 (RFC 8943), and their EDN forms.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::{enc, h, hex};
use tokenator_cbor::{EncodeMode, Item, decode, encode};
use tokenator_edn::datetime::{DateForm, DateTimeError, EpochValue, Instant};

fn at(secs: i64, nanos: u32) -> Instant {
    Instant::new(secs, nanos).unwrap()
}

fn rfc(text: &str) -> Instant {
    Instant::parse_rfc3339(text).unwrap_or_else(|e| panic!("{text}: {e:?}"))
}

const T: i64 = 1_363_896_240; // 2013-03-21T20:04:00Z

#[test]
fn constructor_invariant() {
    assert!(Instant::new(0, 999_999_999).is_some());
    assert!(Instant::new(0, 1_000_000_000).is_none());
    assert_eq!(at(-2, 5).secs(), -2);
    assert_eq!(at(-2, 5).nanos(), 5);
}

#[test]
fn rfc3339_to_epoch() {
    assert_eq!(rfc("2013-03-21T20:04:00Z"), at(T, 0));
    assert_eq!(rfc("1970-01-01T00:00:00Z"), at(0, 0));
    assert_eq!(rfc("1969-07-21T02:56:16Z"), at(-14_159_024, 0));
    assert_eq!(rfc("1969-07-21T02:56:16.5Z"), at(-14_159_024, 500_000_000));
    assert_eq!(rfc("2000-02-29T00:00:00Z"), at(951_782_400, 0));
    assert_eq!(rfc("0000-01-01T00:00:00Z"), at(-62_167_219_200, 0));
    assert_eq!(rfc("9999-12-31T23:59:59Z"), at(253_402_300_799, 0));
}

#[test]
fn time_zones_are_normalized() {
    assert_eq!(rfc("2013-03-21T22:04:00+02:00"), at(T, 0));
    assert_eq!(rfc("2013-03-21T15:34:00-04:30"), at(T, 0));
    assert_eq!(rfc("2013-03-21T20:04:00+00:00"), at(T, 0));
    assert_eq!(rfc("2013-03-21T20:04:00-00:00"), at(T, 0));
    assert_eq!(rfc("2013-03-22T05:04:00+09:00"), at(T, 0));
    // Crossing a date and a year boundary.
    assert_eq!(rfc("1970-01-01T01:00:00+01:00"), at(0, 0));
    assert_eq!(rfc("1969-12-31T23:00:00-01:00"), at(0, 0));
    assert_eq!(rfc("2013-03-21t20:04:00z"), at(T, 0));
}

#[test]
fn fractional_seconds() {
    assert_eq!(rfc("2013-03-21T20:04:00.5Z"), at(T, 500_000_000));
    assert_eq!(rfc("2013-03-21T20:04:00.000000001Z"), at(T, 1));
    assert_eq!(rfc("2013-03-21T20:04:00.123456789Z"), at(T, 123_456_789));
    // Digits beyond nanoseconds are truncated.
    assert_eq!(rfc("2013-03-21T20:04:00.1234567899Z"), at(T, 123_456_789));
    assert_eq!(rfc("2013-03-21T20:04:00.0Z"), at(T, 0));
    // Fractions with an offset.
    assert_eq!(rfc("2013-03-21T22:04:00.25+02:00"), at(T, 250_000_000));
    // Negative epoch with a fraction counts forward from the floor.
    assert_eq!(rfc("1969-12-31T23:59:59.75Z"), at(-1, 750_000_000));
}

#[test]
fn leap_second_maps_to_the_next_second() {
    assert_eq!(rfc("2016-12-31T23:59:60Z"), rfc("2017-01-01T00:00:00Z"));
    assert_eq!(rfc("2016-12-31T23:59:60.5Z"), rfc("2017-01-01T00:00:00.5Z"));
    assert_eq!(
        rfc("2017-01-01T00:59:60+01:00"),
        rfc("2017-01-01T00:00:00Z")
    );
}

#[test]
fn invalid_rfc3339() {
    for text in [
        "2013-02-29T00:00:00Z",
        "2100-02-29T00:00:00Z",
        "1900-02-29T00:00:00Z",
        "2013-04-31T00:00:00Z",
        "2013-13-01T00:00:00Z",
        "2013-00-01T00:00:00Z",
        "2013-01-00T00:00:00Z",
        "2013-01-32T00:00:00Z",
        "2013-01-01T24:00:00Z",
        "2013-01-01T23:60:00Z",
        "2013-01-01T23:59:61Z",
        "2013-01-01T00:00:00+24:00",
        "2013-01-01T00:00:00+01:60",
    ] {
        assert_eq!(
            Instant::parse_rfc3339(text),
            Err(DateTimeError::InvalidDate),
            "{text}"
        );
    }
    for text in [
        "",
        "2013-03-21",
        "2013-03-21 20:04:00Z",
        "2013-03-21T20:04:00",
        "2013-03-21T20:04Z",
        "2013-03-21T20:04:00.Z",
        "2013-03-21T20:04:00+0200",
        "2013-03-21T20:04:00+02",
        "13-03-21T20:04:00Z",
        "+2013-03-21T20:04:00Z",
        "2013-3-21T20:04:00Z",
        "2013-03-21T20:04:00Z ",
        " 2013-03-21T20:04:00Z",
        "2013-03-21T20:04:00ZZ",
        "2013-03-21T20:04:00\u{ff10}Z",
    ] {
        assert_eq!(
            Instant::parse_rfc3339(text),
            Err(DateTimeError::Syntax),
            "{text:?}"
        );
    }
    assert!(Instant::parse_rfc3339("2000-02-29T00:00:00Z").is_ok());
    assert!(Instant::parse_rfc3339("2024-02-29T00:00:00Z").is_ok());
}

#[test]
fn rfc3339_output() {
    assert_eq!(at(T, 0).to_rfc3339().unwrap(), "2013-03-21T20:04:00Z");
    assert_eq!(
        at(T, 500_000_000).to_rfc3339().unwrap(),
        "2013-03-21T20:04:00.5Z"
    );
    assert_eq!(
        at(T, 1).to_rfc3339().unwrap(),
        "2013-03-21T20:04:00.000000001Z"
    );
    assert_eq!(
        at(T, 120_000_000).to_rfc3339().unwrap(),
        "2013-03-21T20:04:00.12Z"
    );
    assert_eq!(at(-1, 0).to_rfc3339().unwrap(), "1969-12-31T23:59:59Z");
    assert_eq!(
        at(-1, 750_000_000).to_rfc3339().unwrap(),
        "1969-12-31T23:59:59.75Z"
    );
    assert_eq!(
        at(-62_167_219_200, 0).to_rfc3339().unwrap(),
        "0000-01-01T00:00:00Z"
    );
    assert_eq!(
        at(253_402_300_800, 0).to_rfc3339(),
        Err(DateTimeError::OutOfRange)
    );
    assert_eq!(
        at(-62_167_219_201, 0).to_rfc3339(),
        Err(DateTimeError::OutOfRange)
    );
}

#[test]
fn rfc3339_with_offset() {
    let t = at(T, 0);
    assert_eq!(
        t.to_rfc3339_with_offset(120).unwrap(),
        "2013-03-21T22:04:00+02:00"
    );
    assert_eq!(
        t.to_rfc3339_with_offset(-330).unwrap(),
        "2013-03-21T14:34:00-05:30"
    );
    assert_eq!(
        t.to_rfc3339_with_offset(0).unwrap(),
        "2013-03-21T20:04:00+00:00"
    );
    assert_eq!(
        t.to_rfc3339_with_offset(9 * 60).unwrap(),
        "2013-03-22T05:04:00+09:00"
    );
    assert_eq!(
        at(T, 500_000_000).to_rfc3339_with_offset(60).unwrap(),
        "2013-03-21T21:04:00.5+01:00"
    );
    assert_eq!(
        t.to_rfc3339_with_offset(24 * 60),
        Err(DateTimeError::InvalidDate)
    );
    // Round trip through the parser.
    for offset in [-720, -1, 0, 1, 345, 840] {
        let text = t.to_rfc3339_with_offset(offset).unwrap();
        assert_eq!(rfc(&text), t, "{text}");
    }
}

#[test]
fn epoch_values() {
    assert_eq!(at(T, 0).epoch(), EpochValue::Int(T));
    assert_eq!(
        at(T, 500_000_000).epoch(),
        EpochValue::Float(1_363_896_240.5)
    );
    assert_eq!(at(-1, 500_000_000).epoch(), EpochValue::Float(-0.5));
    assert_eq!(
        at(-14_159_024, 500_000_000).epoch(),
        EpochValue::Float(-14_159_023.5)
    );
    // The float is the binary64 nearest to the exact decimal.
    assert_eq!(
        at(T, 100_000_000).epoch(),
        EpochValue::Float("1363896240.1".parse().unwrap())
    );
    assert_eq!(
        at(0, 1).epoch(),
        EpochValue::Float("0.000000001".parse().unwrap())
    );
}

#[test]
fn from_epoch() {
    assert_eq!(Instant::from_epoch(EpochValue::Int(T)).unwrap(), at(T, 0));
    assert_eq!(
        Instant::from_epoch(EpochValue::Float(1_363_896_240.5)).unwrap(),
        at(T, 500_000_000)
    );
    assert_eq!(
        Instant::from_epoch(EpochValue::Float(-1.5)).unwrap(),
        at(-2, 500_000_000)
    );
    assert_eq!(
        Instant::from_epoch(EpochValue::Float(1.1)).unwrap(),
        at(1, 100_000_000)
    );
    // Rounds to the nearest nanosecond.
    assert_eq!(
        Instant::from_epoch(EpochValue::Float(0.999_999_999_9)).unwrap(),
        at(1, 0)
    );
    assert_eq!(
        Instant::from_epoch(EpochValue::Float(-0.0)).unwrap(),
        at(0, 0)
    );
    assert_eq!(
        Instant::from_epoch(EpochValue::Float(f64::NAN)),
        Err(DateTimeError::NotFinite)
    );
    assert_eq!(
        Instant::from_epoch(EpochValue::Float(f64::INFINITY)),
        Err(DateTimeError::NotFinite)
    );
    assert_eq!(
        Instant::from_epoch(EpochValue::Float(1e300)),
        Err(DateTimeError::OutOfRange)
    );
    assert_eq!(
        Instant::from_epoch(EpochValue::Int(i64::MIN))
            .unwrap()
            .secs(),
        i64::MIN
    );
}

#[test]
fn milliseconds() {
    assert_eq!(Instant::from_millis(1_500), at(1, 500_000_000));
    assert_eq!(Instant::from_millis(-1_500), at(-2, 500_000_000));
    assert_eq!(at(1, 500_000_000).millis(), Some(1_500));
    assert_eq!(at(-2, 500_000_000).millis(), Some(-1_500));
    assert_eq!(at(0, 999_999).millis(), Some(0));
    assert_eq!(at(-1, 999_999_999).millis(), Some(-1));
    assert_eq!(at(i64::MAX, 0).millis(), None);
}

#[test]
fn days_and_dates() {
    assert_eq!(at(T, 0).days(), 15_785);
    assert_eq!(at(T, 0).to_date().unwrap(), "2013-03-21");
    assert_eq!(Instant::from_days(15_785), at(1_363_824_000, 0));
    assert_eq!(
        Instant::parse_date("2013-03-21").unwrap(),
        at(1_363_824_000, 0)
    );
    assert_eq!(at(-1, 0).days(), -1);
    assert_eq!(at(-1, 0).to_date().unwrap(), "1969-12-31");
    assert_eq!(at(-86_400, 0).days(), -1);
    assert_eq!(at(-86_401, 0).days(), -2);
    assert_eq!(Instant::from_days(-1), at(-86_400, 0));
    // RFC 8943 examples: 1940-10-09 is day -10676, 1980-12-08 is day 3994.
    assert_eq!(Instant::parse_date("1940-10-09").unwrap().days(), -10_676);
    assert_eq!(Instant::parse_date("1980-12-08").unwrap().days(), 3_994);
    assert_eq!(
        Instant::parse_date("2013-02-29"),
        Err(DateTimeError::InvalidDate)
    );
    assert_eq!(
        Instant::parse_date("2013-03-21T00:00:00Z"),
        Err(DateTimeError::Syntax)
    );
}

#[test]
fn items_for_each_form() {
    let t = at(T, 0);
    for (form, edn) in [
        (DateForm::Epoch, "1363896240"),
        (DateForm::Tag1, "1(1363896240)"),
        (DateForm::Rfc3339, "\"2013-03-21T20:04:00Z\""),
        (DateForm::Tag0, "0(\"2013-03-21T20:04:00Z\")"),
        (DateForm::Tag100, "100(15785)"),
        (DateForm::Tag1004, "1004(\"2013-03-21\")"),
        (DateForm::Dt, "1363896240"),
        (DateForm::DtTagged, "1(1363896240)"),
    ] {
        let item = t.to_item(form).unwrap();
        assert_eq!(
            hex(&encode(&item, EncodeMode::Preserve)),
            hex(&enc(edn)),
            "{form:?}"
        );
    }
    let frac = at(T, 500_000_000);
    assert_eq!(
        encode(&frac.to_item(DateForm::Tag1).unwrap(), EncodeMode::Preserve),
        h("c1fb41d452d9ec200000")
    );
    assert_eq!(
        encode(&frac.to_item(DateForm::Tag0).unwrap(), EncodeMode::Preserve),
        enc("0(\"2013-03-21T20:04:00.5Z\")")
    );
}

#[test]
fn edn_for_each_form() {
    let t = at(T, 0);
    for (form, edn) in [
        (DateForm::Epoch, "1363896240"),
        (DateForm::Tag1, "1(1363896240)"),
        (DateForm::Rfc3339, "\"2013-03-21T20:04:00Z\""),
        (DateForm::Tag0, "0(\"2013-03-21T20:04:00Z\")"),
        (DateForm::Tag100, "100(15785)"),
        (DateForm::Tag1004, "1004(\"2013-03-21\")"),
        (DateForm::Dt, "dt'2013-03-21T20:04:00Z'"),
        (DateForm::DtTagged, "DT'2013-03-21T20:04:00Z'"),
    ] {
        assert_eq!(t.to_edn(form).unwrap(), edn, "{form:?}");
        // The EDN parses to the same item.
        assert_eq!(
            hex(&enc(edn)),
            hex(&encode(&t.to_item(form).unwrap(), EncodeMode::Preserve))
        );
    }
    let frac = at(-1, 750_000_000);
    assert_eq!(frac.to_edn(DateForm::Epoch).unwrap(), "-0.25");
    assert_eq!(
        frac.to_edn(DateForm::Dt).unwrap(),
        "dt'1969-12-31T23:59:59.75Z'"
    );
    assert_eq!(hex(&enc("dt'1969-12-31T23:59:59.75Z'")), hex(&enc("-0.25")));
}

#[test]
fn forms_lists_everything() {
    let forms = at(T, 0).forms().unwrap();
    assert_eq!(
        forms.iter().map(|f| f.form).collect::<Vec<_>>(),
        DateForm::ALL
    );
    for f in &forms {
        assert_eq!(hex(&f.cbor), hex(&enc(&f.edn)), "{:?}", f.form);
    }
    assert_eq!(
        at(253_402_300_800, 0).forms(),
        Err(DateTimeError::OutOfRange)
    );
}

#[test]
fn from_items() {
    for (edn, want) in [
        ("1(1363896240)", at(T, 0)),
        ("1(1363896240.5)", at(T, 500_000_000)),
        ("1(-1)", at(-1, 0)),
        ("0(\"2013-03-21T20:04:00Z\")", at(T, 0)),
        ("0(\"2013-03-21T22:04:00+02:00\")", at(T, 0)),
        ("100(15785)", at(1_363_824_000, 0)),
        ("100(-1)", at(-86_400, 0)),
        ("1004(\"2013-03-21\")", at(1_363_824_000, 0)),
        ("1363896240", at(T, 0)),
        ("1363896240.5", at(T, 500_000_000)),
        ("\"2013-03-21T20:04:00Z\"", at(T, 0)),
        ("1(1363896240_3)", at(T, 0)),
        ("1(1.5_3)", at(1, 500_000_000)),
        ("DT'2013-03-21T20:04:00Z'", at(T, 0)),
    ] {
        let item = decode(&enc(edn)).unwrap().into_owned();
        assert_eq!(Instant::from_item(&item).unwrap(), want, "{edn}");
    }
    for edn in [
        "1(\"2013-03-21T20:04:00Z\")",
        "0(1363896240)",
        "100(\"2013-03-21\")",
        "100(1.5)",
        "1004(15785)",
        "2(h'01')",
        "[1]",
        "null",
        "1(1(1))",
        "h'00'",
    ] {
        let item = decode(&enc(edn)).unwrap().into_owned();
        assert_eq!(
            Instant::from_item(&item),
            Err(DateTimeError::UnsupportedItem),
            "{edn}"
        );
    }
    let item = decode(&enc("0(\"garbage\")")).unwrap().into_owned();
    assert_eq!(Instant::from_item(&item), Err(DateTimeError::Syntax));
    let item = decode(&enc("1(NaN)")).unwrap().into_owned();
    assert_eq!(Instant::from_item(&item), Err(DateTimeError::NotFinite));
    let item = Item::int(-1);
    assert_eq!(Instant::from_item(&item).unwrap(), at(-1, 0));
}

#[test]
fn rfc3339_roundtrip_samples() {
    for text in [
        "1970-01-01T00:00:00Z",
        "1969-07-21T02:56:16.5Z",
        "2038-01-19T03:14:08Z",
        "2106-02-07T06:28:16Z",
        "1900-01-01T00:00:00Z",
        "2000-02-29T12:34:56.789Z",
        "9999-12-31T23:59:59.999999999Z",
        "0000-01-01T00:00:00Z",
    ] {
        assert_eq!(rfc(text).to_rfc3339().unwrap(), text);
    }
}

#[test]
fn errors_display() {
    for e in [
        DateTimeError::Syntax,
        DateTimeError::InvalidDate,
        DateTimeError::OutOfRange,
        DateTimeError::NotFinite,
        DateTimeError::UnsupportedItem,
    ] {
        assert!(!e.to_string().is_empty());
    }
}
