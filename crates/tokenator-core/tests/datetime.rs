//! Date/time chit conversions (SPEC §4.3). RFC 8949 §3.4 examples:
//! 1363896240 is 2013-03-21T20:04:00Z.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_core::{DateFormKind, DateTimeForms, DateTimeInput, DateTimeRequest, ErrorCode};

const T: i64 = 1_363_896_240;

fn convert(input: DateTimeInput, now: Option<i64>, offset: i32) -> DateTimeForms {
    engine()
        .datetime(&DateTimeRequest {
            input,
            now,
            local_offset_minutes: offset,
        })
        .unwrap()
}

fn epoch(text: &str) -> DateTimeInput {
    DateTimeInput::Epoch { text: text.into() }
}

fn form(f: &DateTimeForms, kind: DateFormKind) -> (&str, &str) {
    let v = f
        .forms
        .iter()
        .find(|v| v.form == kind)
        .unwrap_or_else(|| panic!("no {kind:?}"));
    (&v.edn, &v.cbor_hex)
}

#[test]
fn all_forms_of_an_instant() {
    let f = convert(epoch("1363896240"), None, 0);
    assert_eq!(f.epoch, "1363896240");
    assert_eq!(f.millis, 1_363_896_240_000);
    assert_eq!(f.rfc3339_utc, "2013-03-21T20:04:00Z");
    assert_eq!(f.rfc3339_local, "2013-03-21T20:04:00+00:00");
    assert_eq!(f.relative, None);
    let kinds: Vec<_> = f.forms.iter().map(|v| v.form).collect();
    assert_eq!(
        kinds,
        [
            DateFormKind::Epoch,
            DateFormKind::Tag1,
            DateFormKind::Rfc3339,
            DateFormKind::Tag0,
            DateFormKind::Tag100,
            DateFormKind::Tag1004,
            DateFormKind::Dt,
            DateFormKind::DtTagged,
        ]
    );
    assert_eq!(form(&f, DateFormKind::Epoch), ("1363896240", "1a514b67b0"));
    assert_eq!(
        form(&f, DateFormKind::Tag1),
        ("1(1363896240)", "c11a514b67b0")
    );
    assert_eq!(
        form(&f, DateFormKind::Rfc3339),
        (
            "\"2013-03-21T20:04:00Z\"",
            "74323031332d30332d32315432303a30343a30305a"
        )
    );
    assert_eq!(
        form(&f, DateFormKind::Tag0),
        (
            "0(\"2013-03-21T20:04:00Z\")",
            "c074323031332d30332d32315432303a30343a30305a"
        )
    );
    assert_eq!(form(&f, DateFormKind::Tag100), ("100(15785)", "d864193da9"));
    assert_eq!(
        form(&f, DateFormKind::Tag1004),
        ("1004(\"2013-03-21\")", "d903ec6a323031332d30332d3231")
    );
    assert_eq!(
        form(&f, DateFormKind::Dt),
        ("dt'2013-03-21T20:04:00Z'", "1a514b67b0")
    );
    assert_eq!(
        form(&f, DateFormKind::DtTagged),
        ("DT'2013-03-21T20:04:00Z'", "c11a514b67b0")
    );
}

#[test]
fn fractional_epochs() {
    let f = convert(epoch("1363896240.5"), None, 0);
    assert_eq!(f.epoch, "1363896240.5");
    assert_eq!(f.millis, 1_363_896_240_500);
    assert_eq!(f.rfc3339_utc, "2013-03-21T20:04:00.5Z");
    assert_eq!(form(&f, DateFormKind::Tag1).1, "c1fb41d452d9ec200000");
    let neg = convert(epoch("-1.5"), None, 0);
    assert_eq!(neg.rfc3339_utc, "1969-12-31T23:59:58.5Z");
    assert_eq!(neg.millis, -1500);
}

#[test]
fn every_input_field_lands_on_the_same_instant() {
    let inputs = [
        epoch("1363896240"),
        DateTimeInput::Millis {
            millis: 1_363_896_240_000,
        },
        DateTimeInput::Rfc3339 {
            text: "2013-03-21T20:04:00Z".into(),
        },
        DateTimeInput::Rfc3339 {
            text: "2013-03-21T22:04:00+02:00".into(),
        },
        DateTimeInput::Edn {
            text: "1(1363896240)".into(),
        },
        DateTimeInput::Edn {
            text: "dt'2013-03-21T20:04:00Z'".into(),
        },
        DateTimeInput::Edn {
            text: "0(\"2013-03-21T20:04:00Z\")".into(),
        },
        DateTimeInput::CborHex {
            hex: "c11a514b67b0".into(),
        },
        DateTimeInput::CborHex {
            hex: "C1 1A 51 4B 67 B0".into(),
        },
    ];
    for input in inputs {
        let f = convert(input.clone(), None, 0);
        assert_eq!(f.epoch, "1363896240", "{input:?}");
    }
}

#[test]
fn date_only_inputs_are_midnight_utc() {
    for input in [
        DateTimeInput::Date {
            text: "2013-03-21".into(),
        },
        DateTimeInput::Days { days: 15785 },
        DateTimeInput::Edn {
            text: "1004(\"2013-03-21\")".into(),
        },
        DateTimeInput::Edn {
            text: "100(15785)".into(),
        },
    ] {
        let f = convert(input.clone(), None, 0);
        assert_eq!(f.rfc3339_utc, "2013-03-21T00:00:00Z", "{input:?}");
        assert_eq!(f.epoch, "1363824000");
    }
}

#[test]
fn local_offsets() {
    assert_eq!(
        convert(epoch("1363896240"), None, 120).rfc3339_local,
        "2013-03-21T22:04:00+02:00"
    );
    assert_eq!(
        convert(epoch("1363896240"), None, -330).rfc3339_local,
        "2013-03-21T14:34:00-05:30"
    );
    let f = convert(epoch("1363896240"), None, -330);
    assert_eq!(f.local_offset_minutes, -330);
    assert_eq!(f.rfc3339_utc, "2013-03-21T20:04:00Z");
}

#[test]
fn relative_strings() {
    let cases = [
        (T, "now"),
        (T + 11_520, "3 h 12 m ago"),
        (T - 11_520, "in 3 h 12 m"),
        (T + 2 * 86_400, "2 d ago"),
        (T + 2 * 86_400 + 60, "2 d ago"),
        (T - 90_061, "in 1 d 1 h"),
        (T + 45, "45 s ago"),
        (T + 61, "1 m 1 s ago"),
        (T - 3_600, "in 1 h"),
    ];
    for (now, want) in cases {
        let f = convert(epoch("1363896240"), Some(now), 0);
        assert_eq!(f.relative.as_deref(), Some(want), "now = T{:+}", now - T);
    }
}

#[test]
fn invalid_inputs_are_errors() {
    let e = engine();
    let bad = [
        DateTimeInput::Rfc3339 {
            text: "2013-02-30T00:00:00Z".into(),
        },
        DateTimeInput::Rfc3339 {
            text: "yesterday".into(),
        },
        DateTimeInput::Date {
            text: "2013-13-01".into(),
        },
        epoch("abc"),
        epoch("1e30"),
        DateTimeInput::Edn {
            text: "{1: 2}".into(),
        },
        DateTimeInput::Edn {
            text: "1(\"text\")".into(),
        },
        DateTimeInput::CborHex { hex: "a1".into() },
    ];
    for input in bad {
        let err = e
            .datetime(&DateTimeRequest {
                input: input.clone(),
                now: None,
                local_offset_minutes: 0,
            })
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::DateTime, "{input:?}");
    }
    let err = e
        .datetime(&DateTimeRequest {
            input: DateTimeInput::CborHex { hex: "zz".into() },
            now: None,
            local_offset_minutes: 0,
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidInput);
}

#[test]
fn time_claims_carry_inline_dates() {
    let e = engine();
    let doc = open_token(&e, CWT_TAGGED);
    let exp = find(&doc, "payload/~e/4").time.clone().unwrap();
    assert_eq!(exp.epoch, 1_444_064_944);
    assert_eq!(exp.rfc3339, "2015-10-05T17:09:04Z");
    assert_eq!(exp.relative, None);
    let jwt = open_token(&e, "rfc7515-a3-jws-es256.txt");
    let exp = find(&jwt, "payload/~e/exp").time.clone().unwrap();
    assert_eq!(exp.epoch, 1_300_819_380);
    assert!(find(&jwt, "payload/~e/iss").time.is_none());

    let with_now = e
        .render(&tokenator_core::RenderRequest {
            doc: tokenator_core::DocRef::from(&doc),
            layers: vec![],
            view: tokenator_core::ViewOptions {
                now: Some(1_444_064_944 - 3_600),
                ..tokenator_core::ViewOptions::default()
            },
        })
        .unwrap();
    assert_eq!(
        find(&with_now, "payload/~e/4")
            .time
            .as_ref()
            .unwrap()
            .relative
            .as_deref(),
        Some("in 1 h")
    );
}
