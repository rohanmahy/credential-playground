//! NaN vectors from draft-bormann-cbor-numbers-03, Appendix B.1.3, Table 2,
//! plus derived sign and width variants, vendored in
//! `testdata/cbor-numbers-nan/nan.tsv` (see the README there).
//!
//! For every row:
//! - `float'<ieee>'` parses to the preferred serialization, and
//!   `float'<ieee>'` with the indicator for the source width parses to the
//!   input bytes;
//! - the input and the preferred bytes print as the expected EDN, which
//!   parses back to exactly those bytes (in strict mode, without warnings);
//! - both survive decode → print → parse → encode(Preserve) for every
//!   print option set.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::{h, hex, rt};
use tokenator_cbor::{EncodeMode, decode, encode};
use tokenator_edn::{ParseOptions, PrintOptions, parse, parse_with, print};

struct Row {
    ieee: String,
    input: Vec<u8>,
    preferred: Vec<u8>,
    edn_input: String,
    edn_preferred: String,
    source: String,
}

fn rows() -> Vec<Row> {
    let path = format!(
        "{}/../../testdata/cbor-numbers-nan/nan.tsv",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut lines = text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty());
    assert_eq!(
        lines.next(),
        Some("ieee\tinput\tpreferred\tedn_input\tedn_preferred\tsource")
    );
    lines
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            assert_eq!(f.len(), 6, "{l}");
            Row {
                ieee: f[0].into(),
                input: h(f[1]),
                preferred: h(f[2]),
                edn_input: f[3].into(),
                edn_preferred: f[4].into(),
                source: f[5].into(),
            }
        })
        .collect()
}

fn width_indicator(cbor: &[u8]) -> &'static str {
    match cbor[0] {
        0xf9 => "_1",
        0xfa => "_2",
        0xfb => "_3",
        b => panic!("not a float head: {b:02x}"),
    }
}

#[test]
fn file_has_the_table2_rows_and_derived_rows() {
    let rows = rows();
    let table2: Vec<_> = rows.iter().filter(|r| r.source == "table2").collect();
    assert_eq!(table2.len(), 10);
    // Spot-check against the draft's Table 2.
    let get = |ieee: &str| {
        table2
            .iter()
            .find(|r| r.ieee == ieee)
            .map(|r| hex(&r.preferred))
    };
    assert_eq!(get("7ff8000000000000").as_deref(), Some("f97e00"));
    assert_eq!(get("7ffffc0000000000").as_deref(), Some("f97fff"));
    assert_eq!(get("7fffffffe0000000").as_deref(), Some("fa7fffffff"));
    assert_eq!(get("7fbff000").as_deref(), Some("fa7fbff000"));
    assert!(rows.len() > 30);
    // Every row is a NaN at its own width.
    for r in &rows {
        assert_eq!(r.input.len(), 1 + r.ieee.len() / 2, "{}", r.ieee);
        assert_eq!(&hex(&r.input)[2..], r.ieee);
    }
}

#[test]
fn float_literal_parses_to_preferred_serialization() {
    for r in rows() {
        let edn = format!("float'{}'", r.ieee);
        assert_eq!(
            hex(&common::enc(&edn)),
            hex(&r.preferred),
            "{edn} ({})",
            r.source
        );
    }
}

#[test]
fn float_literal_with_indicator_parses_to_input() {
    for r in rows() {
        let edn = format!("float'{}'{}", r.ieee, width_indicator(&r.input));
        assert_eq!(
            hex(&common::enc(&edn)),
            hex(&r.input),
            "{edn} ({})",
            r.source
        );
    }
}

#[test]
fn input_and_preferred_print_as_expected() {
    for r in rows() {
        for (bytes, want) in [(&r.input, &r.edn_input), (&r.preferred, &r.edn_preferred)] {
            let item = decode(bytes).unwrap();
            let text = print(&item, &PrintOptions::new()).text;
            assert_eq!(&text, want, "printing {} ({})", hex(bytes), r.source);
        }
    }
}

#[test]
fn expected_edn_parses_to_exact_bytes() {
    let strict = ParseOptions {
        strict: true,
        ..ParseOptions::default()
    };
    for r in rows() {
        for (edn, bytes) in [(&r.edn_input, &r.input), (&r.edn_preferred, &r.preferred)] {
            let parsed = parse_with(edn, &strict).unwrap_or_else(|e| panic!("{edn}: {e:?}"));
            assert!(parsed.warnings.is_empty(), "{edn}");
            assert_eq!(
                hex(&encode(&parsed.items[0], EncodeMode::Preserve)),
                hex(bytes),
                "{edn} ({})",
                r.source
            );
        }
    }
}

#[test]
fn nan_bytes_roundtrip_with_every_option() {
    for r in rows() {
        rt(&r.input).unwrap_or_else(|e| panic!("{}: {e}", r.ieee));
        rt(&r.preferred).unwrap_or_else(|e| panic!("{}: {e}", r.ieee));
    }
}

#[test]
fn nans_inside_containers_keep_their_bytes() {
    let rows = rows();
    let mut bytes = vec![0x98, u8::try_from(rows.len()).unwrap()];
    for r in &rows {
        bytes.extend(&r.input);
    }
    rt(&bytes).unwrap();
    let text = print(&decode(&bytes).unwrap(), &PrintOptions::new()).text;
    let back = parse(&text).unwrap();
    assert_eq!(encode(&back, EncodeMode::Preserve), bytes);
}
