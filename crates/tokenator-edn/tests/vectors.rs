//! Tests driven by https://github.com/hildjj/cbor-test-vectors, vendored in
//! `testdata/cbor-test-vectors` (see the README there for the commit).
//!
//! Each `.edn` file is EDN for a map with `"tests"`: an array of maps with
//! `"encoded"` (a byte string), `"decoded"` (an item), and optional flags. Its
//! `.cbor` twin is the same data encoded by the upstream tooling with
//! preferred serialization. So:
//!
//! - parsing the `.edn` file and encoding it gives exactly the `.cbor` file;
//! - printing the decoded `.cbor` file and parsing it gives the same bytes;
//! - every good `encoded` byte string survives decode → print → parse →
//!   encode(Preserve), with each set of print options;
//! - every `decoded` item prints and re-parses to the same encoding.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::{check_span_map, deep, hex, rt, vector_file};
use tokenator_cbor::{EncodeMode, Item, Value, decode, encode};
use tokenator_edn::{ParseOptions, PrintOptions, parse, parse_with, print};

const FILES: &[&str] = &[
    "rfc8949-appendixA/mt0",
    "rfc8949-appendixA/mt1",
    "rfc8949-appendixA/mt2",
    "rfc8949-appendixA/mt3",
    "rfc8949-appendixA/mt4",
    "rfc8949-appendixA/mt5",
    "rfc8949-appendixA/mt6",
    "rfc8949-appendixA/mt7-float",
    "rfc8949-appendixA/mt7-simple",
    "rfc8949-appendixA/streaming",
    "rfc8949/good",
    "rfc8949/bad",
    "spike/spike",
];

fn edn_text(name: &str) -> String {
    String::from_utf8(vector_file(&format!("{name}.edn"))).unwrap()
}

fn get<'i, 'a>(map: &'i Item<'a>, key: &str) -> Option<&'i Item<'a>> {
    let Value::Map(entries) = &map.value else {
        return None;
    };
    entries.iter().find_map(|(k, v)| match &k.value {
        Value::Text(t) if t == key => Some(v),
        _ => None,
    })
}

fn tests_of<'i, 'a>(file: &'i Item<'a>) -> &'i [Item<'a>] {
    match get(file, "tests").map(|t| &t.value) {
        Some(Value::Array(tests)) => tests,
        _ => panic!("no tests array"),
    }
}

fn description(test: &Item) -> String {
    match get(test, "description").map(|d| &d.value) {
        Some(Value::Text(t)) => t.to_string(),
        _ => "?".into(),
    }
}

#[test]
fn every_vector_file_is_listed() {
    let root = format!(
        "{}/../../testdata/cbor-test-vectors/tests",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut found = Vec::new();
    for dir in std::fs::read_dir(&root).unwrap() {
        let dir = dir.unwrap().path();
        if !dir.is_dir() {
            continue;
        }
        for f in std::fs::read_dir(&dir).unwrap() {
            let f = f.unwrap().path();
            if f.extension().is_some_and(|e| e == "edn") {
                let name = format!(
                    "{}/{}",
                    dir.file_name().unwrap().to_str().unwrap(),
                    f.file_stem().unwrap().to_str().unwrap()
                );
                found.push(name);
            }
        }
    }
    found.sort();
    let mut listed: Vec<String> = FILES.iter().map(|s| s.to_string()).collect();
    listed.sort();
    assert_eq!(found, listed, "update FILES in tests/vectors.rs");
}

fn check_edn_file_encodes_to_cbor(name: &str) {
    let text = edn_text(name);
    let want = vector_file(&format!("{name}.cbor"));
    let item = parse(&text).unwrap_or_else(|e| panic!("{name}.edn: {e:?}"));
    let got = encode(&item, EncodeMode::Preserve);
    if got != want {
        let at = got
            .iter()
            .zip(want.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(got.len().min(want.len()));
        panic!(
            "{name}: parsed EDN encodes differently from the .cbor file \
             (lengths {} vs {}, first difference at byte {at}: got {} want {})",
            got.len(),
            want.len(),
            hex(&got[at.min(got.len())..(at + 16).min(got.len())]),
            hex(&want[at.min(want.len())..(at + 16).min(want.len())]),
        );
    }
}

fn check_cbor_file_roundtrips(name: &str) {
    let bytes = vector_file(&format!("{name}.cbor"));
    rt(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
    let item = decode(&bytes).unwrap();
    let strict = ParseOptions {
        strict: true,
        ..ParseOptions::default()
    };
    for opts in [PrintOptions::new(), PrintOptions::indented(2)] {
        let rendered = print(&item, &opts);
        check_span_map(&item, Some(&bytes), &rendered)
            .unwrap_or_else(|e| panic!("{name} ({:?}): {e}", opts.layout));
        // The printer's default output parses without warnings (#14).
        let parsed = parse_with(&rendered.text, &strict)
            .unwrap_or_else(|e| panic!("{name} ({:?}) in strict mode: {e}", opts.layout));
        assert!(parsed.warnings.is_empty(), "{name}: {:?}", parsed.warnings);
    }
}

fn check_each_test_roundtrips(name: &str) {
    let bytes = vector_file(&format!("{name}.cbor"));
    let file = decode(&bytes).unwrap();
    let mut failures = Vec::new();
    for test in tests_of(&file) {
        let desc = description(test);
        if let Some(Item {
            value: Value::Bytes(encoded),
            ..
        }) = get(test, "encoded")
            && decode(encoded).is_ok()
            && let Err(e) = rt(encoded)
        {
            failures.push(format!("{desc}: encoded: {e}"));
        }
        if let Some(decoded) = get(test, "decoded") {
            let want = encode(decoded, EncodeMode::Preserve);
            for (opt_name, opts) in common::roundtrip_options() {
                let text = print(decoded, &opts).text;
                match parse(&text) {
                    Ok(back) if encode(&back, EncodeMode::Preserve) == want => {}
                    Ok(back) => failures.push(format!(
                        "{desc}: decoded [{opt_name}] {text:?} re-encodes to {}, want {}",
                        hex(&encode(&back, EncodeMode::Preserve)),
                        hex(&want)
                    )),
                    Err(e) => {
                        failures.push(format!("{desc}: decoded [{opt_name}] {text:?}: {e:?}"))
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{name}: {} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Every decodable byte string listed as embedded CBOR (#15): the whole
/// file and every good `encoded` value still round-trip exactly.
fn check_embedded_roundtrips(name: &str) {
    let bytes = vector_file(&format!("{name}.cbor"));
    common::rt_embedded(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
    let file = decode(&bytes).unwrap();
    for test in tests_of(&file) {
        if let Some(Item {
            value: Value::Bytes(encoded),
            ..
        }) = get(test, "encoded")
            && decode(encoded).is_ok()
        {
            common::rt_embedded(encoded)
                .unwrap_or_else(|e| panic!("{name}: {}: {e}", description(test)));
        }
    }
}

macro_rules! vector_tests {
    ($($id:ident => $name:literal,)*) => {
        mod edn_file_encodes_to_cbor {
            $(#[test] fn $id() { super::deep(|| super::check_edn_file_encodes_to_cbor($name)); })*
        }
        mod cbor_file_roundtrips {
            $(#[test] fn $id() { super::deep(|| super::check_cbor_file_roundtrips($name)); })*
        }
        mod each_test_roundtrips {
            $(#[test] fn $id() { super::deep(|| super::check_each_test_roundtrips($name)); })*
        }
        mod embedded_roundtrips {
            $(#[test] fn $id() { super::deep(|| super::check_embedded_roundtrips($name)); })*
        }
    };
}

vector_tests! {
    mt0 => "rfc8949-appendixA/mt0",
    mt1 => "rfc8949-appendixA/mt1",
    mt2 => "rfc8949-appendixA/mt2",
    mt3 => "rfc8949-appendixA/mt3",
    mt4 => "rfc8949-appendixA/mt4",
    mt5 => "rfc8949-appendixA/mt5",
    mt6 => "rfc8949-appendixA/mt6",
    mt7_float => "rfc8949-appendixA/mt7-float",
    mt7_simple => "rfc8949-appendixA/mt7-simple",
    streaming => "rfc8949-appendixA/streaming",
    good => "rfc8949/good",
    bad => "rfc8949/bad",
    spike => "spike/spike",
}

/// The upstream files use these EDN features; make sure each has at least
/// one exact check outside the whole-file comparison.
#[test]
fn features_used_by_the_vectors() {
    common::assert_enc("{\"a\": 1}", "a1616101");
    common::assert_enc("{\n  \"x\": h'18 00', # c\n}", "a1617842 1800");
    common::assert_enc("float'7d1f'", "f97d1f");
    common::assert_enc("float'7ff50c32fdc0b06d'", "fb7ff50c32fdc0b06d");
    common::assert_enc("-0x1c0000000000000001", "c3 49 1c0000000000000000");
    common::assert_enc("0x1c0000000000000000", "c2 49 1c0000000000000000");
    common::assert_enc(r#""𐅑""#, "64f0908591");
    common::assert_enc("[_ ]", "9fff");
    common::assert_enc("(_ \"strea\", \"ming\")", "7f657374726561646d696e67ff");
    common::assert_enc("-Infinity", "f9fc00");
    common::assert_enc("1.0e+300", "fb7e37e43c8800759c");
    common::assert_enc("simple(255)", "f8ff");
    common::assert_enc("{\"__proto__\": 0}", "a1695f5f70726f746f5f5f00");
}
