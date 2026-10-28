//! Tests driven by https://github.com/hildjj/cbor-test-vectors, vendored in
//! `testdata/cbor-test-vectors` (see the README there for the commit).
//!
//! Each `.cbor` file is itself CBOR: a map with `"tests"` (an array of maps
//! with `"description"`, `"encoded"` (a byte string), `"decoded"` (the
//! expected item), and optional `"roundtrip"` and `"fail"`) and an optional
//! file-level `"fail"`. For every good test:
//!
//! - `encoded` decodes, satisfies the span invariants, and re-encodes in
//!   Preserve mode to exactly `encoded`;
//! - it means the same as `decoded` (see `common::sem`);
//! - when `roundtrip` is true (the default) a typical encoder produces
//!   `encoded`, so it has no preferred-serialization findings;
//! - its Deterministic encoding decodes to the same meaning, has no
//!   deterministic findings, and is a fixed point of Deterministic encoding.
//!
//! Failing tests must not decode, except the ones in
//! `ACCEPTED_BY_GENERIC_DECODER`.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::{check_spans, get, hex, sem, sem_unordered};
use tokenator_cbor::{
    EncodeMode, Item, Value, decode, deterministic_findings, encode, preferred_findings,
};

/// Failing tests whose problem is the content of a tag. tokenator-cbor does
/// not interpret tags, so it accepts them (they are well-formed).
const ACCEPTED_BY_GENERIC_DECODER: &[&str] = &[
    "date: unexpected object instead of offset",
    "date: unexpected object instead of string",
];

fn vector_file(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../testdata/cbor-test-vectors/tests/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}

fn as_bool(item: Option<&Item>) -> Option<bool> {
    match item.map(|i| &i.value) {
        Some(Value::Bool(b)) => Some(*b),
        _ => None,
    }
}

fn check_good(encoded: &[u8], decoded: Option<&Item>, roundtrip: bool) -> Result<(), String> {
    let item = decode(encoded).map_err(|e| format!("decode failed: {e}"))?;
    check_spans(&item, encoded)?;
    let preserved = encode(&item, EncodeMode::Preserve);
    if preserved != encoded {
        return Err(format!("Preserve gave {}", hex(&preserved)));
    }
    if let Some(expected) = decoded
        && sem(&item) != sem(expected)
    {
        return Err(format!(
            "decoded as {} but expected {}",
            sem(&item),
            sem(expected)
        ));
    }
    if roundtrip {
        let findings = preferred_findings(&item);
        if !findings.is_empty() {
            return Err(format!("unexpected preferred findings: {findings:?}"));
        }
    }
    let det = encode(&item, EncodeMode::Deterministic);
    let det_item = decode(&det)
        .map_err(|e| format!("Deterministic output {} does not decode: {e}", hex(&det)))?;
    if sem_unordered(&det_item) != sem_unordered(&item) {
        return Err(format!(
            "Deterministic output {} changed the value",
            hex(&det)
        ));
    }
    let findings = deterministic_findings(&det_item);
    if !findings.is_empty() {
        return Err(format!(
            "Deterministic output {} has findings {findings:?}",
            hex(&det)
        ));
    }
    if encode(&det_item, EncodeMode::Deterministic) != det {
        return Err("Deterministic encoding is not idempotent".into());
    }
    Ok(())
}

fn run(name: &str) {
    let file = vector_file(name);
    let root = decode(&file).unwrap_or_else(|e| panic!("{name}: vector file does not decode: {e}"));
    let file_fail = as_bool(get(&root, "fail")).unwrap_or(false);
    let Some(Value::Array(tests)) = get(&root, "tests").map(|t| &t.value) else {
        panic!("{name}: no tests array");
    };
    assert!(!tests.is_empty(), "{name}: empty tests array");
    let mut failures = Vec::new();
    for (i, test) in tests.iter().enumerate() {
        let description = match get(test, "description").map(|d| &d.value) {
            Some(Value::Text(t)) => t.to_string(),
            _ => format!("#{i}"),
        };
        let Some(Value::Bytes(encoded)) = get(test, "encoded").map(|e| &e.value) else {
            failures.push(format!("{description}: no encoded byte string"));
            continue;
        };
        let fail = as_bool(get(test, "fail")).unwrap_or(file_fail);
        let roundtrip = as_bool(get(test, "roundtrip")).unwrap_or(true);
        let result = if fail && !ACCEPTED_BY_GENERIC_DECODER.contains(&description.as_str()) {
            match decode(encoded) {
                Ok(item) => Err(format!("should fail but decoded as {}", sem(&item))),
                Err(_) => Ok(()),
            }
        } else {
            check_good(encoded, get(test, "decoded"), roundtrip && !fail)
        };
        if let Err(e) = result {
            failures.push(format!("#{i} {description} [{}]: {e}", hex(encoded)));
        }
    }
    assert!(
        failures.is_empty(),
        "{name}: {} of {} failed:\n{}",
        failures.len(),
        tests.len(),
        failures.join("\n")
    );
}

#[test]
fn appendix_a_mt0() {
    run("rfc8949-appendixA/mt0.cbor");
}

#[test]
fn appendix_a_mt1() {
    run("rfc8949-appendixA/mt1.cbor");
}

#[test]
fn appendix_a_mt2() {
    run("rfc8949-appendixA/mt2.cbor");
}

#[test]
fn appendix_a_mt3() {
    run("rfc8949-appendixA/mt3.cbor");
}

#[test]
fn appendix_a_mt4() {
    run("rfc8949-appendixA/mt4.cbor");
}

#[test]
fn appendix_a_mt5() {
    run("rfc8949-appendixA/mt5.cbor");
}

#[test]
fn appendix_a_mt6() {
    run("rfc8949-appendixA/mt6.cbor");
}

#[test]
fn appendix_a_mt7_float() {
    run("rfc8949-appendixA/mt7-float.cbor");
}

#[test]
fn appendix_a_mt7_simple() {
    run("rfc8949-appendixA/mt7-simple.cbor");
}

#[test]
fn appendix_a_streaming() {
    run("rfc8949-appendixA/streaming.cbor");
}

#[test]
fn rfc8949_good() {
    run("rfc8949/good.cbor");
}

#[test]
fn rfc8949_bad() {
    run("rfc8949/bad.cbor");
}

#[test]
fn spike() {
    run("spike/spike.cbor");
}

#[test]
fn every_vector_file_is_covered() {
    let dir = format!(
        "{}/../../testdata/cbor-test-vectors/tests",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut found = Vec::new();
    for sub in std::fs::read_dir(&dir).unwrap() {
        let sub = sub.unwrap().path();
        if !sub.is_dir() {
            continue;
        }
        for f in std::fs::read_dir(&sub).unwrap() {
            let f = f.unwrap().path();
            if f.extension().is_some_and(|e| e == "cbor") {
                let rel = f
                    .strip_prefix(&dir)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                found.push(rel);
            }
        }
    }
    found.sort();
    let mut covered = vec![
        "rfc8949-appendixA/mt0.cbor",
        "rfc8949-appendixA/mt1.cbor",
        "rfc8949-appendixA/mt2.cbor",
        "rfc8949-appendixA/mt3.cbor",
        "rfc8949-appendixA/mt4.cbor",
        "rfc8949-appendixA/mt5.cbor",
        "rfc8949-appendixA/mt6.cbor",
        "rfc8949-appendixA/mt7-float.cbor",
        "rfc8949-appendixA/mt7-simple.cbor",
        "rfc8949-appendixA/streaming.cbor",
        "rfc8949/bad.cbor",
        "rfc8949/good.cbor",
        "spike/spike.cbor",
    ];
    covered.sort();
    assert_eq!(found, covered, "add a test for each new vector file");
}
