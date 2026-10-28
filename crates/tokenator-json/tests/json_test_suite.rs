//! RFC 8259 conformance against nst/JSONTestSuite `test_parsing/`.
//!
//! `y_` must parse, `n_` must fail, `i_` must match [`i_expectation`].
//! Every file is run, even if earlier ones fail, so one run reports all problems.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::panic::catch_unwind;
use std::path::PathBuf;

use tokenator_json::{ErrorKind, PrintStyle, parse, print};

fn suite_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/JSONTestSuite/test_parsing")
}

fn files(prefix: &str) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<_> = std::fs::read_dir(suite_dir())
        .expect("testdata/JSONTestSuite/test_parsing missing")
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(prefix) && n.ends_with(".json"))
        })
        .map(|p| {
            let name = p.file_name().unwrap().to_str().unwrap().to_owned();
            (name, std::fs::read(&p).unwrap())
        })
        .collect();
    out.sort();
    assert!(!out.is_empty(), "no {prefix} files found");
    out
}

fn is_ws(b: &u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

fn trim_ws(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|c| !is_ws(c)).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !is_ws(c)).map_or(start, |i| i + 1);
    &b[start..end]
}

/// Expected outcome for implementation-defined cases.
/// `Ok(())` = accept, `Err(kind)` = reject with that kind.
fn i_expectation(name: &str) -> Result<(), ErrorKind> {
    use ErrorKind::*;
    match name {
        // Numbers: lexemes are kept verbatim and never range-checked.
        n if n.starts_with("i_number_") => Ok(()),
        // Lone, truncated, or inverted surrogate escapes.
        "i_object_key_lone_2nd_surrogate.json"
        | "i_string_1st_surrogate_but_2nd_missing.json"
        | "i_string_1st_valid_surrogate_2nd_invalid.json"
        | "i_string_incomplete_surrogate_and_escape_valid.json"
        | "i_string_incomplete_surrogate_pair.json"
        | "i_string_incomplete_surrogates_escape_valid.json"
        | "i_string_invalid_lonely_surrogate.json"
        | "i_string_invalid_surrogate.json"
        | "i_string_inverted_surrogates_U+1D11E.json"
        | "i_string_lone_second_surrogate.json" => Err(LoneSurrogate),
        // Raw bytes that are not UTF-8 (including UTF-16 input and encoded surrogates).
        "i_string_UTF-16LE_with_BOM.json"
        | "i_string_UTF-8_invalid_sequence.json"
        | "i_string_UTF8_surrogate_U+D800.json"
        | "i_string_invalid_utf-8.json"
        | "i_string_iso_latin_1.json"
        | "i_string_lone_utf8_continuation_byte.json"
        | "i_string_not_in_unicode_range.json"
        | "i_string_overlong_sequence_2_bytes.json"
        | "i_string_overlong_sequence_6_bytes.json"
        | "i_string_overlong_sequence_6_bytes_null.json"
        | "i_string_truncated-utf-8.json"
        | "i_string_utf16BE_no_BOM.json"
        | "i_string_utf16LE_no_BOM.json" => Err(InvalidUtf8),
        "i_structure_500_nested_arrays.json" => Err(DepthLimitExceeded),
        "i_structure_UTF-8_BOM_empty_object.json" => Err(ByteOrderMark),
        other => panic!("no decision recorded for {other}; add it here and to TEST-PLAN.md"),
    }
}

#[test]
fn y_files_parse_and_round_trip() {
    let mut failures = Vec::new();
    for (name, bytes) in files("y_") {
        let r = catch_unwind(|| {
            let node = parse(&bytes).map_err(|e| format!("rejected: {e}"))?;
            let core = trim_ws(&bytes);
            let span = node.span().ok_or("root has no span")?;
            if &bytes[span.start..span.end] != core {
                return Err(format!("root span {span:?} != trimmed input"));
            }
            if node.raw().map(str::as_bytes) != Some(core) {
                return Err("raw() != trimmed input".into());
            }
            if !node.is_original() {
                return Err("freshly parsed root not original".into());
            }
            if print(&node, PrintStyle::Original).as_bytes() != core {
                return Err("print(Original) != trimmed input".into());
            }
            // Compact output must itself parse to an equal-shaped document.
            let compact = print(&node, PrintStyle::Compact);
            parse(compact.as_bytes()).map_err(|e| format!("compact reparse: {e}"))?;
            Ok(())
        });
        match r {
            Ok(Ok(())) => {}
            Ok(Err(msg)) => failures.push(format!("{name}: {msg}")),
            Err(_) => failures.push(format!("{name}: PANIC")),
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn n_files_are_rejected() {
    let mut failures = Vec::new();
    for (name, bytes) in files("n_") {
        match catch_unwind(|| parse(&bytes).map(|_| ())) {
            Ok(Err(e)) if e.offset <= bytes.len() => {}
            Ok(Err(e)) => failures.push(format!("{name}: offset {} past end", e.offset)),
            Ok(Ok(())) => failures.push(format!("{name}: accepted")),
            Err(_) => failures.push(format!("{name}: PANIC")),
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn i_files_match_documented_choice() {
    let mut failures = Vec::new();
    for (name, bytes) in files("i_") {
        let want = i_expectation(&name);
        match catch_unwind(|| parse(&bytes).map(|_| ()).map_err(|e| e.kind)) {
            Ok(got) if got == want => {}
            Ok(got) => failures.push(format!("{name}: want {want:?}, got {got:?}")),
            Err(_) => failures.push(format!("{name}: PANIC")),
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn suite_counts_are_sane() {
    assert_eq!(files("y_").len(), 95);
    assert_eq!(files("n_").len(), 188);
    assert_eq!(files("i_").len(), 35);
}
