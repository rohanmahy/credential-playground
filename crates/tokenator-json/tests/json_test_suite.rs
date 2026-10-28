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

use tokenator_json::{
    ErrorKind, ParseOptions, PrintOptions, PrintStyle, Value, WarningKind, parse,
    parse_with_options, print, print_bytes,
};

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
#[derive(Debug, PartialEq)]
enum Expect {
    /// Accepted with exactly these warnings (offset, kind), in order.
    Accept(Vec<(usize, WarningKind)>),
    /// Rejected with this error kind.
    Reject(ErrorKind),
}

fn i_expectation(name: &str) -> Expect {
    use Expect::*;
    use WarningKind::*;
    let utf8 = |offs: &[usize]| Accept(offs.iter().map(|&o| (o, InvalidUtf8)).collect());
    match name {
        // Numbers: lexemes kept verbatim; JavaScript-range warnings (#3).
        "i_number_double_huge_neg_exp.json" | "i_number_real_underflow.json" => {
            Accept(vec![(1, NumberUnderflow)])
        }
        "i_number_huge_exp.json"
        | "i_number_neg_int_huge_exp.json"
        | "i_number_pos_double_huge_exp.json"
        | "i_number_real_neg_overflow.json"
        | "i_number_real_pos_overflow.json" => Accept(vec![(1, NumberOverflow)]),
        "i_number_too_big_neg_int.json"
        | "i_number_too_big_pos_int.json"
        | "i_number_very_big_negative_int.json" => Accept(vec![(1, UnsafeInteger)]),
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
        | "i_string_lone_second_surrogate.json" => Reject(ErrorKind::LoneSurrogate),
        // Invalid UTF-8 inside a string: accepted, one warning per U+FFFD
        // (same replacement policy as String::from_utf8_lossy).
        "i_string_UTF-8_invalid_sequence.json" => utf8(&[7]),
        "i_string_UTF8_surrogate_U+D800.json" => utf8(&[2, 3, 4]),
        "i_string_invalid_utf-8.json"
        | "i_string_iso_latin_1.json"
        | "i_string_lone_utf8_continuation_byte.json" => utf8(&[2]),
        "i_string_not_in_unicode_range.json" => utf8(&[2, 3, 4, 5]),
        "i_string_overlong_sequence_2_bytes.json" | "i_string_truncated-utf-8.json" => {
            utf8(&[2, 3])
        }
        "i_string_overlong_sequence_6_bytes.json"
        | "i_string_overlong_sequence_6_bytes_null.json" => utf8(&[2, 3, 4, 5, 6, 7]),
        // UTF-16 input: fails at the first NUL or non-UTF-8 byte outside a string.
        "i_string_UTF-16LE_with_BOM.json" | "i_string_utf16BE_no_BOM.json" => {
            Reject(ErrorKind::UnexpectedCharacter)
        }
        "i_string_utf16LE_no_BOM.json" => Reject(ErrorKind::UnexpectedCharacter),
        "i_structure_500_nested_arrays.json" => Reject(ErrorKind::DepthLimitExceeded),
        "i_structure_UTF-8_BOM_empty_object.json" => Reject(ErrorKind::ByteOrderMark),
        other => panic!("no decision recorded for {other}; add it here and to TEST-PLAN.md"),
    }
}

/// Run the i_ file and describe the outcome in the same shape as [`Expect`].
fn i_outcome(bytes: &[u8]) -> Result<Expect, String> {
    match parse_with_options(bytes, &ParseOptions::default()) {
        Err(e) => Ok(Expect::Reject(e.kind)),
        Ok(parsed) => {
            let node = &parsed.node;
            let core = trim_ws(bytes);
            if node.raw_bytes() != Some(core) {
                return Err("raw_bytes() != trimmed input".into());
            }
            let exact = print_bytes(node, &PrintOptions::default());
            if exact != core {
                return Err("print_bytes(Original) != trimmed input".into());
            }
            // Strings decode lossily; the raw text stays exact.
            if let Some(Value::String(s)) = node.index(0).map(|n| n.value()) {
                let inner = &core[2..core.len() - 2];
                if s.as_ref() != String::from_utf8_lossy(inner) {
                    return Err(format!("decoded {s:?} != lossy decoding"));
                }
            }
            let w = parsed.warnings.iter().map(|w| (w.offset, w.kind)).collect();
            Ok(Expect::Accept(w))
        }
    }
}

#[test]
fn y_files_parse_and_round_trip() {
    let mut failures = Vec::new();
    for (name, bytes) in files("y_") {
        let r = catch_unwind(|| {
            let parsed = parse_with_options(&bytes, &ParseOptions::default())
                .map_err(|e| format!("rejected: {e}"))?;
            if !parsed.warnings.is_empty() {
                return Err(format!("unexpected warnings {:?}", parsed.warnings));
            }
            let node = parsed.node;
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
        match catch_unwind(|| i_outcome(&bytes)) {
            Ok(Ok(got)) if got == want => {}
            Ok(Ok(got)) => failures.push(format!("{name}: want {want:?}, got {got:?}")),
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
fn suite_counts_are_sane() {
    assert_eq!(files("y_").len(), 95);
    assert_eq!(files("n_").len(), 188);
    assert_eq!(files("i_").len(), 35);
}
