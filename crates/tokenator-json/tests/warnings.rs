//! Parse warnings (issue #3): invalid UTF-8 inside strings, and numbers
//! outside the range JavaScript can represent.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;
use common::{num, string};
use std::borrow::Cow;
use tokenator_json::{
    Member, Node, ParseOptions, Parsed, PrintOptions, PrintStyle, Span, Value, Warning,
    WarningKind, parse, parse_with_options, print, print_bytes, print_with,
};

use WarningKind::*;

#[track_caller]
fn parsed(input: &[u8]) -> Parsed<'_> {
    match parse_with_options(input, &ParseOptions::default()) {
        Ok(p) => p,
        Err(e) => panic!("rejected {:?}: {e}", String::from_utf8_lossy(input)),
    }
}

fn warns(p: &Parsed<'_>) -> Vec<(usize, WarningKind)> {
    p.warnings.iter().map(|w| (w.offset, w.kind)).collect()
}

fn opts(style: PrintStyle) -> PrintOptions {
    PrintOptions {
        style,
        ..PrintOptions::default()
    }
}

// ---- invalid UTF-8 ----

#[test]
fn invalid_utf8_in_string_is_a_warning() {
    let input = b"[\"a\xffb\", \"ok\"]";
    let p = parsed(input);
    assert_eq!(warns(&p), [(3, InvalidUtf8)]);
    let s = p.node.index(0).unwrap();
    assert_eq!(string(s), "a\u{fffd}b");
    assert!(matches!(s.value(), Value::String(Cow::Owned(_))));
    assert_eq!(s.span(), Some(Span { start: 1, end: 6 }));
    assert_eq!(s.raw(), None, "raw() is None when the bytes are not UTF-8");
    assert_eq!(s.raw_bytes(), Some(&b"\"a\xffb\""[..]));
    assert_eq!(p.node.raw(), None);
    assert_eq!(p.node.raw_bytes(), Some(&input[..]));
    assert!(p.node.is_original());
    // A clean sibling is unaffected.
    let ok = p.node.index(1).unwrap();
    assert_eq!(ok.raw(), Some("\"ok\""));
    assert!(matches!(ok.value(), Value::String(Cow::Borrowed("ok"))));
}

#[test]
fn one_warning_per_replacement_character() {
    // Same replacement policy as String::from_utf8_lossy.
    let input = b"\"\xf0\x9f\x98 \xc0\xaf \xed\xa0\x80\"";
    let p = parsed(input);
    assert_eq!(
        string(&p.node),
        String::from_utf8_lossy(&input[1..input.len() - 1])
    );
    assert_eq!(
        warns(&p),
        [
            (1, InvalidUtf8),
            (5, InvalidUtf8),
            (6, InvalidUtf8),
            (8, InvalidUtf8),
            (9, InvalidUtf8),
            (10, InvalidUtf8),
        ]
    );
}

#[test]
fn invalid_utf8_mixed_with_escapes() {
    let p = parsed(b"\"\\n\xff\\u0041\"");
    assert_eq!(string(&p.node), "\n\u{fffd}A");
    assert_eq!(warns(&p), [(3, InvalidUtf8)]);
}

#[test]
fn invalid_utf8_in_key() {
    let input = b"{\"k\xc3\": 1, \"k\": 2}";
    let p = parsed(input);
    assert_eq!(warns(&p), [(3, InvalidUtf8)]);
    let m = &p.node.members().unwrap()[0];
    assert_eq!(m.key(), "k\u{fffd}");
    assert!(matches!(m.key(), Cow::Owned(_)));
    assert_eq!(m.key_span(), Some(Span { start: 1, end: 5 }));
    assert_eq!(m.key_raw(), None);
    assert_eq!(m.key_raw_bytes(), Some(&b"\"k\xc3\""[..]));
    assert_eq!(num(p.node.get("k\u{fffd}").unwrap()), "1");
    assert_eq!(num(p.node.get("k").unwrap()), "2");
}

#[test]
fn simple_parse_accepts_and_drops_warnings() {
    let node = parse(b"[\"\xff\", 1e999]").unwrap();
    assert_eq!(string(node.index(0).unwrap()), "\u{fffd}");
    assert_eq!(num(node.index(1).unwrap()), "1e999");
}

#[test]
fn errors_still_win_over_warnings() {
    let e = parse(b"[\"\xff\"").unwrap_err();
    assert_eq!(
        (e.kind, e.offset),
        (tokenator_json::ErrorKind::UnexpectedEnd, 4)
    );
    let e = parse(b"[\"\xff\x01\"]").unwrap_err();
    assert_eq!(
        (e.kind, e.offset),
        (tokenator_json::ErrorKind::ControlCharacterInString, 3)
    );
}

#[test]
fn printing_documents_with_invalid_utf8() {
    let input = b"{\"a\": \"x\xffy\",  \"b\": 1}";
    let p = parsed(input);
    let node = &p.node;
    // Exact bytes, all styles that keep original token text.
    assert_eq!(print_bytes(node, &opts(PrintStyle::Original)), input);
    assert_eq!(
        print_bytes(node, &opts(PrintStyle::Compact)),
        b"{\"a\":\"x\xffy\",\"b\":1}"
    );
    // String output is lossy.
    assert_eq!(
        print(node, PrintStyle::Original),
        String::from_utf8_lossy(input)
    );
    assert_eq!(
        print_with(node, &opts(PrintStyle::Compact)),
        "{\"a\":\"x\u{fffd}y\",\"b\":1}"
    );
    // Pretty prints the decoded text.
    assert_eq!(
        print(node, PrintStyle::Pretty),
        "{\n  \"a\": \"x\u{fffd}y\",\n  \"b\": 1\n}"
    );
}

#[test]
fn editing_next_to_invalid_utf8_keeps_its_bytes() {
    let input = b"[\"\xfe\" , 1]";
    let mut node = parsed(input).node;
    node.index_mut(1).unwrap().set_value(Value::Bool(true));
    assert_eq!(
        print_bytes(&node, &opts(PrintStyle::Original)),
        b"[\"\xfe\" , true]"
    );
    let Value::Array(xs) = node.value_mut() else {
        panic!()
    };
    xs.push(Node::new(Value::Null));
    let out = print_bytes(&node, &opts(PrintStyle::Original));
    assert!(out.starts_with(b"[\"\xfe\" , true"), "{out:?}");
    // Editing the bad string replaces its bytes entirely.
    node.index_mut(0)
        .unwrap()
        .set_value(Value::String("ok".into()));
    let out = print_bytes(&node, &opts(PrintStyle::Original));
    assert!(out.starts_with(b"[\"ok\" , true"), "{out:?}");
    assert!(std::str::from_utf8(&out).is_ok());
}

#[test]
fn invalid_utf8_key_survives_member_edits() {
    let mut node = parsed(b"{\"\x80\":0}").node;
    node.members_mut().unwrap()[0]
        .value_mut()
        .set_value(Value::Number("1".into()));
    assert_eq!(
        print_bytes(&node, &opts(PrintStyle::Original)),
        b"{\"\x80\":1}"
    );
    let Value::Object(ms) = node.value_mut() else {
        panic!()
    };
    ms.push(Member::new("z", Node::new(Value::Null)));
    let out = print_bytes(&node, &opts(PrintStyle::Original));
    assert!(out.starts_with(b"{\"\x80\":1"), "{out:?}");
}

// ---- numbers ----

#[test]
fn number_range_warnings() {
    let big = format!("1{}", "0".repeat(400));
    let cases: Vec<(&str, Option<WarningKind>)> = vec![
        ("0", None),
        ("-0", None),
        ("0.0", None),
        ("9007199254740991", None),
        ("-9007199254740991", None),
        ("9007199254740992", Some(UnsafeInteger)),
        ("-9007199254740992", Some(UnsafeInteger)),
        ("12345678901234567890", Some(UnsafeInteger)),
        // Not integer lexemes: no precision warning.
        ("9007199254740993.0", None),
        ("9007199254740993e0", None),
        ("1e16", None),
        // Overflow to infinity, which takes precedence over UnsafeInteger.
        ("1.8e308", Some(NumberOverflow)),
        ("-1e309", Some(NumberOverflow)),
        ("1E+400", Some(NumberOverflow)),
        (&big, Some(NumberOverflow)),
        ("1.7976931348623157e308", None),
        // Underflow of a non-zero lexeme to zero.
        ("1e-400", Some(NumberUnderflow)),
        ("-1.5E-400", Some(NumberUnderflow)),
        ("2e-324", Some(NumberUnderflow)),
        ("3e-324", None),
        ("5e-324", None),
        ("0e-400", None),
        ("-0.000e-999", None),
        ("0e999", None),
    ];
    for (lexeme, want) in cases {
        let want: Vec<_> = want.into_iter().map(|k| (2, k)).collect();
        let input = format!("[ {lexeme}]");
        let p = parsed(input.as_bytes());
        assert_eq!(warns(&p), want, "{lexeme}");
        assert_eq!(num(p.node.index(0).unwrap()), lexeme, "lexeme verbatim");
        assert_eq!(print(&p.node, PrintStyle::Original), input);
    }
}

#[test]
fn number_warning_offset_is_number_start() {
    let p = parsed(b"{\"exp\":  -1e999, \"n\": [1, 99999999999999999]}");
    assert_eq!(
        p.warnings,
        [
            Warning {
                offset: 9,
                kind: NumberOverflow
            },
            Warning {
                offset: 26,
                kind: UnsafeInteger
            },
        ]
    );
}

#[test]
fn warnings_sorted_by_offset_across_kinds() {
    let input = b"[\"\xff\", 9007199254740993, {\"\xfe\": 1e-999}]";
    let p = parsed(input);
    assert_eq!(
        warns(&p),
        [
            (2, InvalidUtf8),
            (6, UnsafeInteger),
            (26, InvalidUtf8),
            (30, NumberUnderflow),
        ]
    );
}

#[test]
fn clean_documents_have_no_warnings() {
    let p = parsed(br#"{"iat": 1700000000, "x": [1.5, -2, 0.1e-5, "\u00e9"]}"#);
    assert!(p.warnings.is_empty(), "{:?}", p.warnings);
}
