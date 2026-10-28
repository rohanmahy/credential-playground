//! Error kinds and offsets for malformed input.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use tokenator_json::{
    DEFAULT_MAX_DEPTH, ErrorKind, JsonError, ParseOptions, parse, parse_with_options,
};

use ErrorKind::*;

#[track_caller]
fn err(input: &[u8]) -> JsonError {
    match parse(input) {
        Ok(n) => panic!("accepted {:?}: {n:?}", String::from_utf8_lossy(input)),
        Err(e) => e,
    }
}

#[track_caller]
fn expect(input: &[u8], kind: ErrorKind, offset: usize) {
    let e = err(input);
    assert_eq!(
        (e.kind, e.offset),
        (kind, offset),
        "input {:?}",
        String::from_utf8_lossy(input)
    );
}

#[test]
fn truncated_input_is_unexpected_end_at_len() {
    for input in [
        "",
        "   ",
        "{",
        "[",
        "{\"a\"",
        "{\"a\":",
        "{\"a\":1",
        "{\"a\":1,",
        "[1,2",
        "[1,",
        "\"abc",
        "\"a\\",
        "\"\\u00",
        "\"\\ud800",
        "tru",
        "fals",
        "n",
        "-",
        "1.",
        "1e",
        "1e+",
        "[\"a\",{",
    ] {
        expect(input.as_bytes(), UnexpectedEnd, input.len());
    }
}

#[test]
fn trailing_characters() {
    expect(b"{} x", TrailingCharacters, 3);
    expect(b"1 2", TrailingCharacters, 2);
    expect(b"{}}", TrailingCharacters, 2);
    expect(b"[1]]", TrailingCharacters, 3);
    expect(b"\"a\"\"b\"", TrailingCharacters, 3);
    expect(b"[1]\0", TrailingCharacters, 3);
    expect(b"null\n,", TrailingCharacters, 5);
    expect(b"0 /* comment */", TrailingCharacters, 2);
}

#[test]
fn byte_order_mark() {
    expect(b"\xEF\xBB\xBF{}", ByteOrderMark, 0);
    expect(b"\xEF\xBB\xBF", ByteOrderMark, 0);
    // Not at the start: it's just an unexpected (valid UTF-8) character.
    expect(b" \xEF\xBB\xBF{}", UnexpectedCharacter, 1);
    expect(b"[\xEF\xBB\xBF]", UnexpectedCharacter, 1);
    // Inside a string a U+FEFF is ordinary content.
    assert!(parse("\"\u{feff}\"".as_bytes()).is_ok());
}

#[test]
fn lone_and_inverted_surrogates() {
    expect(br#"["\ud800"]"#, LoneSurrogate, 2);
    expect(br#"["ab\udc00"]"#, LoneSurrogate, 4);
    expect(br#"["\uDBFF\u0041"]"#, LoneSurrogate, 2);
    expect(br#"["\ud800\n"]"#, LoneSurrogate, 2);
    expect(br#"["\ud800x"]"#, LoneSurrogate, 2);
    expect(br#"["\udd1e\ud834"]"#, LoneSurrogate, 2);
    expect(br#"["\ud834\udd1e\ud800"]"#, LoneSurrogate, 14);
    expect(br#"{"\udfaa":0}"#, LoneSurrogate, 2);
    expect(br#"["\ud800\ud800"]"#, LoneSurrogate, 2);
    // A valid pair is fine.
    assert!(parse(br#"["\uD834\uDD1E"]"#).is_ok());
}

#[test]
fn invalid_utf8() {
    expect(b"[\"\xff\"]", InvalidUtf8, 2);
    expect(b"\xc3", InvalidUtf8, 0);
    expect(b"\"\xc0\xaf\"", InvalidUtf8, 1);
    expect(b"{\"a\xed\xa0\x80\":1}", InvalidUtf8, 3);
    expect(b"\"\xf4\x90\x80\x80\"", InvalidUtf8, 1);
    // Whole input is validated before grammar errors are reported.
    expect(b"[1]\xff", InvalidUtf8, 3);
    expect(b"\x00[\xe9]", InvalidUtf8, 2);
}

#[test]
fn control_characters_in_strings() {
    expect(b"[\"a\tb\"]", ControlCharacterInString, 3);
    expect(b"\"\x00\"", ControlCharacterInString, 1);
    expect(b"\"\x1f\"", ControlCharacterInString, 1);
    expect(b"{\"a\nb\":1}", ControlCharacterInString, 3);
    // DEL and C1 controls are allowed by RFC 8259.
    assert!(parse(b"\"\x7f\"").is_ok());
    assert!(parse("\"\u{85}\"".as_bytes()).is_ok());
}

#[test]
fn invalid_escapes() {
    expect(br#""\x""#, InvalidEscape, 1);
    expect(br#""ab\'""#, InvalidEscape, 3);
    expect(br#""\U0041""#, InvalidEscape, 1);
    expect(br#""\u12G4""#, InvalidEscape, 1);
    expect(br#""\u 123""#, InvalidEscape, 1);
    expect(br#"{"\a":1}"#, InvalidEscape, 2);
}

#[test]
fn invalid_numbers() {
    expect(b"[01]", InvalidNumber, 2);
    expect(b"[-01]", InvalidNumber, 3);
    expect(b"[1.]", InvalidNumber, 3);
    expect(b"[1.e5]", InvalidNumber, 3);
    expect(b"[1e+]", InvalidNumber, 4);
    expect(b"[-a]", InvalidNumber, 2);
    expect(b"[-Infinity]", InvalidNumber, 2);
    expect(b"[1ea]", InvalidNumber, 3);
    // Not a number start at all.
    expect(b"[.5]", UnexpectedCharacter, 1);
    expect(b"[+1]", UnexpectedCharacter, 1);
}

#[test]
fn unexpected_characters() {
    expect(b"[1,]", UnexpectedCharacter, 3);
    expect(b"{\"a\":1,}", UnexpectedCharacter, 7);
    expect(b"{,}", UnexpectedCharacter, 1);
    expect(b"{a:1}", UnexpectedCharacter, 1);
    expect(b"{\"a\" 1}", UnexpectedCharacter, 5);
    expect(b"{\"a\":1 \"b\":2}", UnexpectedCharacter, 7);
    expect(b"[1 2]", UnexpectedCharacter, 3);
    expect(b"{1:1}", UnexpectedCharacter, 1);
    expect(b"nulL", UnexpectedCharacter, 3);
    expect(b"True", UnexpectedCharacter, 0);
    expect(b"'a'", UnexpectedCharacter, 0);
    expect(b"NaN", UnexpectedCharacter, 0);
    expect(b"Infinity", UnexpectedCharacter, 0);
    expect(b"/* */ 1", UnexpectedCharacter, 0);
    expect(b"\x0c1", UnexpectedCharacter, 0);
    expect("\u{a0}1".as_bytes(), UnexpectedCharacter, 0);
    expect(b"[1}", UnexpectedCharacter, 2);
    expect(b"{\"a\":1]", UnexpectedCharacter, 6);
}

#[test]
fn depth_limit_boundary() {
    let two = ParseOptions { max_depth: 2 };
    assert!(parse_with_options(b"[[1]]", &two).is_ok());
    assert!(parse_with_options(b"[[],{},[]]", &two).is_ok());
    let e = parse_with_options(b"[[[1]]]", &two).unwrap_err();
    assert_eq!((e.kind, e.offset), (DepthLimitExceeded, 2));
    let e = parse_with_options(br#"{"a":{"b":{}}}"#, &two).unwrap_err();
    assert_eq!((e.kind, e.offset), (DepthLimitExceeded, 10));

    let zero = ParseOptions { max_depth: 0 };
    assert!(parse_with_options(b"\"scalar\"", &zero).is_ok());
    let e = parse_with_options(b" []", &zero).unwrap_err();
    assert_eq!((e.kind, e.offset), (DepthLimitExceeded, 1));
}

#[test]
fn default_depth_limit() {
    assert_eq!(ParseOptions::default().max_depth, DEFAULT_MAX_DEPTH);
    let d = DEFAULT_MAX_DEPTH;
    let ok = format!("{}{}", "[".repeat(d), "]".repeat(d));
    assert!(parse(ok.as_bytes()).is_ok());
    let deep = format!("{}{}", "[".repeat(d + 1), "]".repeat(d + 1));
    expect(deep.as_bytes(), DepthLimitExceeded, d);
}

#[test]
fn nesting_bombs_error_without_stack_overflow() {
    let d = DEFAULT_MAX_DEPTH;
    expect("[".repeat(100_000).as_bytes(), DepthLimitExceeded, d);
    expect(
        "{\"a\":".repeat(100_000).as_bytes(),
        DepthLimitExceeded,
        5 * d,
    );
    expect(
        "[{\"\":".repeat(50_000).as_bytes(),
        DepthLimitExceeded,
        d / 2 * 5,
    );
    let balanced = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    expect(balanced.as_bytes(), DepthLimitExceeded, d);
}

#[test]
fn error_display_mentions_offset() {
    let e = err(b"[1,]");
    let msg = e.to_string();
    assert!(msg.contains('3'), "{msg}");
    let _: &dyn std::error::Error = &e;
}
