//! Pretty normalizes string escapes (issue #4.5). Original and Compact keep
//! the original token text.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;
use common::p;
use tokenator_json::{PrintStyle, Value, print};

use PrintStyle::{Compact, Original, Pretty};

#[track_caller]
fn pretty(input: &str, want: &str) {
    assert_eq!(print(&p(input), Pretty), want, "input {input}");
}

#[test]
fn printable_ascii_is_unescaped() {
    pretty(r#""\u0041\u0062\/\u0020\u007e\u007E""#, r#""Ab/ ~~""#);
    pretty(r#""plain text""#, r#""plain text""#);
}

#[test]
fn quote_and_backslash_stay_escaped() {
    pretty(r#""\u0022\u005c\u005C""#, r#""\"\\\\""#);
    pretty(r#""\"\\""#, r#""\"\\""#);
}

#[test]
fn controls_use_short_or_lowercase_u_escapes() {
    pretty(r#""\u000a\u000D\u0009\u0008\u000c""#, r#""\n\r\t\b\f""#);
    pretty(
        r#""\u0000\u001F\u001f\u000B""#,
        r#""\u0000\u001f\u001f\u000b""#,
    );
    pretty(r#""\n\t""#, r#""\n\t""#);
}

#[test]
fn above_7e_keeps_original_form() {
    pretty(r#""\u00e9\u00E9é""#, r#""\u00e9\u00E9é""#);
    pretty(
        r#""\uD83D\uDE00😀\ud83d\ude00""#,
        r#""\uD83D\uDE00😀\ud83d\ude00""#,
    );
    pretty(r#""\u007f""#, r#""\u007f""#);
    pretty("\"\u{7f}\"", "\"\u{7f}\"");
    pretty(r#""\u0080\u2028""#, r#""\u0080\u2028""#);
}

#[test]
fn mixed_string_normalizes_only_what_it_should() {
    pretty(
        r#""a\u0041\u00e9\/\u000A\"x\uD834\uDD1E""#,
        r#""aA\u00e9/\n\"x\uD834\uDD1E""#,
    );
}

#[test]
fn keys_are_normalized_too() {
    pretty(
        r#"{"\u0061\/": "\u0062", "\u00e9": ["\u0063"]}"#,
        "{\n  \"a/\": \"b\",\n  \"\\u00e9\": [\n    \"c\"\n  ]\n}",
    );
}

#[test]
fn original_and_compact_keep_original_escapes() {
    let input = r#"{ "\u0061" : "\u0041\/\u000A" }"#;
    let node = p(input);
    assert_eq!(print(&node, Original), input);
    assert_eq!(print(&node, Compact), r#"{"\u0061":"\u0041\/\u000A"}"#);
    assert_eq!(print(&node, Pretty), "{\n  \"a\": \"A/\\n\"\n}");
}

#[test]
fn edited_strings_in_pretty_use_minimal_escaping() {
    let mut node = p(r#"["\u0041"]"#);
    node.index_mut(0)
        .unwrap()
        .set_value(Value::String("q\"/\u{1}é".into()));
    assert_eq!(print(&node, Pretty), "[\n  \"q\\\"/\\u0001é\"\n]");
}

#[test]
fn pretty_is_idempotent_and_preserves_values() {
    let input = r#"{"\u0061":"\u0041\/\u000A\u00e9\uD834\uDD1E\u0000"}"#;
    let once = print(&p(input), Pretty);
    let twice = print(&p(&once), Pretty);
    assert_eq!(once, twice);
    common::assert_same(&p(&once), &p(input));
}
