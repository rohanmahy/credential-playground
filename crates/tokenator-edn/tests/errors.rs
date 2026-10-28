//! Malformed EDN: error kinds with byte offsets and 1-based line/column
//! positions, the error's `Display`, and the nesting depth limit.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::deep;
use tokenator_cbor::{EncodeMode, MAX_DEPTH, decode, encode};
use tokenator_edn::{EdnError, EdnErrorKind, Position, WarningKind, parse, parse_seq};

fn err(edn: &str) -> EdnError {
    match parse(edn) {
        Ok(_) => panic!("{edn:?} should not parse"),
        Err(e) => e,
    }
}

#[track_caller]
fn at(edn: &str, kind: EdnErrorKind, offset: usize, line: usize, column: usize) {
    let e = err(edn);
    assert_eq!(e.kind, kind, "{edn:?}");
    assert_eq!(
        e.pos,
        Position {
            offset,
            line,
            column
        },
        "{edn:?}"
    );
}

#[test]
fn positions_of_unexpected_characters() {
    at("@", EdnErrorKind::UnexpectedChar('@'), 0, 1, 1);
    at("[1,\n  @]", EdnErrorKind::UnexpectedChar('@'), 6, 2, 3);
    at("[1,\r\n@]", EdnErrorKind::UnexpectedChar('@'), 5, 2, 1);
    at("[1,\n\n\n  @]", EdnErrorKind::UnexpectedChar('@'), 8, 4, 3);
    at("{1: 2 3}", EdnErrorKind::UnexpectedChar('}'), 7, 1, 8);
    at("]", EdnErrorKind::UnexpectedChar(']'), 0, 1, 1);
}

#[test]
fn columns_count_characters() {
    at("\"\u{fc}\" x", EdnErrorKind::TrailingInput, 5, 1, 5);
    at(
        "[\"\u{1F600}\", @]",
        EdnErrorKind::UnexpectedChar('@'),
        9,
        1,
        7,
    );
    at("/ \u{2318} / @", EdnErrorKind::UnexpectedChar('@'), 8, 1, 7);
}

#[test]
fn positions_of_trailing_input() {
    at("[1, ]]", EdnErrorKind::TrailingInput, 5, 1, 6);
    at("1 2", EdnErrorKind::TrailingInput, 2, 1, 3);
    at("1\n# c\n2", EdnErrorKind::TrailingInput, 6, 3, 1);
}

#[test]
fn positions_of_unexpected_end() {
    at("[1, 2", EdnErrorKind::UnexpectedEnd, 5, 1, 6);
    at("\"abc", EdnErrorKind::UnexpectedEnd, 4, 1, 5);
    at("", EdnErrorKind::UnexpectedEnd, 0, 1, 1);
    at("1(\n", EdnErrorKind::UnexpectedEnd, 3, 2, 1);
    at("/* x", EdnErrorKind::UnexpectedEnd, 4, 1, 5);
}

#[test]
fn positions_point_at_the_construct() {
    // Numbers: the start of the literal.
    at("[00]", EdnErrorKind::InvalidNumber, 1, 1, 2);
    at("[1, 1e400]", EdnErrorKind::InvalidNumber, 4, 1, 5);
    // Escapes: the backslash.
    at("\"ab\\x\"", EdnErrorKind::InvalidEscape, 3, 1, 4);
    at("\"ab\\ud800\"", EdnErrorKind::InvalidCodePoint, 3, 1, 4);
    // Control characters: the character itself.
    at("\"a\tb\"", EdnErrorKind::ControlCharacter, 2, 1, 3);
    // Tag numbers and simple values: the start of the number.
    at(
        "[18446744073709551616(0)]",
        EdnErrorKind::OutOfRange,
        1,
        1,
        2,
    );
    at("simple(24)", EdnErrorKind::OutOfRange, 7, 1, 8);
    // Separators: the item that lacks one.
    at("[[][]]", EdnErrorKind::MissingSeparator, 3, 1, 4);
    // Encoding indicators: the underscore.
    at("[256_0]", EdnErrorKind::InvalidEncodingIndicator, 4, 1, 5);
    // Streamstrings: the opening parenthesis.
    at("[(_ \"a\", h'00')]", EdnErrorKind::InvalidChunks, 1, 1, 2);
    // Prefixes: the start of the prefix.
    at("[Dt'x']", EdnErrorKind::InvalidPrefix, 1, 1, 2);
}

#[test]
fn extension_errors_point_at_the_literal() {
    let e = err("[1,\n h'0']");
    assert!(matches!(e.kind, EdnErrorKind::Extension { ref prefix, .. } if prefix == "h"));
    assert_eq!(
        e.pos,
        Position {
            offset: 5,
            line: 2,
            column: 2
        }
    );
    let e = err("dt'2013-02-30T00:00:00Z'");
    assert!(
        matches!(e.kind, EdnErrorKind::Extension { ref prefix, ref message }
        if prefix == "dt" && !message.is_empty())
    );
    assert_eq!(e.pos.offset, 0);
}

#[test]
fn strict_mode_positions() {
    let strict = tokenator_edn::ParseOptions {
        strict: true,
        ..tokenator_edn::ParseOptions::default()
    };
    for (edn, kind, offset, line, column) in [
        ("[1,\n h'00 ...']", WarningKind::Ellipsis, 5, 2, 2),
        ("[1,\n (_ \"a\")]", WarningKind::Streamstring, 5, 2, 2),
        (
            "[1,\n 2_4]",
            WarningKind::ReservedEncodingIndicator("4".into()),
            6,
            2,
            3,
        ),
        ("[1]\n  # c", WarningKind::EolCommentAtEof, 6, 2, 3),
    ] {
        let e = tokenator_edn::parse_with(edn, &strict).unwrap_err();
        assert_eq!(e.kind, EdnErrorKind::Strict(kind), "{edn:?}");
        assert_eq!(
            e.pos,
            Position {
                offset,
                line,
                column
            },
            "{edn:?}"
        );
    }
}

#[test]
fn display_mentions_line_and_column() {
    let e = err("[1,\n  @]");
    let text = e.to_string();
    assert!(text.contains("line 2"), "{text}");
    assert!(text.contains("column 3"), "{text}");
    let e = err("dt'x'");
    assert!(e.to_string().contains("dt"), "{e}");
}

#[test]
fn sequence_errors_have_positions_too() {
    let e = parse_seq("1, 2,, 3").unwrap_err();
    assert_eq!(e.pos.offset, 5);
}

// ---------------------------------------------------------------- depth

fn nested(open: &str, leaf: &str, close: &str, n: usize) -> String {
    format!("{}{leaf}{}", open.repeat(n), close.repeat(n))
}

#[test]
fn depth_limit_matches_the_decoder() {
    deep(|| {
        for (open, close) in [("[", "]"), ("{0: ", "}"), ("1(", ")"), ("[_ ", "]")] {
            let ok = nested(open, "0", close, MAX_DEPTH);
            let item = parse(&ok).unwrap_or_else(|e| panic!("{open}: {e:?}"));
            assert!(decode(&encode(&item, EncodeMode::Preserve).unwrap()).is_ok());
            let too_deep = nested(open, "0", close, MAX_DEPTH + 1);
            assert_eq!(err(&too_deep).kind, EdnErrorKind::DepthLimit, "{open}");
        }
    });
}

#[test]
fn embedded_sequences_count_towards_depth() {
    deep(|| {
        assert!(parse(&nested("<<", "0", ">>", MAX_DEPTH)).is_ok());
        assert_eq!(
            err(&nested("<<", "0", ">>", MAX_DEPTH + 1)).kind,
            EdnErrorKind::DepthLimit
        );
        assert_eq!(
            err(&nested("h<<", "0", ">>", MAX_DEPTH + 1)).kind,
            EdnErrorKind::DepthLimit
        );
    });
}

#[test]
fn depth_bombs_fail_fast() {
    deep(|| {
        for open in ["[", "{", "1(", "<<", "[_ ", "{1: ", "foo<<"] {
            let bomb = open.repeat(1_000_000);
            let start = std::time::Instant::now();
            assert_eq!(err(&bomb).kind, EdnErrorKind::DepthLimit, "{open}");
            assert!(start.elapsed().as_secs() < 5, "{open} took too long");
        }
    });
}

#[test]
fn depth_error_position() {
    deep(|| {
        let e = err(&"[".repeat(MAX_DEPTH + 10));
        assert_eq!(e.kind, EdnErrorKind::DepthLimit);
        // The first item inside more than MAX_DEPTH containers.
        assert_eq!(e.pos.offset, MAX_DEPTH + 1);
    });
}

#[test]
fn large_inputs() {
    let big = format!("h'{}'", "ab".repeat(500_000));
    let item = parse(&big).unwrap();
    assert_eq!(encode(&item, EncodeMode::Preserve).unwrap().len(), 500_005);
    let many = format!("[{}]", "1, ".repeat(100_000));
    assert!(parse(&many).is_ok());
}
