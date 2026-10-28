//! Warnings decided in issue #14, and strict mode, which turns them into
//! errors:
//!
//! 3. an ellipsis inside `h''`, or a tag 888 in the input, warns; the
//!    ellipsis becomes the draft-ietf-cbor-edn-literals-27 §5.2 "CPA888"
//!    form;
//! 4. the deprecated streamstring syntax `(_ …)` warns, and the printer's
//!    default output (`ilbs<<…>>`/`ilts<<…>>`) re-parses without warnings;
//! 5. an encoding indicator other than `_0`..`_3`, `_i` (and `_` for
//!    indefinite length) warns;
//! 7. an end-of-line comment at the end of the input without a line feed
//!    warns.
//!
//! From issue #7: a NaN other than the canonical `f97e00` warns, but is kept
//! as written.
//!
//! Unknown app-extensions keep their own option (`unknown_extensions`) and
//! are not affected by `strict`.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::{enc, h, hex};
use tokenator_cbor::{EncodeMode, decode, encode};
use tokenator_edn::{
    ELLIPSIS_TAG, EdnErrorKind, IndefiniteStringStyle, ParseOptions, Position, PrintOptions,
    WarningKind, parse, parse_with, print,
};

fn lenient() -> ParseOptions {
    ParseOptions::default()
}

fn strict() -> ParseOptions {
    ParseOptions {
        strict: true,
        ..ParseOptions::default()
    }
}

/// Warnings as (kind, offset).
fn warnings(edn: &str) -> Vec<(WarningKind, usize)> {
    parse_with(edn, &lenient())
        .unwrap_or_else(|e| panic!("{edn:?}: {e:?}"))
        .warnings
        .into_iter()
        .map(|w| (w.kind, w.pos.offset))
        .collect()
}

/// The strict-mode error as (kind, offset).
fn strict_error(edn: &str) -> (EdnErrorKind, usize) {
    match parse_with(edn, &strict()) {
        Ok(_) => panic!("{edn:?} should fail in strict mode"),
        Err(e) => (e.kind, e.pos.offset),
    }
}

#[track_caller]
fn clean(edn: &str) {
    assert_eq!(warnings(edn), [], "{edn:?}");
    assert!(parse_with(edn, &strict()).is_ok(), "{edn:?} in strict mode");
}

#[track_caller]
fn warns(edn: &str, kind: WarningKind, offset: usize) {
    assert_eq!(warnings(edn), [(kind.clone(), offset)], "{edn:?}");
    assert_eq!(
        strict_error(edn),
        (EdnErrorKind::Strict(kind), offset),
        "{edn:?}"
    );
}

#[track_caller]
fn same(a: &str, b: &str) {
    assert_eq!(hex(&enc(a)), hex(&enc(b)), "{a:?} vs {b:?}");
}

// ---------------------------------------------------------------- 3. ellipsis

#[test]
fn ellipsis_tag_number() {
    assert_eq!(ELLIPSIS_TAG, 888);
}

#[test]
fn ellipsis_in_h_becomes_tag_888() {
    same("h'4711...0815'", "888([h'4711', 888(null), h'0815'])");
    same("h'...'", "888(null)");
    same("h'4711...'", "888([h'4711', 888(null)])");
    same("h'...0815'", "888([888(null), h'0815'])");
    same("h'47 ... ... 11'", "888([h'47', 888(null), h'11'])");
    same("h'47......11'", "888([h'47', 888(null), h'11'])");
    same("h'47 /c/ ... # c\n 11'", "888([h'47', 888(null), h'11'])");
    same(
        "h'47...11...22'",
        "888([h'47', 888(null), h'11', 888(null), h'22'])",
    );
    same("h`4711...0815`", "888([h'4711', 888(null), h'0815'])");
    same("h<<\"4711...0815\">>", "888([h'4711', 888(null), h'0815'])");
    assert_enc_888("h'4711...0815'", "d9 0378 83 42 4711 d9 0378 f6 42 0815");
}

fn assert_enc_888(edn: &str, want: &str) {
    assert_eq!(hex(&enc(edn)), hex(&h(want)));
}

#[test]
fn ellipsis_needs_whole_bytes() {
    let e = parse("h'4...'").unwrap_err();
    assert!(
        matches!(e.kind, EdnErrorKind::Extension { ref prefix, .. } if prefix == "h"),
        "{e:?}"
    );
    assert!(parse("h'..'").is_err(), "two dots are not an ellipsis");
}

#[test]
fn ellipsis_warns_once_per_literal() {
    warns("h'4711...0815'", WarningKind::Ellipsis, 0);
    warns("[1, h'00...']", WarningKind::Ellipsis, 4);
    warns("h'47...11...22'", WarningKind::Ellipsis, 0);
}

#[test]
fn tag_888_in_the_input_warns() {
    warns("888(null)", WarningKind::Ellipsis, 0);
    warns("[1, 888(null)]", WarningKind::Ellipsis, 4);
    warns("888_1(null)", WarningKind::Ellipsis, 0);
    let w = warnings("[888([h'00', 888(null)])]");
    assert_eq!(
        w.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
        [WarningKind::Ellipsis, WarningKind::Ellipsis]
    );
    assert_eq!(strict_error("[888([h'00', 888(null)])]").1, 1);
    clean("[887(null), 889(null), 8880(null)]");
}

#[test]
fn ellipsis_values_print_as_tags() {
    let bytes = enc("h'4711...0815'");
    assert_eq!(
        print(&decode(&bytes).unwrap(), &PrintOptions::new()).text,
        "888([h'4711', 888(null), h'0815'])"
    );
    common::rt(&bytes).unwrap();
}

// ---------------------------------------------------------------- 4. streamstrings

#[test]
fn streamstrings_warn() {
    warns("(_ \"a\")", WarningKind::Streamstring, 0);
    warns("(_ h'0102', h'030405')", WarningKind::Streamstring, 0);
    warns("[1, (_ h'00')]", WarningKind::Streamstring, 4);
    warns("<<(_ \"a\")>>", WarningKind::Streamstring, 2);
    // The result is unchanged.
    assert_eq!(hex(&enc("(_ \"a\", \"b\")")), "7f61616162ff");
}

#[test]
fn replacement_forms_do_not_warn() {
    clean("ilts<<\"a\", \"b\">>");
    clean("ilbs<<>>");
    clean("ilbs<<'Hello '_0, 'world'>>");
    // The empty forms of §4.3 are not the streamstring syntax.
    clean("''_");
    clean("\"\"_");
}

#[test]
fn default_printer_output_parses_without_warnings() {
    for bytes in [
        "5f 4101 ff",
        "7f 6161 6162 ff",
        "5fff",
        "7fff",
        "7f 780161 ff",
        "9f 5f4101ff 7f6161ff 5fff 7fff 1801 ff",
        "bf 7f6161ff 5f40ff ff",
        "a1 01 d818 44 7f6161ff",
        "c2 49 010000000000000000",
        // Non-canonical NaNs (fa7fc00000, fb7ff8000000000001) warn by design
        // (#7); see non_canonical_nans_warn_but_keep_their_bits.
    ] {
        let item = decode(&h(bytes)).unwrap().into_owned();
        for opts in [PrintOptions::new(), PrintOptions::indented(2)] {
            let text = print(&item, &opts).text;
            let parsed =
                parse_with(&text, &strict()).unwrap_or_else(|e| panic!("{bytes}: {text:?}: {e:?}"));
            assert!(
                parsed.warnings.is_empty(),
                "{text:?}: {:?}",
                parsed.warnings
            );
            assert_eq!(
                encode(&parsed.items[0], EncodeMode::Preserve).unwrap(),
                h(bytes),
                "{text:?}"
            );
        }
    }
}

#[test]
fn old_syntax_is_still_available_in_the_printer() {
    let item = decode(&h("7f 6161 6162 ff")).unwrap().into_owned();
    let opts = PrintOptions {
        indefinite_strings: IndefiniteStringStyle::Streamstring,
        ..PrintOptions::new()
    };
    let text = print(&item, &opts).text;
    assert_eq!(text, "(_ \"a\", \"b\")");
    assert_eq!(
        warnings(&text),
        [(WarningKind::Streamstring, 0)],
        "the old syntax warns when read back"
    );
}

// ---------------------------------------------------------------- 5. encoding indicators

#[test]
fn standard_indicators_do_not_warn() {
    clean("[_ 1_0, {_1 1: 2}, 1_i(3_2), 1.5_3, h'00'_3, [_i ], {_ }]");
    clean("[_0 ]");
    clean("<<1_1>>");
}

#[test]
fn other_indicators_warn() {
    for (edn, ei, offset) in [
        ("1_4", "4", 1),
        ("1_5", "5", 1),
        ("1_6", "6", 1),
        ("1_7", "7", 1),
        ("1_x", "x", 1),
        ("1_i0", "i0", 1),
        ("1_00", "00", 1),
        ("[_foo 1]", "foo", 1),
        ("[1, \"a\"_9]", "9", 7),
        ("1_4(2)", "4", 1),
    ] {
        warns(
            edn,
            WarningKind::ReservedEncodingIndicator(ei.into()),
            offset,
        );
    }
}

#[test]
fn ignored_indicators_on_bignums_warn() {
    warns(
        "18446744073709551616_1",
        WarningKind::IgnoredEncodingIndicator,
        20,
    );
}

// ---------------------------------------------------------------- 7. comments at EOF

#[test]
fn eol_comment_at_eof_warns() {
    warns("1 # c", WarningKind::EolCommentAtEof, 2);
    warns("1 // c", WarningKind::EolCommentAtEof, 2);
    warns("[1] #", WarningKind::EolCommentAtEof, 4);
    let e = parse_with("1\n# c", &strict()).unwrap_err();
    assert_eq!(
        e.pos,
        Position {
            offset: 2,
            line: 2,
            column: 1
        }
    );
    // Accepted, with the same result, outside strict mode.
    assert_eq!(hex(&enc("1 # c")), "01");
}

#[test]
fn terminated_and_inner_comments_do_not_warn() {
    clean("1 # c\n");
    clean("1 # c\r\n");
    clean("1 /c/");
    clean("[1, # c\n2]");
    clean("# c\n1");
    // Inside h'' and b64'' the content grammar allows a final comment.
    clean("h'00 # c'");
    clean("b64'AQ # c'");
}

#[test]
fn eol_comment_at_eof_in_sequences() {
    let opts = ParseOptions {
        sequence: true,
        ..ParseOptions::default()
    };
    let parsed = parse_with("# only a comment", &opts).unwrap();
    assert!(parsed.items.is_empty());
    assert_eq!(
        parsed.warnings.iter().map(|w| &w.kind).collect::<Vec<_>>(),
        [&WarningKind::EolCommentAtEof]
    );
    let strict_seq = ParseOptions {
        sequence: true,
        strict: true,
        ..ParseOptions::default()
    };
    assert!(parse_with("1, 2 # c", &strict_seq).is_err());
}

// ---------------------------------------------------------------- strict mode

#[test]
fn strict_mode_leaves_unknown_extensions_to_their_option() {
    let parsed = parse_with("cri'x'", &strict()).unwrap();
    assert_eq!(
        parsed.warnings.iter().map(|w| &w.kind).collect::<Vec<_>>(),
        [&WarningKind::UnknownExtension("cri".into())]
    );
}

#[test]
fn strict_mode_reports_the_first_warning() {
    let edn = "[(_ \"a\"), 1_4, h'...'] # c";
    assert_eq!(
        warnings(edn)
            .into_iter()
            .map(|(k, _)| k)
            .collect::<Vec<_>>(),
        [
            WarningKind::Streamstring,
            WarningKind::ReservedEncodingIndicator("4".into()),
            WarningKind::Ellipsis,
            WarningKind::EolCommentAtEof,
        ]
    );
    assert_eq!(
        strict_error(edn),
        (EdnErrorKind::Strict(WarningKind::Streamstring), 1)
    );
}

#[test]
fn plain_parse_is_lenient() {
    for edn in ["(_ \"a\")", "1_4", "h'00...'", "888(null)", "1 # c"] {
        assert!(parse(edn).is_ok(), "{edn:?}");
    }
}

#[test]
fn strict_error_display() {
    let e = parse_with("[1_4]", &strict()).unwrap_err();
    let text = e.to_string();
    assert!(text.contains("line 1"), "{text}");
    assert!(text.contains("column 3"), "{text}");
}

// ------------------------------------------------------- #7 non-canonical NaN

#[test]
fn canonical_nan_does_not_warn() {
    for edn in [
        "NaN",
        "NaN_1",
        "float'7e00'",
        "float'7fc00000'",
        "[NaN, 1.5]",
    ] {
        clean(edn);
    }
}

#[test]
fn non_canonical_nans_warn_but_keep_their_bits() {
    for (edn, offset, bytes) in [
        ("float'7fc00001'", 0, "fa7fc00001"),
        ("float'7e01'", 0, "f97e01"),
        ("float'fe00'", 0, "f9fe00"),
        ("float'7c01'", 0, "f97c01"),
        ("float'7ff0000000000001'", 0, "fb7ff0000000000001"),
        ("NaN_2", 0, "fa7fc00000"),
        ("NaN_3", 0, "fb7ff8000000000000"),
        ("float'7ff8000000000001'", 0, "fb7ff8000000000001"),
        ("float'7e00'_2", 0, "fa7fc00000"),
        ("[1, float'7e01']", 4, "8201f97e01"),
        ("{float'7e01': 0}", 1, "a1f97e0100"),
    ] {
        warns(edn, WarningKind::NonCanonicalNaN, offset);
        assert_eq!(hex(&enc(edn)), bytes, "{edn}");
    }
}

#[test]
fn printed_non_canonical_nans_reparse_with_a_warning() {
    let input = h("fa7fc00001");
    let item = decode(&input).unwrap();
    let text = print(&item, &PrintOptions::new()).text;
    warns(&text, WarningKind::NonCanonicalNaN, 0);
    let back = parse(&text).unwrap();
    assert_eq!(
        encode(&back, EncodeMode::Preserve).unwrap(),
        h("fa7fc00001")
    );
    assert_eq!(
        encode(&back, EncodeMode::PreferredPlus).unwrap(),
        h("f97e00")
    );
}
