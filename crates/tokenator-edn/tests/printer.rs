//! The printer: exact compact and indented output, text escaping, float
//! formatting, embedded CBOR, `DT''`/`IP''` forms, byte styles,
//! indefinite-string styles, and annotator comments.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::{enc, h, rt};
use tokenator_cbor::{EncodeMode, Item, Value, decode, encode};
use tokenator_edn::{
    ByteStyle, EmbeddedCbor, IndefiniteStringStyle, Path, PathSegment, PrintOptions, parse, print,
};

fn show(bytes: &[u8], opts: &PrintOptions) -> String {
    print(&decode(bytes).unwrap(), opts).text
}

fn show_edn(edn: &str, opts: &PrintOptions) -> String {
    show(&enc(edn), opts)
}

/// Prints and checks that the output re-encodes to the same bytes.
#[track_caller]
fn check(edn: &str, opts: &PrintOptions, want: &str) {
    let bytes = enc(edn);
    let text = show(&bytes, opts);
    assert_eq!(text, want, "printing {edn}");
    let back = parse(&text).unwrap_or_else(|e| panic!("{text:?}: {e:?}"));
    assert_eq!(encode(&back, EncodeMode::Preserve), bytes, "{text:?}");
}

// ---------------------------------------------------------------- compact

#[test]
fn compact_layout() {
    let o = PrintOptions::new();
    check("[1, [2, 3], {}]", &o, "[1, [2, 3], {}]");
    check("{1: [], \"a\": {2: 3}}", &o, "{1: [], \"a\": {2: 3}}");
    check("1(2(3))", &o, "1(2(3))");
    check("6([1, {2: 3}])", &o, "6([1, {2: 3}])");
    check("[_ [_ ], {_ }]", &o, "[_ [_ ], {_ }]");
    check("{h'00': null, [1]: true}", &o, "{h'00': null, [1]: true}");
    check("simple(59)", &o, "simple(59)");
    check("{simple(59): 1}", &o, "{simple(59): 1}");
}

// ---------------------------------------------------------------- indented

#[test]
fn indented_layout() {
    check(
        "{\"a\": [1, 2], \"b\": 3(h'00'), \"c\": {}, \"d\": []}",
        &PrintOptions::indented(2),
        "{\n  \"a\": [\n    1,\n    2\n  ],\n  \"b\": 3(h'00'),\n  \"c\": {},\n  \"d\": []\n}",
    );
}

#[test]
fn indent_width() {
    check(
        "[1, [2]]",
        &PrintOptions::indented(4),
        "[\n    1,\n    [\n        2\n    ]\n]",
    );
    check("[1, [2]]", &PrintOptions::indented(0), "[\n1,\n[\n2\n]\n]");
}

#[test]
fn indented_scalars_and_empty_containers() {
    let o = PrintOptions::indented(2);
    check("1", &o, "1");
    check("\"a\"", &o, "\"a\"");
    check("[]", &o, "[]");
    check("{}", &o, "{}");
    check("[_ ]", &o, "[_ ]");
    check("[_0 ]", &o, "[_0 ]");
}

#[test]
fn indented_tags() {
    let o = PrintOptions::indented(2);
    check("6([1, {2: 3}])", &o, "6([\n  1,\n  {\n    2: 3\n  }\n])");
    check("{1: 2([3])}", &o, "{\n  1: 2([\n    3\n  ])\n}");
    check("1(2(3))", &o, "1(2(3))");
}

#[test]
fn indented_indicators() {
    let o = PrintOptions::indented(2);
    check("[_ 1, [_ ]]", &o, "[_\n  1,\n  [_ ]\n]");
    check("[_0 1]", &o, "[_0\n  1\n]");
    check("{_ 1: 2}", &o, "{_\n  1: 2\n}");
    check(
        "(_ \"strea\", \"ming\")",
        &o,
        "(_\n  \"strea\",\n  \"ming\"\n)",
    );
}

#[test]
fn indented_container_keys() {
    check(
        "{[1]: 2}",
        &PrintOptions::indented(2),
        "{\n  [\n    1\n  ]: 2\n}",
    );
}

// ---------------------------------------------------------------- strings

#[test]
fn text_escaping() {
    let o = PrintOptions::new();
    check(
        "\"a\\nb\\t\\\"\\\\\\u0001\\u007f\u{fc}\"",
        &o,
        "\"a\\nb\\t\\\"\\\\\\u0001\u{7f}\u{fc}\"",
    );
    check("\"\\b\\f\\r\"", &o, "\"\\b\\f\\r\"");
    check("\"/\"", &o, "\"/\"");
    check("\"'\"", &o, "\"'\"");
    let ascii = PrintOptions {
        ascii: true,
        ..PrintOptions::new()
    };
    check("\"\u{fc}\u{1F600}\"", &ascii, "\"\\u00fc\\ud83d\\ude00\"");
    check("\"\u{7f}\"", &ascii, "\"\u{7f}\"");
}

#[test]
fn byte_styles() {
    let o = PrintOptions::new();
    check("h'fbff'", &o, "h'fbff'");
    check("'hi'", &o, "h'6869'");
    let b64 = PrintOptions {
        bytes: ByteStyle::Base64,
        ..PrintOptions::new()
    };
    check("h'fbff'", &b64, "b64'-_8'");
    check("h''", &b64, "b64''");
    check("h'12345678'", &b64, "b64'EjRWeA'");
}

#[test]
fn indefinite_string_styles() {
    let o = PrintOptions::new();
    check("ilbs<<'a', h'00'>>", &o, "(_ h'61', h'00')");
    check("''_", &o, "''_");
    check("\"\"_", &o, "\"\"_");
    let ilxs = PrintOptions {
        indefinite_strings: IndefiniteStringStyle::AppExtension,
        ..PrintOptions::new()
    };
    check("(_ \"a\", \"b\")", &ilxs, "ilts<<\"a\", \"b\">>");
    check("(_ \"a\"_0)", &ilxs, "ilts<<\"a\"_0>>");
    check("(_ h'01')", &ilxs, "ilbs<<h'01'>>");
    check("''_", &ilxs, "ilbs<<>>");
    check("\"\"_", &ilxs, "ilts<<>>");
}

// ---------------------------------------------------------------- floats

#[test]
fn float_formatting() {
    let o = PrintOptions::new();
    for (edn, want) in [
        ("1.0", "1.0"),
        ("-0.0", "-0.0"),
        ("0.1", "0.1"),
        ("123456.789", "123456.789"),
        ("100000.0", "100000.0"),
        ("9007199254740992.0", "9007199254740992.0"),
        ("1e16", "1.0e+16"),
        ("1.5e300", "1.5e+300"),
        ("0.00001", "0.00001"),
        ("0.000025", "0.000025"),
        ("9.5e-6", "9.5e-6"),
        ("5e-324", "5.0e-324"),
        ("-1.7976931348623157e+308", "-1.7976931348623157e+308"),
        ("0x1p-14", "0.00006103515625"),
        ("0x1p-24", "5.960464477539063e-8"),
    ] {
        check(edn, &o, want);
    }
}

#[test]
fn printed_floats_always_reparse_as_floats() {
    for bits in [
        0x3ff0_0000_0000_0000_u64,
        0x4340_0000_0000_0000,
        0x4630_0000_0000_0000,
        0x0000_0000_0000_0001,
        0x7fef_ffff_ffff_ffff,
        0x3e70_0000_0000_0000,
    ] {
        let f = f64::from_bits(bits);
        let text = print(&Item::float(f), &PrintOptions::new()).text;
        assert!(
            text.contains('.') || text.contains('e'),
            "{text} would parse as an integer"
        );
        let back = parse(&text).unwrap();
        assert!(
            matches!(back.value, Value::Float(g, _) if g.to_bits() == bits),
            "{text}"
        );
    }
}

// ---------------------------------------------------------------- embedded CBOR

fn embedded(mode: EmbeddedCbor) -> PrintOptions<'static> {
    PrintOptions {
        embedded_cbor: mode,
        ..PrintOptions::new()
    }
}

#[test]
fn embedded_off_by_default() {
    check(
        "24(<<\"IETF\">>)",
        &PrintOptions::new(),
        "24(h'6449455446')",
    );
    check("<<[1, 2]>>", &PrintOptions::new(), "h'820102'");
}

#[test]
fn embedded_containers_mode() {
    let o = embedded(EmbeddedCbor::Containers);
    check("24(<<\"IETF\">>)", &o, "24(<<\"IETF\">>)");
    check("63(<<1>>)", &o, "63(<<1>>)");
    check("<<[1, 2]>>", &o, "<<[1, 2]>>");
    check("<<{1: 2}>>", &o, "<<{1: 2}>>");
    check("<<1(1)>>", &o, "<<1(1)>>");
    check("h'01'", &o, "h'01'");
    check("h'0102'", &o, "h'0102'");
    check("h'ff'", &o, "h'ff'");
    check("h''", &o, "h''");
    check("h'8201'", &o, "h'8201'");
    check("24(h'ff')", &o, "24(h'ff')");
    check("24(h'0102')", &o, "24(h'0102')");
    check("[<<[1]>>, h'00']", &o, "[<<[1]>>, h'00']");
    check("<<<<[1]>>>>", &o, "h'428101'");
    check("<<[<<[1]>>]>>", &o, "<<[<<[1]>>]>>");
}

#[test]
fn embedded_any_item_mode() {
    let o = embedded(EmbeddedCbor::AnyItem);
    check("h'01'", &o, "<<1>>");
    check("h'0102'", &o, "h'0102'");
    check("<<\"IETF\">>", &o, "<<\"IETF\">>");
    check("<<1_0>>_0", &o, "<<1_0>>_0");
    check("(_ h'01')", &o, "(_ h'01')");
}

#[test]
fn embedded_indented() {
    check(
        "24(<<[1, 2]>>)",
        &PrintOptions {
            embedded_cbor: EmbeddedCbor::Containers,
            ..PrintOptions::indented(2)
        },
        "24(<<\n  [\n    1,\n    2\n  ]\n>>)",
    );
}

// ---------------------------------------------------------------- DT'' and IP''

#[test]
fn dt_literals() {
    let o = PrintOptions {
        dt_literals: true,
        ..PrintOptions::new()
    };
    check("1(1363896240)", &o, "DT'2013-03-21T20:04:00Z'");
    check("1(1363896240.5)", &o, "DT'2013-03-21T20:04:00.5Z'");
    check("1(-1)", &o, "DT'1969-12-31T23:59:59Z'");
    check("1(1.0)", &o, "DT'1970-01-01T00:00:01.0Z'");
    check("1(1.1)", &o, "DT'1970-01-01T00:00:01.1Z'");
    // Only where DT'' re-encodes exactly.
    check("1(1363896240_3)", &o, "1(1363896240_3)");
    check("1_0(1363896240)", &o, "1_0(1363896240)");
    check("1(1.5_2)", &o, "1(1.5_2)");
    check("1(1.0e-10)", &o, "1(1.0e-10)");
    check("1(253402300800)", &o, "1(253402300800)");
    check("1(\"text\")", &o, "1(\"text\")");
    check(
        "0(\"2013-03-21T20:04:00Z\")",
        &o,
        "0(\"2013-03-21T20:04:00Z\")",
    );
    check("1363896240", &o, "1363896240");
}

#[test]
fn ip_literals() {
    let o = PrintOptions {
        ip_literals: true,
        ..PrintOptions::new()
    };
    check("52(h'c000022a')", &o, "IP'192.0.2.42'");
    check(
        "54(h'20010db8000000000000000000000042')",
        &o,
        "IP'2001:db8::42'",
    );
    check("54([64, h'20010db8'])", &o, "IP'2001:db8::/64'");
    check("52([24, h'c00002'])", &o, "IP'192.0.2.0/24'");
    check(
        "54(h'00000000000000000000ffffc0000201')",
        &o,
        "IP'::ffff:192.0.2.1'",
    );
    check(
        "54(h'20010db8000000010000000000000001')",
        &o,
        "IP'2001:db8:0:1::1'",
    );
    check("52(h'c00002')", &o, "52(h'c00002')");
    check("52([24, h'c0000200'])", &o, "52([24, h'c0000200'])");
    check("54([_ 64, h'20010db8'])", &o, "54([_ 64, h'20010db8'])");
    check(
        "54([h'fe800000000000000000000000000001', 64, 42])",
        &o,
        "54([h'fe800000000000000000000000000001', 64, 42])",
    );
}

// ---------------------------------------------------------------- annotator

fn names(path: &Path, _: &Item) -> Option<String> {
    match path.segments() {
        [PathSegment::Key(0)] => Some("iss".into()),
        [PathSegment::Value(1)] => Some("val".into()),
        _ => None,
    }
}

#[test]
fn annotator_comments() {
    let o = PrintOptions {
        annotator: Some(&names),
        ..PrintOptions::new()
    };
    check(
        "{1: \"x\", 2: \"y\"}",
        &o,
        "{/ iss / 1: \"x\", 2: / val / \"y\"}",
    );
    let o = PrintOptions {
        annotator: Some(&names),
        ..PrintOptions::indented(2)
    };
    check(
        "{1: \"x\", 2: \"y\"}",
        &o,
        "{\n  / iss / 1: \"x\",\n  2: / val / \"y\"\n}",
    );
}

#[test]
fn annotator_on_root() {
    let root = |p: &Path, _: &Item| p.segments().is_empty().then(|| "root".to_string());
    let o = PrintOptions {
        annotator: Some(&root),
        ..PrintOptions::new()
    };
    check("[1]", &o, "/ root / [1]");
}

#[test]
fn annotator_comments_are_sanitized() {
    for comment in [
        "HMAC 256/64",
        "a */ b / c",
        "multi\nline",
        "",
        "/",
        "*",
        "**/",
        "#",
        "\u{fc}",
    ] {
        let c = comment.to_string();
        let ann = move |_: &Path, _: &Item| Some(c.clone());
        let o = PrintOptions {
            annotator: Some(&ann),
            ..PrintOptions::indented(2)
        };
        let bytes = enc("{1: [2, 3]}");
        let text = show(&bytes, &o);
        let back = parse(&text).unwrap_or_else(|e| panic!("{comment:?} gave {text:?}: {e:?}"));
        assert_eq!(encode(&back, EncodeMode::Preserve), bytes, "{text}");
    }
    let ann = |_: &Path, _: &Item| Some("HMAC 256/64".to_string());
    let o = PrintOptions {
        annotator: Some(&ann),
        ..PrintOptions::new()
    };
    assert_eq!(show_edn("4", &o), "/* HMAC 256/64 */ 4");
}

// ---------------------------------------------------------------- misc

#[test]
fn print_never_panics_on_odd_built_items() {
    let items = [
        // Chunks that no longer match the value.
        Item {
            chunks: vec![Item::text("x")],
            ..Item::text("y").with_width(tokenator_cbor::Width::Indefinite)
        },
        // Indefinite width on an integer.
        Item::int(5).with_width(tokenator_cbor::Width::Indefinite),
        // Chunks of mixed types.
        Item::indefinite_string(vec![Item::bytes(vec![1u8]), Item::text("a")]),
        Item::new(Value::Float(f64::NAN, tokenator_cbor::FloatWidth::F16)),
    ];
    // Not well-formed: printing must not panic, but nothing re-parses.
    let _ = print(&Item::simple(24), &PrintOptions::new());
    for item in items {
        let text = print(&item, &PrintOptions::new()).text;
        let back = parse(&text).unwrap_or_else(|e| panic!("{text:?}: {e:?}"));
        assert_eq!(
            encode(&back, EncodeMode::Preserve),
            encode(&item, EncodeMode::Preserve),
            "{text}"
        );
    }
}

#[test]
fn rendered_text_roundtrips_for_mixed_document() {
    // A COSE_Sign1-like document with nested embedded CBOR.
    let bytes = h(
        "d2 84 43 a10126 a1 04 42 3131 4c a2 01 63 697373 04 1a 5f5e1000 \
                   58 40 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    );
    rt(&bytes).unwrap();
}
