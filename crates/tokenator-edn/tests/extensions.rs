//! App-extensions (draft-ietf-cbor-edn-literals-28 §3, §5.2): the built-ins
//! `h`, `b64`, `dt`, `ip`, `hash` (§3.4), `b1`, `t1`, `ilbs`, `ilts`, `float`,
//! unknown prefixes as opaque tag-999 values, and custom extensions.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::{assert_enc, diag, enc, hex};
use tokenator_cbor::{EncodeMode, Item, Value, decode, encode};
use tokenator_edn::{
    AppExtension, EdnErrorKind, ExtError, Extensions, ParseOptions, PrintOptions,
    UNRESOLVED_EXTENSION_TAG, UnknownExtensions, WarningKind, parse, parse_with, print,
};

#[track_caller]
fn same(a: &str, b: &str) {
    assert_eq!(hex(&enc(a)), hex(&enc(b)), "{a:?} vs {b:?}");
}

#[track_caller]
fn ext_err(edn: &str) -> String {
    match parse(edn) {
        Err(e) => match e.kind {
            EdnErrorKind::Extension { prefix, .. } => prefix,
            other => panic!("{edn:?}: expected an extension error, got {other:?}"),
        },
        Ok(item) => panic!(
            "{edn:?} parsed as {}",
            hex(&encode(&item, EncodeMode::Preserve))
        ),
    }
}

fn warnings_of(edn: &str, options: &ParseOptions) -> Vec<WarningKind> {
    parse_with(edn, options)
        .unwrap()
        .warnings
        .into_iter()
        .map(|w| w.kind)
        .collect()
}

// ---------------------------------------------------------------- h

#[test]
fn h_blank_space_and_comments() {
    let hello = "h'48656c6c6f20776f726c64'";
    same(hello, "h'48 65 6c 6c 6f 20 77 6f 72 6c 64'");
    same(hello, "h'4 86 56c 6c6f\n  20776 f726c64'");
    same(
        hello,
        "h'48 65 6c /doubled l!/ 6c 6f # hello\n  20 /space/\n  77 6f 72 6c 64' /world/",
    );
    same(hello, "'Hello world'");
    same("h'/head/ 63 /contents/ 66 6f 6f'", "<<\"foo\">>");
    assert_enc("h''", "40");
    assert_enc("h'  '", "40");
    assert_enc("h'0 /c/ 1'", "41 01");
    assert_enc("h'00 /* c / still c */ 01'", "42 0001");
    assert_enc("h'00 // c\n01'", "42 0001");
    assert_enc("h'00 # trailing comment'", "41 00");
    assert_enc("h'AbCd'", "42 abcd");
    assert_enc("h'00\r\n01'", "42 0001");
}

#[test]
fn h_other_input_forms() {
    assert_enc("h`00ff`", "42 00ff");
    assert_enc("h`00 # c\nff`", "42 00ff");
    assert_enc("h<<\"00ff\">>", "42 00ff");
    assert_enc("h<<'00ff'>>", "42 00ff");
}

#[test]
fn h_errors() {
    assert_eq!(ext_err("h'0'"), "h");
    assert_eq!(ext_err("h'zz'"), "h");
    assert_eq!(ext_err("h'0x00'"), "h");
    assert_eq!(ext_err("h'00 /unterminated'"), "h");
    assert_eq!(ext_err("h<<1>>"), "h");
    assert_eq!(ext_err("H'00'"), "H");
    // Ellipses are accepted with a warning since #14 (see warnings.rs).
    assert!(parse("h'00 ... 01'").is_ok());
    assert!(parse("h '00'").is_err());
}

// ---------------------------------------------------------------- b64

#[test]
fn b64_alphabets_padding_and_comments() {
    same("b64'EjRWeA'", "h'12345678'");
    same("b64'EjRWeA=='", "h'12345678'");
    same("b64'AQI='", "h'0102'");
    same("b64'AQID'", "h'010203'");
    same("b64'-_8'", "h'fbff'");
    same("b64'+/8'", "h'fbff'");
    same("b64''", "h''");
    same("b64'AQ # c\n  ID'", "h'010203'");
    same("b64'AQ\r\nID'", "h'010203'");
    same(
        "b64'/base64 not a comment/ but one follows # comment'",
        "h'FDB6AC 7BAE27A2D69CA2699E9EDFDBBADA2779FA25 968C2C'",
    );
    same("b64`EjRWeA`", "h'12345678'");
}

#[test]
fn b64_errors() {
    assert_eq!(ext_err("b64'A'"), "b64");
    assert_eq!(ext_err("b64'A*'"), "b64");
    assert_eq!(ext_err("b64'AQ=x'"), "b64");
    assert_eq!(ext_err("b64'A==='"), "b64");
    assert_eq!(ext_err("B64'AQ'"), "B64");
}

// ---------------------------------------------------------------- dt

#[test]
fn dt_table3() {
    same("dt'1969-07-21T02:56:16Z'", "-14159024");
    same("dt'1969-07-21T02:56:16.0Z'", "-14159024.0");
    same("dt'1969-07-21T02:56:16.5Z'", "-14159023.5");
    same("dt`1969-07-21T02:56:16.5Z`", "-14159023.5");
    same("dt<<'1969-07-21T02:56:16.5Z'>>", "-14159023.5");
    same("dt<<\"1969-07-21T02:56:16.5Z\">>", "-14159023.5");
    same("dt<<`1969-07-21T02:56:16.5Z`>>", "-14159023.5");
    same("DT'1969-07-21T02:56:16Z'", "1(-14159024)");
    assert_enc("dt'1969-07-21T02:56:16Z'", "3a 00d80caf");
    assert_enc("dt'1969-07-21T02:56:16.0Z'", "fa cb580cb0");
    assert_enc("dt'1969-07-21T02:56:16.5Z'", "fb c16b0195f0000000");
}

#[test]
fn dt_offsets_and_fractions() {
    same("dt'2013-03-21T20:04:00Z'", "1363896240");
    same("dt'2013-03-21T22:04:00+02:00'", "1363896240");
    same("dt'2013-03-21T15:34:00-04:30'", "1363896240");
    same("dt'2013-03-21T20:04:00-00:00'", "1363896240");
    same("dt'2013-03-21t20:04:00z'", "1363896240");
    same("dt'2013-03-21T20:04:00.5Z'", "1363896240.5");
    same("dt'2013-03-21T20:04:00.1Z'", "1363896240.1");
    assert_enc("dt'2013-03-21T20:04:00.1Z'", "fb 41d452d9ec066666");
    same("dt'1970-01-01T00:00:00Z'", "0");
    same("dt'1970-01-01T00:00:00.000Z'", "0.0");
    same("DT'2013-03-21T20:04:00.5Z'", "1(1363896240.5)");
}

#[test]
fn dt_errors() {
    for edn in [
        "dt'2013-02-30T00:00:00Z'",
        "dt'2013-13-01T00:00:00Z'",
        "dt'2013-03-21T24:00:00Z'",
        "dt'2013-03-21T20:60:00Z'",
        "dt'2013-03-21'",
        "dt'2013-03-21 20:04:00Z'",
        "dt'2013-03-21T20:04:00'",
        "dt'2013-03-21T20:04:00+0200'",
        "dt'not a date'",
        "dt''",
        "dt<<1>>",
        "dt<<'2013-03-21T20:04:00Z', 1>>",
    ] {
        assert_eq!(ext_err(edn), "dt", "{edn}");
    }
}

// ---------------------------------------------------------------- ip

#[test]
fn ip_table4() {
    same("ip'192.0.2.42'", "h'c000022a'");
    same("ip<<'192.0.2.42'>>", "h'c000022a'");
    same("IP'192.0.2.42'", "52(h'c000022a')");
    same("IP'192.0.2.0/24'", "52([24,h'c00002'])");
    same("ip'2001:db8::42'", "h'20010db8000000000000000000000042'");
    same(
        "IP'2001:db8::42'",
        "54(h'20010db8000000000000000000000042')",
    );
    same("IP'2001:db8::/64'", "54([64,h'20010db8'])");
}

#[test]
fn ip_more_forms() {
    same("ip'2001:db8::/56'", "[56, h'20010db8']");
    same("ip'192.0.2.0/24'", "[24, h'c00002']");
    same("ip'::1'", "h'00000000000000000000000000000001'");
    same("ip'::'", "h'00000000000000000000000000000000'");
    same("IP'0.0.0.0/0'", "52([0, h''])");
    same("IP'::/0'", "54([0, h''])");
    same(
        "IP'::ffff:192.0.2.1'",
        "54(h'00000000000000000000ffffc0000201')",
    );
    same("ip'FE80::1'", "h'fe800000000000000000000000000001'");
    same("ip'1:2:3:4:5:6:7:8'", "h'00010002000300040005000600070008'");
    same("IP'192.0.2.42/32'", "52([32, h'c000022a'])");
}

#[test]
fn ip_errors() {
    for edn in [
        "ip'1.2.3'",
        "ip'256.0.0.1'",
        "ip'01.2.3.4'",
        "ip'1.2.3.4/33'",
        "ip'1.2.3.4/'",
        "ip'::1::2'",
        "ip'2001:db8::/129'",
        "ip'1:2:3:4:5:6:7:8:9'",
        "ip'fe80::1%eth0'",
        "ip'12345::'",
        "ip''",
        "ip<<1>>",
    ] {
        assert_eq!(ext_err(edn), "ip", "{edn}");
    }
}

// ---------------------------------------------------------------- hash (§3.4)
//
// `hash''` needs the optional `hash` cargo feature (issue #15). CI runs the
// suite with default features and with `--all-features`.

#[cfg(feature = "hash")]
const SHA256_FOO: &str = "2C26B46B68FFC68FF99B453C1D30413413422D706483BFA0F98A5E886266E7AE";
#[cfg(feature = "hash")]
const SHA384_FOO: &str = "98c11ffdfdd540676b1a137cb1a22b2a70350c9a44171d6b1180c6be5cbb2ee3\
                          f79d532c8a1dd9ef2e8e08e752a3babb";
#[cfg(feature = "hash")]
const SHA512_FOO: &str = "F7FBBA6E0636F890E56FBBF3283E524C6FA3204AE298382D624741D0DC663832\
                          6E282C41BE5E4254D8820772C5518A2C5A8C0C7F7EDA19594A7EB539453E1ED7";

#[cfg(feature = "hash")]
#[test]
fn hash_table5() {
    let sha256 = format!("h'{SHA256_FOO}'");
    let sha512 = format!("h'{SHA512_FOO}'");
    same("hash<<'foo'>>", &sha256);
    same("hash'foo'", &sha256);
    same("hash<<'foo', -16>>", &sha256);
    same("hash<<'foo', \"SHA-256\">>", &sha256);
    same("hash<<'foo', -44>>", &sha512);
    same("hash<<'foo', \"SHA-512\">>", &sha512);
}

#[cfg(feature = "hash")]
#[test]
fn hash_more_algorithms_and_inputs() {
    same("hash<<'foo', -43>>", &format!("h'{SHA384_FOO}'"));
    same("hash<<'foo', \"SHA-384\">>", &format!("h'{SHA384_FOO}'"));
    same("hash<<'foo', -15>>", "h'2c26b46b68ffc68f'");
    same("hash<<'foo', \"SHA-256/64\">>", "h'2c26b46b68ffc68f'");
    // Text and byte strings hash the same bytes.
    same("hash<<\"foo\">>", &format!("h'{SHA256_FOO}'"));
    same("hash`foo`", &format!("h'{SHA256_FOO}'"));
    same("hash<<h'666f6f'>>", &format!("h'{SHA256_FOO}'"));
    same(
        "hash<<''>>",
        "h'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'",
    );
}

/// Malformed input is an extension error with or without the feature.
#[test]
fn hash_errors() {
    for edn in [
        "hash<<1>>",
        "hash<<>>",
        "hash<<'foo', 99>>",
        "hash<<'foo', \"MD5\">>",
        "hash<<'foo', -16, 1>>",
        "hash<<'foo', 1.5>>",
    ] {
        assert_eq!(ext_err(edn), "hash", "{edn}");
    }
    assert_eq!(ext_err("HASH'foo'"), "HASH");
}

/// Without the feature, `hash''` stays a built-in (so it is neither opaque
/// nor warned about as unknown) and evaluating it is an extension error
/// that names the feature.
#[cfg(not(feature = "hash"))]
#[test]
fn hash_needs_the_hash_feature() {
    for edn in [
        "hash'foo'",
        "hash<<'foo', -44>>",
        "hash<<\"foo\", \"SHA-256\">>",
    ] {
        let e = parse(edn).unwrap_err();
        match e.kind {
            EdnErrorKind::Extension { prefix, message } => {
                assert_eq!(prefix, "hash", "{edn}");
                assert!(message.contains("feature"), "{edn}: {message}");
            }
            other => panic!("{edn}: {other:?}"),
        }
        assert_eq!(e.pos.offset, 0);
    }
    assert!(Extensions::builtin().get("hash").is_some());
    assert!(Extensions::is_builtin_name("hash"));
    let strict_unknown = ParseOptions {
        unknown_extensions: UnknownExtensions::Error,
        ..ParseOptions::default()
    };
    assert!(matches!(
        parse_with("hash'foo'", &strict_unknown).unwrap_err().kind,
        EdnErrorKind::Extension { .. }
    ));
    // An opaque value named "hash" still prints as a tag, not as hash''.
    let bytes = enc("999([\"hash\", [\"foo\"]])");
    assert_eq!(diag(&bytes), "999([\"hash\", [\"foo\"]])");
}

// ---------------------------------------------------------------- b1 / t1 (§3.5)

#[test]
fn t1_concatenation() {
    for edn in [
        "\"Hello world\"",
        "t1<<\"Hello \", \"world\">>",
        "t1<<\"Hello\", h'20', \"world\">>",
        "t1<<h'48656c6c6f20776f726c64'>>",
        "t1'Hello world'",
    ] {
        same(edn, "\"Hello world\"");
    }
    same("t1<<h'c3', h'bc'>>", "\"\u{fc}\"");
    same("t1<<>>", "\"\"");
    same("t1<<\"a\"\n\"b\">>", "\"ab\"");
}

#[test]
fn b1_concatenation() {
    for edn in [
        "b1<<'Hello ', 'world'>>",
        "b1<<'Hello ', h'776f726c64'>>",
        "b1<<'Hello', h'20', 'world'>>",
        "b1<<h'48656c6c6f20776f726c64', '', b64''>>",
        "b1<<h'4 86 56c 6c6f', h' 20776 f726c64'>>",
        "b1<<\"Hello world\">>",
    ] {
        same(edn, "'Hello world'");
    }
    same("b1<<>>", "h''");
    // Indicators on the arguments do not matter for the result.
    same("b1<<'a'_1>>", "'a'");
}

#[test]
fn b1_t1_errors() {
    assert_eq!(ext_err("t1<<h'ff'>>"), "t1");
    assert_eq!(ext_err("t1<<h'c3'>>"), "t1");
    assert_eq!(ext_err("t1<<1>>"), "t1");
    assert_eq!(ext_err("b1<<[]>>"), "b1");
    assert_eq!(ext_err("T1'x'"), "T1");
}

// ---------------------------------------------------------------- ilbs / ilts (§3.6)

#[test]
fn ilbs_ilts_section_3_6() {
    assert_enc("'Hello world'", "4b 48656c6c6f20776f726c64");
    assert_enc("ilbs<<>>", "5f ff");
    assert_enc("ilbs<<\"Hello world\">>", "5f 4b 48656c6c6f20776f726c64 ff");
    assert_enc(
        "ilbs<<'Hello ', \"world\">>",
        "5f 46 48656c6c6f20 45 776f726c64 ff",
    );
    assert_enc(
        "ilbs<<'Hello '_0, 'world'>>",
        "5f 5806 48656c6c6f20 45 776f726c64 ff",
    );
    assert_enc("ilts<<>>", "7f ff");
    assert_enc("ilts<<\"a\", h'62'>>", "7f 6161 6162 ff");
    assert_enc("ilts<<\"a\"_1>>", "7f 79000161 ff");
    assert_enc("ilts'ab'", "7f 626162 ff");
    assert_eq!(ext_err("ilts<<h'ff'>>"), "ilts");
    assert_eq!(ext_err("ilbs<<1>>"), "ilbs");
}

// ---------------------------------------------------------------- float (§3.7)

#[test]
fn float_section_3_7() {
    assert_enc(
        "[float'fe00', float'fe00'_2, float'47110815']",
        "83 f9fe00 faffc00000 fa47110815",
    );
    same("float'47110815'", "0x1.22102ap+15");
    assert_enc("float'3c00'", "f9 3c00");
    assert_enc("float<<h'3c00'>>", "f9 3c00");
    assert_enc("float'3ff0000000000000'", "f9 3c00");
    assert_enc("float'7d1f'", "f9 7d1f");
    assert_enc("float'7ff50c32fdc0b06d'", "fb 7ff50c32fdc0b06d");
    assert_enc("float'7ff8000000000000'", "f9 7e00");
    for edn in [
        "float'00'",
        "float'000000'",
        "float''",
        "float'0000000000000000 00'",
        "float<<1>>",
    ] {
        assert_eq!(ext_err(edn), "float", "{edn}");
    }
    assert_eq!(diag(&[0xf9, 0xfe, 0x00]), "float'fe00'");
}

// ---------------------------------------------------------------- unknown prefixes

#[test]
fn unknown_extensions_are_opaque_with_a_warning() {
    same(
        "cri'https://example.com'",
        "999([\"cri\", [\"https://example.com\"]])",
    );
    same("foo<<1, \"x\">>", "999([\"foo\", [1, \"x\"]])");
    same("foo<<>>", "999([\"foo\", []])");
    same("FOO'x'", "999([\"FOO\", [\"x\"]])");
    same("cri`a\\b`", "999([\"cri\", [\"a\\\\b\"]])");
    same("d-t'x'", "999([\"d-t\", [\"x\"]])");
    // Arguments keep their encoding indicators.
    same("foo<<1_0>>", "999([\"foo\", [1_0]])");
    assert_eq!(UNRESOLVED_EXTENSION_TAG, 999);
    assert_eq!(
        warnings_of("[cri'x', foo<<>>]", &ParseOptions::default()),
        [
            WarningKind::UnknownExtension("cri".into()),
            WarningKind::UnknownExtension("foo".into())
        ]
    );
    assert!(warnings_of("h'00'", &ParseOptions::default()).is_empty());
}

#[test]
fn unknown_extensions_error_under_strict_policy() {
    let strict = ParseOptions {
        unknown_extensions: UnknownExtensions::Error,
        ..ParseOptions::default()
    };
    let e = parse_with("[1, cri'x']", &strict).unwrap_err();
    assert_eq!(e.kind, EdnErrorKind::UnknownExtension("cri".into()));
    assert_eq!(e.pos.offset, 4);
    assert!(parse_with("h'00'", &strict).is_ok());
}

#[test]
fn warning_positions() {
    let parsed = parse_with("[1,\n  cri'x']", &ParseOptions::default()).unwrap();
    assert_eq!(parsed.warnings.len(), 1);
    let pos = parsed.warnings[0].pos;
    assert_eq!((pos.offset, pos.line, pos.column), (6, 2, 3));
}

#[test]
fn opaque_values_print_as_prefixed_literals() {
    for edn in [
        "cri'https://example.com'",
        "foo<<1, \"x\">>",
        "foo<<\"a\", \"b\">>",
        "foo<<h'00'>>",
        "foo<<>>",
        "FOO'x'",
        "x'it\\'s'",
        "x'a\\\\b'",
        "x'line\\nbreak'",
    ] {
        let bytes = enc(edn);
        assert_eq!(diag(&bytes), edn, "printing {}", hex(&bytes));
    }
    // A single text argument always uses the string form.
    assert_eq!(diag(&enc("foo<<\"x\">>")), "foo'x'");
}

#[test]
fn opaque_values_that_cannot_be_prefixed_print_as_tags() {
    for edn in [
        "999([\"h\", [\"00\"]])",
        "999([\"dt\", [\"x\"]])",
        "999([\"Mixed\", [\"x\"]])",
        "999([\"false\", [\"x\"]])",
        "999([\"9x\", [\"x\"]])",
        "999([1, [\"x\"]])",
        "999([\"x\", \"y\"])",
        "999([\"x\", [\"y\"], 1])",
        "999_2([\"x\", [\"y\"]])",
        "999([_ \"x\", [\"y\"]])",
        "999([\"x\"_0, [\"y\"]])",
        "999([\"x\", [_ \"y\"]])",
        "999(1)",
    ] {
        let bytes = enc(edn);
        assert_eq!(diag(&bytes), edn, "printing {}", hex(&bytes));
    }
}

#[test]
fn opaque_printing_can_be_turned_off() {
    let item = parse("cri'x'").unwrap();
    let opts = PrintOptions {
        unresolved_as_prefixed: false,
        ..PrintOptions::new()
    };
    assert_eq!(print(&item, &opts).text, "999([\"cri\", [\"x\"]])");
}

// ---------------------------------------------------------------- prefixes

#[test]
fn prefix_case_and_reserved_words() {
    for edn in [
        "Dt'2013-03-21T20:04:00Z'",
        "dT'x'",
        "Cri'x'",
        "true'x'",
        "null<<>>",
    ] {
        assert_eq!(
            parse(edn).unwrap_err().kind,
            EdnErrorKind::InvalidPrefix,
            "{edn}"
        );
    }
}

// ---------------------------------------------------------------- custom extensions

struct Upper;

impl AppExtension for Upper {
    fn name(&self) -> &str {
        "upper"
    }

    fn evaluate(&self, args: &[Item<'static>], uppercase: bool) -> Result<Item<'static>, ExtError> {
        if uppercase {
            return Err(ExtError("no UPPER variant".into()));
        }
        match args {
            [
                Item {
                    value: Value::Text(t),
                    ..
                },
            ] => Ok(Item::text(t.to_uppercase())),
            _ => Err(ExtError("expected one text string".into())),
        }
    }
}

struct NullH;

impl AppExtension for NullH {
    fn name(&self) -> &str {
        "h"
    }

    fn evaluate(&self, _: &[Item<'static>], _: bool) -> Result<Item<'static>, ExtError> {
        Ok(Item::new(Value::Null))
    }
}

#[test]
fn custom_extensions() {
    let mut exts = Extensions::builtin();
    exts.register(Box::new(Upper));
    let opts = ParseOptions {
        extensions: exts,
        ..ParseOptions::default()
    };
    let parsed = parse_with("[upper'abc', upper<<\"d\">>, h'00']", &opts).unwrap();
    assert!(parsed.warnings.is_empty());
    assert_eq!(
        hex(&encode(&parsed.items[0], EncodeMode::Preserve)),
        hex(&enc("[\"ABC\", \"D\", h'00']"))
    );
    let e = parse_with("UPPER'abc'", &opts).unwrap_err();
    assert!(matches!(
        e.kind,
        EdnErrorKind::Extension { ref prefix, ref message }
            if prefix == "UPPER" && message.contains("no UPPER variant")
    ));
    assert!(parse_with("upper<<1>>", &opts).is_err());
}

#[test]
fn registering_replaces_a_builtin() {
    let mut exts = Extensions::builtin();
    exts.register(Box::new(NullH));
    let names = exts.names();
    assert_eq!(names.iter().filter(|n| **n == "h").count(), 1);
    let opts = ParseOptions {
        extensions: exts,
        ..ParseOptions::default()
    };
    let item = &parse_with("h'00'", &opts).unwrap().items[0];
    assert_eq!(item.value, Value::Null);
}

#[test]
fn builtin_registry() {
    let exts = Extensions::builtin();
    let mut names = exts.names();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "b1", "b64", "dt", "float", "h", "hash", "ilbs", "ilts", "ip", "t1"
        ]
    );
    assert!(exts.get("dt").is_some());
    assert!(
        exts.get("DT").is_none(),
        "lookups use the lowercase identifier"
    );
    assert!(exts.get("cri").is_none());
    for name in names {
        assert!(Extensions::is_builtin_name(name));
    }
    assert!(!Extensions::is_builtin_name("cri"));
}

#[test]
fn empty_registry_makes_everything_opaque() {
    let opts = ParseOptions {
        extensions: Extensions::empty(),
        ..ParseOptions::default()
    };
    let parsed = parse_with("h'00'", &opts).unwrap();
    assert_eq!(
        hex(&encode(&parsed.items[0], EncodeMode::Preserve)),
        hex(&enc("999([\"h\", [\"00\"]])"))
    );
    assert_eq!(
        parsed.warnings.iter().map(|w| &w.kind).collect::<Vec<_>>(),
        [&WarningKind::UnknownExtension("h".into())]
    );
}

#[test]
fn extension_results_roundtrip_through_the_printer() {
    let mut literals = vec![
        "dt'2013-03-21T20:04:00.5Z'",
        "DT'2013-03-21T20:04:00Z'",
        "IP'2001:db8::/64'",
        "ilbs<<'Hello '_0, 'world'>>",
        "float'7fe00000'_2",
    ];
    if cfg!(feature = "hash") {
        literals.push("hash'foo'");
    }
    for edn in literals {
        let bytes = enc(edn);
        common::rt(&bytes).unwrap_or_else(|e| panic!("{edn}: {e}"));
        let item = decode(&bytes).unwrap();
        let back = parse(&print(&item, &PrintOptions::new()).text).unwrap();
        assert_eq!(encode(&back, EncodeMode::Preserve), bytes);
    }
}
