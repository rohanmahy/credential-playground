//! The core grammar of draft-ietf-cbor-edn-literals-28 (§2, §5.1): numbers,
//! strings, raw strings, embedded CBOR, arrays, maps, tags, simple values,
//! streamstrings, separators, and newline handling.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::{assert_enc, enc, hex};
use tokenator_cbor::{EncodeMode, Value, encode};
use tokenator_edn::{EdnErrorKind, parse, parse_seq};

#[track_caller]
fn err(edn: &str) -> EdnErrorKind {
    match parse(edn) {
        Ok(item) => panic!(
            "{edn:?} parsed as {}, expected an error",
            hex(&encode(&item, EncodeMode::Preserve))
        ),
        Err(e) => e.kind,
    }
}

#[track_caller]
fn same(a: &str, b: &str) {
    assert_eq!(hex(&enc(a)), hex(&enc(b)), "{a:?} vs {b:?}");
}

// ---------------------------------------------------------------- numbers

#[test]
fn table1_equivalent_numbers() {
    for edn in ["4711", "0x1267", "0o11147", "0b1001001100111"] {
        assert_enc(edn, "19 1267");
    }
    for edn in ["1.5", "0.15e1", "15e-1", "0x1.8p0", "0x18p-4"] {
        assert_enc(edn, "f9 3e00");
    }
    for edn in ["0", "+0", "-0"] {
        assert_enc(edn, "00");
    }
    for edn in ["0.0", "+0.0"] {
        assert_enc(edn, "f9 0000");
    }
    assert_enc("-0.0", "f9 8000");
    assert_enc("Infinity", "f9 7c00");
    assert_enc("-Infinity", "f9 fc00");
    assert_enc("NaN", "f9 7e00");
}

#[test]
fn decimal_forms() {
    assert_enc("+1", "01");
    assert_enc("-1", "20");
    assert_enc("-24", "37");
    assert_enc("-25", "3818");
    assert_enc(".5", "f9 3800");
    assert_enc("-.5", "f9 b800");
    assert_enc("3.", "f9 4200");
    assert_enc("1e5", "fa 47c35000");
    assert_enc("1E2", "f9 5640");
    assert_enc("1e+2", "f9 5640");
    assert_enc("100e-2", "f9 3c00");
    assert_enc("0.1", "fb 3fb999999999999a");
    assert_enc("1.1", "fb 3ff199999999999a");
    assert_enc("65505.0", "fa 477fe100");
    assert_enc("1.0000001192092896", "fa 3f800001");
    assert_enc("5e-324", "fb 0000000000000001");
    assert_enc("2.2250738585072014e-308", "fb 0010000000000000");
    assert_enc("1.7976931348623157e+308", "fb 7fefffffffffffff");
}

#[test]
fn integral_floats_stay_floats() {
    // A "." or exponent makes a float even when the value is integral.
    assert_enc("1.0", "f9 3c00");
    assert_enc("1e0", "f9 3c00");
    assert_enc("0x1p0", "f9 3c00");
    assert_enc("4294967296.0", "fa 4f800000");
}

#[test]
fn prefixes_are_case_insensitive() {
    // ABNF quoted strings are case-insensitive: "0x", "0o", "0b", "e", "p".
    assert_enc("0X10", "10");
    assert_enc("0xfF", "18 ff");
    assert_enc("0B11", "03");
    assert_enc("0O17", "0f");
    assert_enc("0x1P4", "f9 4c00");
}

#[test]
fn hex_floats() {
    assert_enc("0x1.22102ap+15", "fa 47110815");
    assert_enc("0x4711p+03", "fa 480e2200");
    assert_enc("-0x1p-1074", "fb 8000000000000001");
    assert_enc("0x.8p1", "f9 3c00");
    assert_enc("0x1.p1", "f9 4000");
}

#[test]
fn signed_radix_integers() {
    assert_enc("-0x10", "2f");
    assert_enc("+0x10", "10");
    assert_enc("-0b1", "20");
    assert_enc("-0o10", "27");
    assert_enc("0x0001", "01");
}

#[test]
fn bignums() {
    assert_enc("18446744073709551615", "1b ffffffffffffffff");
    assert_enc("18446744073709551616", "c2 49 010000000000000000");
    assert_enc("-18446744073709551616", "3b ffffffffffffffff");
    assert_enc("-18446744073709551617", "c3 49 010000000000000000");
    assert_enc(
        "340282366920938463463374607431768211456",
        "c2 51 0100000000000000000000000000000000",
    );
    assert_enc(
        "0x100000000000000000000000000000000",
        "c2 51 0100000000000000000000000000000000",
    );
    assert_enc("0x00010000000000000000", "c2 49 010000000000000000");
    assert_enc(
        "0b10000000000000000000000000000000000000000000000000000000000000000",
        "c2 49 010000000000000000",
    );
    assert_enc("0o2000000000000000000000", "c2 49 010000000000000000");
    assert_enc("-0x10000000000000000", "3b ffffffffffffffff");
    assert_enc("-0x10000000000000001", "c3 49 010000000000000000");
    // draft §5.1 item 5
    assert_enc("987654321098765432310", "c2 49 358a750438f380f5f6");
    assert_enc("-987654321098765432311", "c3 49 358a750438f380f5f6");
}

#[test]
fn bad_numbers() {
    for edn in [
        "00",
        "01",
        "-01",
        "00.5",
        "0x",
        "0b2",
        "0o8",
        "0xg",
        "1.2.3",
        "1e",
        "1e+",
        "--1",
        "+-1",
        "-",
        "+",
        "0x1.8",
        "1e400",
        "-1e400",
        "0x1p99999",
        "infinity",
        "nan",
        "+Infinity",
        "+NaN",
        "-NaN",
    ] {
        assert!(parse(edn).is_err(), "{edn:?} should not parse");
    }
    assert_eq!(err("00"), EdnErrorKind::InvalidNumber);
    assert_eq!(err("1e400"), EdnErrorKind::InvalidNumber);
    assert_eq!(err("0b2"), EdnErrorKind::InvalidNumber);
}

// ---------------------------------------------------------------- text strings

#[test]
fn json_escapes() {
    assert_enc(r#""\b\f\n\r\t\/\\\"""#, "68 080c0a0d092f5c22");
    assert_enc(r#""\u0000""#, "61 00");
    assert_enc(r#""\u00fc""#, "62 c3bc");
    assert_enc(r#""\u00FC""#, "62 c3bc");
    assert_enc(r#""\ud800\udd51""#, "64 f0908591");
    assert_enc(r#""\uD83C\uDC73""#, "64 f09f81b3");
    assert_enc(r#""'""#, "61 27");
}

#[test]
fn brace_escapes() {
    same(
        r#""D\u{6f}mino's \u{1F073} + \u{2318}""#,
        r#""D\u006Fmino's \uD83C\uDC73 + \u2318""#,
    );
    same(
        r#""D\u{6f}mino's \u{1F073} + \u{2318}""#,
        "\"Domino's \u{1F073} + \u{2318}\"",
    );
    assert_enc(r#""\u{0}""#, "61 00");
    assert_enc(r#""\u{0000000041}""#, "61 41");
    assert_enc(r#""\u{10FFFF}""#, "64 f48fbfbf");
}

#[test]
fn bad_escapes() {
    assert_eq!(err(r#""\x""#), EdnErrorKind::InvalidEscape);
    assert_eq!(err(r#""\u12""#), EdnErrorKind::InvalidEscape);
    assert_eq!(err(r#""\u{}""#), EdnErrorKind::InvalidEscape);
    assert_eq!(err(r#""\U0041""#), EdnErrorKind::InvalidEscape);
    assert_eq!(err(r#""\ud800""#), EdnErrorKind::InvalidCodePoint);
    assert_eq!(err(r#""\udc00\ud800""#), EdnErrorKind::InvalidCodePoint);
    assert_eq!(err(r#""\ud800\u0041""#), EdnErrorKind::InvalidCodePoint);
    assert_eq!(err(r#""\u{d800}""#), EdnErrorKind::InvalidCodePoint);
    assert_eq!(err(r#""\u{110000}""#), EdnErrorKind::InvalidCodePoint);
}

#[test]
fn newlines_and_controls_in_strings() {
    assert_enc("\"a\nb\"", "63 610a62");
    assert_enc("\"a\r\nb\"", "63 610a62");
    assert_enc("\"a\rb\"", "62 6162");
    assert_eq!(err("\"a\tb\""), EdnErrorKind::ControlCharacter);
    assert_eq!(err("\"a\u{1}b\""), EdnErrorKind::ControlCharacter);
    assert_eq!(err("'a\tb'"), EdnErrorKind::ControlCharacter);
    assert_enc("\"\u{7f}\"", "61 7f");
}

#[test]
fn unterminated_strings() {
    assert_eq!(err("\"abc"), EdnErrorKind::UnexpectedEnd);
    assert_eq!(err("'abc"), EdnErrorKind::UnexpectedEnd);
    assert_eq!(err("\"abc\\"), EdnErrorKind::UnexpectedEnd);
    assert_eq!(err("`abc"), EdnErrorKind::UnexpectedEnd);
}

// ---------------------------------------------------------------- byte strings

#[test]
fn single_quoted_byte_strings() {
    same("'hello world'", "h'68656c6c6f20776f726c64'");
    assert_enc("''", "40");
    assert_enc(r"'it\'s'", "44 69742773");
    assert_enc(r#"'"'"#, "41 22");
    assert_enc(r"'\u00e9'", "42 c3a9");
    assert_enc(r"'\u{e9}'", "42 c3a9");
    assert_enc(r"'\u007f'", "41 7f");
    assert_enc(r"'\u001f'", "41 1f");
    assert_enc(r"'\n\\'", "42 0a5c");
    assert_enc("'\u{fc}'", "42 c3bc");
}

#[test]
fn single_quoted_escape_restrictions() {
    // \u escapes of printable ASCII and \/ are not available in '…'.
    assert_eq!(err(r"'\u0041'"), EdnErrorKind::InvalidEscape);
    assert_eq!(err(r"'\u{41}'"), EdnErrorKind::InvalidEscape);
    assert_eq!(err(r"'\u0020'"), EdnErrorKind::InvalidEscape);
    assert_eq!(err(r"'\/'"), EdnErrorKind::InvalidEscape);
    assert_eq!(err(r#"'\"'"#), EdnErrorKind::InvalidEscape);
    // …but they are in "…".
    assert_enc(r#""\u0041\/""#, "62 412f");
}

// ---------------------------------------------------------------- raw strings

#[test]
fn raw_strings() {
    same(r#"``[^ \t\n\r"'`]``"#, r#""[^ \\t\\n\\r\"'`]""#);
    same("`abc`", "\"abc\"");
    same(r"`\n`", r#""\\n""#);
    same(
        "```To emulate typographic quotes, sometimes double backward and\n\
         forward single quotes are used, as in ``text.''\n```",
        "\"To emulate typographic quotes, sometimes double backward and\\n\
         forward single quotes are used, as in ``text.''\\n\"",
    );
}

#[test]
fn raw_string_leading_newline_rule() {
    same("```a```", "\"a\"");
    same("```\na```", "\"a\"");
    same("```\r\na```", "\"a\"");
    same("```\n``text''```", "\"``text''\"");
    same("```\n\na```", "\"\\na\"");
    // Only one leading newline is removed, and trailing ones are kept.
    same("`\na\n`", "\"a\\n\"");
}

#[test]
fn raw_string_space_rule() {
    same("``` a = ``foo`` ```", "\"a = ``foo``\"");
    same("` a `", "\"a\"");
    same("`  a  `", "\" a \"");
    same("` a`", "\" a\"");
    same("`a `", "\"a \"");
    // The newline rule wins over the space rule.
    same("`\n a `", "\" a \"");
}

#[test]
fn raw_strings_drop_cr_and_keep_tabs_out() {
    same("`a\r\nb`", "\"a\\nb\"");
    assert!(parse("`a\tb`").is_err(), "HT is not a rawchar");
}

#[test]
fn raw_strings_as_prefixed_literals() {
    same("h`00ff`", "h'00ff'");
    same("b64`EjRWeA`", "h'12345678'");
}

// ---------------------------------------------------------------- embedded CBOR

#[test]
fn embedded_cbor() {
    assert_enc("<<1>>", "41 01");
    assert_enc("<<1, 2>>", "42 0102");
    assert_enc("<<1 2>>", "42 0102");
    assert_enc("<<1,>>", "41 01");
    assert_enc(r#"<<"hello", null>>"#, "47 6568656c6c6f f6");
    assert_enc("<<>>", "40");
    assert_enc("<< >>", "40");
    assert_enc("<< /c/ >>", "40");
    assert_enc("<< <<1>> >>", "42 4101");
    assert_enc("<<[1, {2: 3}]>>", "45 8201a10203");
    assert!(parse("<<,>>").is_err());
    assert!(parse("<<1,,2>>").is_err());
    assert_eq!(err("<<1"), EdnErrorKind::UnexpectedEnd);
}

#[test]
fn embedded_cbor_honors_indicators_inside() {
    assert_enc("<<1_1>>", "43 190001");
    assert_enc("<<1_0, 2_2>>", "47 1801 1a00000002");
    assert_enc(r#"<<"hello"_0, null>>"#, "48 7805 68656c6c6f f6");
    assert_enc("<<[_ 1]>>", "43 9f01ff");
    assert_enc("<<1>>_0", "5801 01");
}

// ---------------------------------------------------------------- arrays and maps

#[test]
fn optional_commas_section_2_4_1() {
    for edn in [
        "[1, 2, 3]",
        "[1, 2, 3,]",
        "[1  2  3]",
        "[1  2  3,]",
        "[1  2, 3]",
        "[1  2, 3,]",
        "[1, 2  3]",
        "[1, 2  3,]",
        "[1\n2\n3\n]",
        "[1/a/2#b\n3]",
        "[ 1 , 2 , 3 , ]",
    ] {
        assert_enc(edn, "83 010203");
    }
    for edn in [
        r#"{1: "n", "x": "a"}"#,
        r#"{1: "n", "x": "a",}"#,
        r#"{1: "n"  "x": "a"}"#,
        r#"{1:"n","x":"a"}"#,
        "{1 : \"n\"\n\"x\" : \"a\"\n}",
    ] {
        assert_enc(edn, "a2 01616e 61786161");
    }
}

#[test]
fn separators_are_mandatory() {
    assert_enc("[11]", "81 0b");
    assert_enc("[1 1]", "82 0101");
    assert_enc("[[] []]", "82 8080");
    assert_enc("[[],[]]", "82 8080");
    assert_eq!(err("[[][]]"), EdnErrorKind::MissingSeparator);
    assert_eq!(err("[{}{}]"), EdnErrorKind::MissingSeparator);
    assert_eq!(err("[\"a\"\"b\"]"), EdnErrorKind::MissingSeparator);
    assert!(parse("{1: 2[3]: 4}").is_err());
    // Blank space alone is a separator.
    assert_enc("{1: 2 3: 4}", "a2 0102 0304");
}

#[test]
fn juxtaposed_strings_are_separate_items() {
    // -28 §2.3 removed string concatenation by juxtaposition.
    assert_enc(r#"["a" "b"]"#, "82 6161 6162");
    assert_eq!(err(r#""a" "b""#), EdnErrorKind::TrailingInput);
    assert_eq!(err("'a' 'b'"), EdnErrorKind::TrailingInput);
}

#[test]
fn malformed_containers() {
    for edn in [
        "[,]", "[1,,2]", "[", "[1", "]", "{1}", "{1:}", "{:1}", "{1:2,,}", "{1 2}", "{", "}", "[}",
        "{]", "{1: 2:}", "[1:2]",
    ] {
        assert!(parse(edn).is_err(), "{edn:?} should not parse");
    }
    assert_eq!(err("[1"), EdnErrorKind::UnexpectedEnd);
    assert_eq!(err("]"), EdnErrorKind::UnexpectedChar(']'));
}

#[test]
fn maps_keep_arrival_order_and_duplicates() {
    assert_enc(r#"{"b": 1, "a": 2}"#, "a2 616201 616102");
    assert_enc(r#"{1: "to", 1: "from"}"#, "a2 0162746f 016466726f6d");
    let item = parse(r#"{3: 0, 1: 0, 2: 0}"#).unwrap();
    let Value::Map(entries) = &item.value else {
        panic!()
    };
    let keys: Vec<_> = entries.iter().map(|(k, _)| k.value.clone()).collect();
    assert_eq!(keys, [Value::Uint(3), Value::Uint(1), Value::Uint(2)]);
}

#[test]
fn any_item_as_map_key() {
    assert_enc("{[1]: 2, {}: 3, 1.5: 4}", "a3 810102 a003 f93e0004");
    assert_enc("{h'00': 1, 1(2): 3, null: 4}", "a3 410001 c10203 f604");
}

// ---------------------------------------------------------------- tags

#[test]
fn tags() {
    assert_enc("0(\"x\")", "c0 6178");
    assert_enc("1(1)", "c1 01");
    assert_enc("1( 2 )", "c1 02");
    assert_enc("1(/c/2/c/)", "c1 02");
    assert_enc("1(2(3))", "c1 c2 03");
    assert_enc("24(1)", "d818 01");
    assert_enc("55799(1)", "d9d9f7 01");
    assert_enc("18446744073709551615(0)", "db ffffffffffffffff 00");
    assert_eq!(err("18446744073709551616(0)"), EdnErrorKind::OutOfRange);
    assert_eq!(err("01(2)"), EdnErrorKind::OutOfRange);
    assert!(parse("1 (2)").is_err());
    assert!(parse("1()").is_err());
    assert!(parse("1(2, 3)").is_err());
    assert!(parse("-1(2)").is_err());
    assert!(parse("0x1(2)").is_err());
    assert_eq!(err("1(2"), EdnErrorKind::UnexpectedEnd);
}

// ---------------------------------------------------------------- simple values

#[test]
fn simple_values() {
    assert_enc("false", "f4");
    assert_enc("true", "f5");
    assert_enc("null", "f6");
    assert_enc("undefined", "f7");
    assert_enc("simple(0)", "e0");
    assert_enc("simple(19)", "f3");
    assert_enc("simple(20)", "f4");
    assert_enc("simple(21)", "f5");
    assert_enc("simple(22)", "f6");
    assert_enc("simple(23)", "f7");
    assert_enc("simple(32)", "f820");
    assert_enc("simple(59)", "f83b");
    assert_enc("simple(255)", "f8ff");
    assert_enc("simple( 16 )", "f0");
    assert_enc("simple(/c/16)", "f0");
    for n in 24..=31 {
        assert_eq!(err(&format!("simple({n})")), EdnErrorKind::OutOfRange);
    }
    assert_eq!(err("simple(256)"), EdnErrorKind::OutOfRange);
    for edn in [
        "simple(016)",
        "simple(-1)",
        "simple()",
        "simple(0x10)",
        "Simple(1)",
        "simple (1)",
        "True",
        "NULL",
        "nul",
        "undefine",
        "truex",
    ] {
        assert!(parse(edn).is_err(), "{edn:?} should not parse");
    }
}

// ---------------------------------------------------------------- streamstrings

#[test]
fn streamstrings() {
    assert_enc("(_ \"a\")", "7f 6161 ff");
    assert_enc("(_ \"strea\", \"ming\")", "7f 657374726561 646d696e67 ff");
    assert_enc("(_ \"a\" \"b\")", "7f 6161 6162 ff");
    assert_enc("(_ \"a\",)", "7f 6161 ff");
    assert_enc("(_ h'0102', h'030405')", "5f 420102 43030405 ff");
    assert_enc("(_ 'a', h'')", "5f 4161 40 ff");
    assert_enc("(_ <<1>>)", "5f 4101 ff");
    assert_enc("(_ '')", "5f 40 ff");
    assert_enc("(_ \"\")", "7f 60 ff");
    assert_enc("(_ `raw`)", "7f 63726177 ff");
    assert_enc("(_\n\"a\"\n)", "7f 6161 ff");
    assert_enc("(_ \"a\"_0)", "7f 780161 ff");
}

#[test]
fn empty_indefinite_strings() {
    assert_enc("''_", "5f ff");
    assert_enc("\"\"_", "7f ff");
}

#[test]
fn bad_streamstrings() {
    assert_eq!(err("(_ )"), EdnErrorKind::InvalidChunks);
    assert_eq!(err("(_ \"a\", h'01')"), EdnErrorKind::InvalidChunks);
    assert!(parse("(_ 1)").is_err());
    assert!(parse("(_\"a\")").is_err());
    assert!(parse("( \"a\")").is_err());
    assert!(parse("(_ \"a\"").is_err());
    assert!(parse("'a'_").is_err());
    assert!(parse("\"a\"_").is_err());
}

// ---------------------------------------------------------------- sequences and whitespace

#[test]
fn single_item_and_trailing_input() {
    assert_enc("  1  ", "01");
    assert_enc("\n\t1\n", "01");
    assert_enc("/c/ 1 /c/", "01");
    assert_enc("# c\n1 # c", "01");
    assert_eq!(err(""), EdnErrorKind::UnexpectedEnd);
    assert_eq!(err("   "), EdnErrorKind::UnexpectedEnd);
    assert_eq!(err("/c/"), EdnErrorKind::UnexpectedEnd);
    assert_eq!(err("1 2"), EdnErrorKind::TrailingInput);
    assert_eq!(err("1, 2"), EdnErrorKind::TrailingInput);
}

#[test]
fn sequences() {
    let enc_all = |edn: &str| -> Vec<String> {
        parse_seq(edn)
            .unwrap()
            .iter()
            .map(|i| hex(&encode(i, EncodeMode::Preserve)))
            .collect()
    };
    assert!(enc_all("").is_empty());
    assert!(enc_all("  # only a comment").is_empty());
    assert_eq!(enc_all("1"), ["01"]);
    assert_eq!(enc_all("1, 2"), ["01", "02"]);
    assert_eq!(enc_all("1 2"), ["01", "02"]);
    assert_eq!(enc_all("1, 2,"), ["01", "02"]);
    assert_eq!(enc_all("[1]\n{}"), ["8101", "a0"]);
    assert!(parse_seq("1,,2").is_err());
    assert!(parse_seq(",").is_err());
    assert!(parse_seq("[][]").is_err());
}

#[test]
fn crlf_and_lf_give_the_same_result() {
    let lf = "{\n  1: \"multi\nline\", # c\n  2: h'00 # c\n 01',\n  3: `raw\nstring`,\n  \
              4: /* a\n b */ [1,\n 2],\n  5: b64'AQ # c\n  ID'\n}\n";
    let crlf = lf.replace('\n', "\r\n");
    assert_eq!(hex(&enc(lf)), hex(&enc(&crlf)));
    assert_enc(
        lf,
        "a5 01 6a 6d756c74690a6c696e65 02 42 0001 03 6a 7261770a737472696e67 04 82 0102 05 43 010203",
    );
}

#[test]
fn tabs_are_blank_space_outside_strings() {
    assert_enc("[\t1,\t2\t]", "82 0102");
}

#[test]
fn non_ascii_outside_strings_is_rejected() {
    assert!(parse("[1,\u{a0}2]").is_err());
}
