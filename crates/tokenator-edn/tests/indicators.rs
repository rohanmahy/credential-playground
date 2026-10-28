//! Encoding indicators (draft-ietf-cbor-edn-literals-28 §4): parsing them
//! reproduces exact non-preferred bytes, and the printer emits them where
//! needed (default), always, or never.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::{assert_enc, h, rt};
use tokenator_cbor::{FloatWidth, Item, Value, Width, decode};
use tokenator_edn::{
    EdnErrorKind, EncodingIndicators, ParseOptions, PrintOptions, WarningKind, parse, parse_with,
    print,
};

fn warnings(edn: &str) -> Vec<WarningKind> {
    parse_with(edn, &ParseOptions::default())
        .unwrap_or_else(|e| panic!("{edn:?}: {e:?}"))
        .warnings
        .into_iter()
        .map(|w| w.kind)
        .collect()
}

#[track_caller]
fn bad(edn: &str) {
    match parse(edn) {
        Err(e) => assert_eq!(
            e.kind,
            EdnErrorKind::InvalidEncodingIndicator,
            "{edn:?}: {e:?}"
        ),
        Ok(_) => panic!("{edn:?} should be rejected"),
    }
}

fn print_with(bytes: &str, mode: EncodingIndicators) -> String {
    let item = decode(&h(bytes)).unwrap().into_owned();
    print(
        &item,
        &PrintOptions {
            encoding_indicators: mode,
            ..PrintOptions::new()
        },
    )
    .text
}

// ---------------------------------------------------------------- parsing

#[test]
fn table7_definite_length_indicators() {
    assert_enc("1_1", "190001");
    assert_enc("0x4711_3", "1b0000000000004711");
    assert_enc("-1_1", "390000");
    assert_enc("'A'_1", "59000141");
    assert_enc("\"A\"_1", "79000161");
    assert_enc("[_1 \"bar\"]", "99000163626172");
    assert_enc("{_1 \"bar\": 1}", "b900016362617201");
    assert_enc("1_1(4711)", "d90001191267");
    assert_enc("1.5_2", "fa3fc00000");
    assert_enc("0x4711p+03_3", "fb4101c44000000000");
}

#[test]
fn table2_float_indicators() {
    assert_enc("1.1", "fb3ff199999999999a");
    bad("1.1_1");
    bad("1.1_2");
    assert_enc("1.1_3", "fb3ff199999999999a");
    assert_enc("1.5_1", "f93e00");
    assert_enc("1.5_2", "fa3fc00000");
    assert_enc("1.5_3", "fb3ff8000000000000");
    assert_enc("Infinity_1", "f97c00");
    assert_enc("Infinity_2", "fa7f800000");
    assert_enc("Infinity_3", "fb7ff0000000000000");
    assert_enc("-Infinity_1", "f9fc00");
    assert_enc("-Infinity_2", "faff800000");
    assert_enc("-Infinity_3", "fbfff0000000000000");
    assert_enc("NaN_1", "f97e00");
    assert_enc("NaN_2", "fa7fc00000");
    assert_enc("NaN_3", "fb7ff8000000000000");
    assert_enc("-0.0_3", "fb8000000000000000");
    assert_enc("100000.0_3", "fb40f86a0000000000");
    bad("100000.0_1");
}

#[test]
fn immediate_indicator() {
    assert_enc("1_i", "01");
    assert_enc("23_i", "17");
    assert_enc("-24_i", "37");
    assert_enc("[_i 1]", "8101");
    assert_enc("\"a\"_i", "6161");
    assert_enc("1_i(2)", "c102");
    bad("24_i");
    bad("-25_i");
    bad("1.5_i");
    bad("1.5_0");
}

#[test]
fn width_indicators_on_every_major_type() {
    assert_enc("0_0", "1800");
    assert_enc("255_0", "18ff");
    assert_enc("1_2", "1a00000001");
    assert_enc("1_3", "1b0000000000000001");
    assert_enc("-256_0", "38ff");
    assert_enc("-1_3", "3b0000000000000000");
    assert_enc("''_0", "5800");
    assert_enc("h'01'_2", "5a0000000101");
    assert_enc("\"\"_3", "7b0000000000000000");
    assert_enc("[_0 false, true]", "9802f4f5");
    assert_enc("[_0 ]", "9800");
    assert_enc("{_0 }", "b800");
    assert_enc("{_3 1: 2}", "bb00000000000000010102");
    assert_enc("1_0(2)", "d80102");
    assert_enc("1_3(2)", "db000000000000000102");
    assert_enc("<<1>>_1", "59000101");
    bad("256_0");
    bad("-257_0");
    bad("65536_1");
    bad("4294967296_2");
    bad("256_0(1)");
}

#[test]
fn indicator_right_after_the_bracket() {
    assert_enc("[_]", "9fff");
    assert_enc("[_ ]", "9fff");
    assert_enc("{_}", "bfff");
    assert_enc("[_1]", "990000");
    assert_enc("[_1 ]", "990000");
    assert_enc("[1_1]", "81190001");
    assert_enc("[_ 1, 2]", "9f0102ff");
    assert_enc("[_\n1]", "9f01ff");
    assert_enc("{_ 1: 2}", "bf0102ff");
    assert_enc("[_ [_ ], {_ }]", "9f9fffbfffff");
    // An indicator inside a container needs blank space before the item.
    assert!(parse("[_1\"a\"]").is_err());
}

#[test]
fn indefinite_indicator_only_where_allowed() {
    bad("1_");
    bad("1.5_");
    bad("1_(2)");
    bad("h'00'_");
    bad("<<1>>_");
    assert!(parse("true_1").is_err(), "simple values take no indicator");
    assert!(parse("simple(1)_0").is_err());
    assert!(parse("null_").is_err());
}

#[test]
fn nested_indicators() {
    assert_enc(
        "{_ \"a\"_1: [_2 1_3]}",
        "bf 79000161 9a00000001 1b0000000000000001 ff",
    );
    assert_enc("1_1(2_2(3_3))", "d90001 da00000002 1b0000000000000003");
    assert_enc("(_ \"a\"_1, \"b\")", "7f 7900016 1 6162 ff");
}

#[test]
fn parsed_items_record_widths() {
    let item = parse("[_ 1_0, 1.5_3, \"a\"_1]").unwrap();
    assert_eq!(item.width, Width::Indefinite);
    let Value::Array(items) = &item.value else {
        panic!()
    };
    assert_eq!(items[0].width, Width::U8);
    assert_eq!(items[1].value, Value::Float(1.5, FloatWidth::F64));
    assert_eq!(items[2].width, Width::U16);
    let plain = parse("[1, 1.5, \"a\"]").unwrap();
    assert_eq!(plain.width, Width::Immediate);
    let Value::Array(items) = &plain.value else {
        panic!()
    };
    assert_eq!(items[1].value, Value::Float(1.5, FloatWidth::F16));
}

#[test]
fn reserved_indicators_warn_and_are_ignored() {
    for (edn, ei) in [
        ("1_4", "4"),
        ("1_7", "7"),
        ("1_x", "x"),
        ("1_i0", "i0"),
        ("1_00", "00"),
    ] {
        assert_enc(edn, "01");
        assert_eq!(
            warnings(edn),
            [WarningKind::ReservedEncodingIndicator(ei.into())]
        );
    }
    assert_enc("[_foo 1]", "8101");
    assert_eq!(
        warnings("[_foo 1]"),
        [WarningKind::ReservedEncodingIndicator("foo".into())]
    );
}

#[test]
fn indicators_on_bignum_literals_warn() {
    assert_enc("18446744073709551616_1", "c249010000000000000000");
    assert_eq!(
        warnings("18446744073709551616_1"),
        [WarningKind::IgnoredEncodingIndicator]
    );
    assert!(warnings("2_3(h'010000000000000000'_1)").is_empty());
    assert_enc(
        "2_3(h'00 00 00 35 8a 75 04 38 f3 80 f5 f6'_1)",
        "db0000000000000002 59000c 0000003 58a750438f380f5f6",
    );
}

// ---------------------------------------------------------------- floats via float''

#[test]
fn float_literal_widths() {
    assert_enc("float'7fe00000'", "f97f00");
    assert_enc("float'7fe00000'_2", "fa7fe00000");
    assert_enc("float'fe00'_2", "faffc00000");
    assert_enc("float'3c00'_3", "fb3ff0000000000000");
    bad("float'47110815'_1");
}

// ---------------------------------------------------------------- printing

#[test]
fn printer_emits_indicators_only_where_needed() {
    let m = EncodingIndicators::NonPreferred;
    for (bytes, want) in [
        ("1800", "0_0"),
        ("1801", "1_0"),
        ("190001", "1_1"),
        ("1b0000000000004711", "18193_3"),
        ("390000", "-1_1"),
        ("59000141", "h'41'_1"),
        ("79000161", "\"A\"_1"),
        ("99000163626172", "[_1 \"bar\"]"),
        ("b900016362617201", "{_1 \"bar\": 1}"),
        ("d90001191267", "1_1(4711)"),
        ("fa3fc00000", "1.5_2"),
        ("fb3ff8000000000000", "1.5_3"),
        ("fb4101c44000000000", "145544.0_3"),
        ("9802f4f5", "[_0 false, true]"),
        ("9800", "[_0 ]"),
        ("9fff", "[_ ]"),
        ("bfff", "{_ }"),
        ("9f0102ff", "[_ 1, 2]"),
        ("bf0102ff", "{_ 1: 2}"),
        ("5fff", "''_"),
        ("7fff", "\"\"_"),
        ("5f40ff", "(_ h'')"),
        ("7f780161ff", "(_ \"a\"_0)"),
        ("fb3ff199999999999a", "1.1"),
        ("f97c00", "Infinity"),
        ("fa7f800000", "Infinity_2"),
    ] {
        assert_eq!(print_with(bytes, m), want, "printing {bytes}");
        rt(&h(bytes)).unwrap();
    }
}

#[test]
fn printer_with_indicators_always() {
    let m = EncodingIndicators::Always;
    for (bytes, want) in [
        ("01", "1_i"),
        ("8101", "[_i 1_i]"),
        ("f93e00", "1.5_1"),
        ("fa3fc00000", "1.5_2"),
        ("c102", "1_i(2_i)"),
        ("6161", "\"a\"_i"),
        ("a10102", "{_i 1_i: 2_i}"),
        ("1864", "100_0"),
        ("f5", "true"),
        ("f0", "simple(16)"),
        ("9f01ff", "[_ 1_i]"),
        ("7f6161ff", "(_ \"a\"_i)"),
        ("80", "[_i ]"),
    ] {
        assert_eq!(print_with(bytes, m), want, "printing {bytes}");
    }
}

#[test]
fn printer_with_indicators_never() {
    let m = EncodingIndicators::Never;
    for (bytes, want) in [
        ("1801", "1"),
        ("9f01ff", "[1]"),
        ("bf0102ff", "{1: 2}"),
        ("7f61616162ff", "\"ab\""),
        ("5fff", "h''"),
        ("fa3fc00000", "1.5"),
        ("d90001191267", "1(4711)"),
        ("fa7fc00000", "NaN"),
        ("fa7fa3f553", "float'7fa3f553'"),
    ] {
        assert_eq!(print_with(bytes, m), want, "printing {bytes}");
    }
}

#[test]
fn printer_nan_forms() {
    let m = EncodingIndicators::NonPreferred;
    for (bytes, want) in [
        ("f97e00", "NaN"),
        ("fa7fc00000", "NaN_2"),
        ("fb7ff8000000000000", "NaN_3"),
        ("f97d1f", "float'7d1f'"),
        ("f9fe00", "float'fe00'"),
        ("faffc00000", "float'fe00'_2"),
        ("fa7fe00000", "float'7f00'_2"),
        ("fa7fa3f553", "float'7fa3f553'"),
        ("fb7ff50c32fdc0b06d", "float'7ff50c32fdc0b06d'"),
        ("fb7ff4000000000000", "float'7d00'_3"),
    ] {
        assert_eq!(print_with(bytes, m), want, "printing {bytes}");
        rt(&h(bytes)).unwrap();
    }
}

#[test]
fn printer_uses_effective_width_of_built_items() {
    // Too-narrow widths fall back to preferred in the encoder, so the printer
    // must not emit an indicator for them.
    let item = Item::int(1000).with_width(Width::Immediate);
    assert_eq!(print(&item, &PrintOptions::new()).text, "1000");
    let item = Item::new(Value::Float(1.1, FloatWidth::F16));
    assert_eq!(print(&item, &PrintOptions::new()).text, "1.1");
    let item = Item::int(1).with_width(Width::U32);
    assert_eq!(print(&item, &PrintOptions::new()).text, "1_2");
    let item = Item::array(vec![]).with_width(Width::Indefinite);
    assert_eq!(print(&item, &PrintOptions::new()).text, "[_ ]");
    let item = Item::new(Value::Float(1.5, FloatWidth::F64));
    assert_eq!(print(&item, &PrintOptions::new()).text, "1.5_3");
}

#[test]
fn non_preferred_items_roundtrip() {
    for bytes in [
        "1800",
        "1b0000000000000000",
        "3b0000000000000000",
        "5800",
        "7b0000000000000000",
        "9b0000000000000000",
        "bb0000000000000000",
        "d800 00",
        "db0000000000000000 00",
        "f90000",
        "fa00000000",
        "fb0000000000000000",
        "fa80000000",
        "9f9f9fffffff",
        "bf9fff bfffff",
        "5f 5801 00 ff",
        "7f 7b0000000000000001 61 ff",
        "c2 5900 09 010000000000000000",
        "d818 58 02 1801",
    ] {
        rt(&h(bytes)).unwrap_or_else(|e| panic!("{bytes}: {e}"));
    }
}
