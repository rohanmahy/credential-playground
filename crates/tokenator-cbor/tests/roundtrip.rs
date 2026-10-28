//! Exact Preserve round trips of non-preferred encodings, Deterministic
//! re-encoding, map arrival order, builders, and edits.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::borrow::Cow;

use common::{decode_diag, det, enc, h, hex, plus};
use tokenator_cbor::{
    EncodeError, EncodeMode, FloatWidth, Item, Value, Width, decode, decode_seq, encode,
};

fn preserve(item: &Item) -> String {
    hex(&enc(item, EncodeMode::Preserve))
}

fn deterministic(item: &Item) -> String {
    hex(&enc(item, EncodeMode::Deterministic))
}

fn preferred_plus(item: &Item) -> String {
    hex(&enc(item, EncodeMode::PreferredPlus))
}

// ---------------------------------------------------------------- arguments

/// (input, diag, deterministic) for non-preferred integer, length, and tag
/// arguments.
const LONG_ARGUMENTS: &[(&str, &str, &str)] = &[
    ("1800", "0_0", "00"),
    ("1817", "23_0", "17"),
    ("190001", "1_1", "01"),
    ("1900ff", "255_1", "18ff"),
    ("1a00000001", "1_2", "01"),
    ("1a0000ffff", "65535_2", "19ffff"),
    ("1b0000000000000001", "1_3", "01"),
    ("1b00000000ffffffff", "4294967295_3", "1affffffff"),
    ("3800", "-1_0", "20"),
    ("390000", "-1_1", "20"),
    ("3a000000ff", "-256_2", "38ff"),
    ("3b0000000000000000", "-1_3", "20"),
    ("5800", "h''_0", "40"),
    ("590001aa", "h'aa'_1", "41aa"),
    ("5a00000001aa", "h'aa'_2", "41aa"),
    ("5b0000000000000001aa", "h'aa'_3", "41aa"),
    ("780161", "\"a\"_0", "6161"),
    ("79000161", "\"a\"_1", "6161"),
    ("9800", "[_0 ]", "80"),
    ("99000101", "[_1 1]", "8101"),
    ("9a0000000101", "[_2 1]", "8101"),
    ("9b000000000000000101", "[_3 1]", "8101"),
    ("b800", "{_0 }", "a0"),
    ("b9000101 02", "{_1 1: 2}", "a10102"),
    ("d80100", "1_0(0)", "c100"),
    ("d9000100", "1_1(0)", "c100"),
    ("da0000000100", "1_2(0)", "c100"),
    ("db000000000000000100", "1_3(0)", "c100"),
    ("d818 1800", "24(0_0)", "d81800"),
];

#[test]
fn long_arguments_round_trip_exactly() {
    for (input, expected, _) in LONG_ARGUMENTS {
        assert_eq!(decode_diag(input), *expected, "{input}");
    }
}

#[test]
fn long_arguments_encode_deterministically_to_preferred() {
    for (input, _, expected) in LONG_ARGUMENTS {
        assert_eq!(det(input), *expected, "{input}");
    }
}

#[test]
fn long_arguments_encode_preferred_plus_to_shortest() {
    for (input, _, expected) in LONG_ARGUMENTS {
        assert_eq!(plus(input), *expected, "{input}");
    }
}

#[test]
fn recorded_widths() {
    let cases: &[(&str, Width)] = &[
        ("00", Width::Immediate),
        ("1800", Width::U8),
        ("190001", Width::U16),
        ("1a00000001", Width::U32),
        ("1b0000000000000001", Width::U64),
        ("9f00ff", Width::Indefinite),
        ("bfff", Width::Indefinite),
        ("5fff", Width::Indefinite),
        ("7fff", Width::Indefinite),
        ("d9ffff00", Width::U16),
    ];
    for (input, width) in cases {
        let bytes = h(input);
        assert_eq!(decode(&bytes).unwrap().width, *width, "{input}");
    }
}

// ------------------------------------------------------- indefinite strings

/// (input, diag, deterministic)
const INDEFINITE: &[(&str, &str, &str)] = &[
    ("5fff", "(_ )", "40"),
    ("7fff", "(_ )", "60"),
    ("5f40ff", "(_ h'')", "40"),
    ("5f4101ff", "(_ h'01')", "4101"),
    ("5f41014102ff", "(_ h'01', h'02')", "420102"),
    ("5f580101ff", "(_ h'01'_0)", "4101"),
    ("7f6161780162ff", "(_ \"a\", \"b\"_0)", "626162"),
    ("7f60606161ff", "(_ \"\", \"\", \"a\")", "6161"),
    ("9f9fffff", "[_ [_ ]]", "8180"),
    ("bf9fff bfffff", "{_ [_ ]: {_ }}", "a180a0"),
    ("bf5fff7fffff", "{_ (_ ): (_ )}", "a14060"),
    ("c25f4101ff", "2((_ h'01'))", "c24101"),
];

#[test]
fn indefinite_items_round_trip_exactly() {
    for (input, expected, _) in INDEFINITE {
        assert_eq!(decode_diag(input), *expected, "{input}");
    }
}

#[test]
fn indefinite_items_encode_deterministically_as_definite() {
    for (input, _, expected) in INDEFINITE {
        assert_eq!(det(input), *expected, "{input}");
    }
}

#[test]
fn indefinite_items_encode_preferred_plus_as_definite() {
    // c25f4101ff is the bignum 1, which preferred-plus writes as 01.
    for (input, _, expected) in INDEFINITE {
        let expected = if *input == "c25f4101ff" {
            "01"
        } else {
            expected
        };
        assert_eq!(plus(input), expected, "{input}");
    }
}

#[test]
fn indefinite_string_value_is_the_concatenation() {
    let bytes = h("5f42010243030405ff");
    let item = decode(&bytes).unwrap();
    assert_eq!(item.value, Value::Bytes(Cow::Owned(vec![1, 2, 3, 4, 5])));
    assert_eq!(item.chunks.len(), 2);

    let bytes = h("7f657374726561646d696e67ff");
    let item = decode(&bytes).unwrap();
    assert!(matches!(&item.value, Value::Text(t) if t == "streaming"));
    assert_eq!(item.chunks.len(), 2);
}

#[test]
fn definite_items_have_no_chunks() {
    for input in ["4401020304", "6161", "83010203", "00"] {
        let bytes = h(input);
        assert!(decode(&bytes).unwrap().chunks.is_empty(), "{input}");
    }
}

// ------------------------------------------------------------------- floats

/// (input, diag, deterministic)
const FLOATS: &[(&str, &str, &str)] = &[
    // f32 / f64 that f16 represents exactly
    ("fa3fc00000", "1.5_2", "f93e00"),
    ("fb3ff8000000000000", "1.5_3", "f93e00"),
    ("fa00000000", "0.0_2", "f90000"),
    ("fa80000000", "-0.0_2", "f98000"),
    ("fb8000000000000000", "-0.0_3", "f98000"),
    ("fa477fe000", "65504.0_2", "f97bff"),
    ("fb40effc0000000000", "65504.0_3", "f97bff"),
    // f16 subnormal written wider
    ("fa33800000", "5.960464477539063e-8_2", "f90001"),
    ("fb3e70000000000000", "5.960464477539063e-8_3", "f90001"),
    // f64 that f32 (but not f16) represents exactly
    ("fb40f86a0000000000", "100000.0_3", "fa47c35000"),
    // already shortest
    ("fb3ff199999999999a", "1.1_3", "fb3ff199999999999a"),
    ("fa3f800001", "1.0000001192092896_2", "fa3f800001"),
    ("f903ff", "6.097555160522461e-5_1", "f903ff"),
    // Preserve keeps every NaN bit for bit (payloads, signaling NaNs, sign
    // bit, wide encodings of the quiet NaN); preferred-plus and
    // deterministic write only the canonical f97e00 (draft §4.1 rule 4).
    ("f97e00", "NaN_1", "f97e00"),
    ("fa7fc00000", "NaN_2", "f97e00"),
    ("fb7ff8000000000000", "NaN_3", "f97e00"),
    ("f97e01", "nan(0x7ff8040000000000)_1", "f97e00"),
    ("fa7fc02000", "nan(0x7ff8040000000000)_2", "f97e00"),
    ("fb7ff8040000000000", "nan(0x7ff8040000000000)_3", "f97e00"),
    ("f97c01", "nan(0x7ff0040000000000)_1", "f97e00"),
    ("fa7f800001", "nan(0x7ff0000020000000)_2", "f97e00"),
    ("fb7ff0000000000001", "nan(0x7ff0000000000001)_3", "f97e00"),
    ("fb7ff8000000000001", "nan(0x7ff8000000000001)_3", "f97e00"),
    ("f9fe00", "nan(0xfff8000000000000)_1", "f97e00"),
    ("faffc00000", "nan(0xfff8000000000000)_2", "f97e00"),
];

#[test]
fn floats_round_trip_exactly() {
    for (input, expected, _) in FLOATS {
        assert_eq!(decode_diag(input), *expected, "{input}");
    }
}

#[test]
fn floats_encode_deterministically_to_shortest_exact_width() {
    for (input, _, expected) in FLOATS {
        assert_eq!(det(input), *expected, "{input}");
    }
}

#[test]
fn floats_encode_preferred_plus_like_deterministic() {
    for (input, _, expected) in FLOATS {
        assert_eq!(plus(input), *expected, "{input}");
    }
}

#[test]
fn built_nans_follow_the_mode() {
    let payload = Item::new(Value::Float(
        f64::from_bits(0x7ff8_0400_0000_0000),
        FloatWidth::F16,
    ));
    assert_eq!(preserve(&payload), "f97e01");
    assert_eq!(preferred_plus(&payload), "f97e00");
    assert_eq!(deterministic(&payload), "f97e00");
    let negative = Item::new(Value::Float(-f64::NAN, FloatWidth::F64));
    assert_eq!(preserve(&negative), "fbfff8000000000000");
    assert_eq!(preferred_plus(&negative), "f97e00");
}

#[test]
fn float_value_and_width() {
    let bytes = h("fa3fc00000");
    let item = decode(&bytes).unwrap();
    assert_eq!(item.value, Value::Float(1.5, FloatWidth::F32));
    let bytes = h("f93c00");
    assert_eq!(
        decode(&bytes).unwrap().value,
        Value::Float(1.0, FloatWidth::F16)
    );
}

// --------------------------------------------------------------------- maps

#[test]
fn map_arrival_order_is_preserved() {
    assert_eq!(decode_diag("a3 03 00 01 00 02 00"), "{3: 0, 1: 0, 2: 0}");
    let bytes = h("a2 6162 01 6161 02");
    let item = decode(&bytes).unwrap();
    let Value::Map(entries) = &item.value else {
        panic!("not a map");
    };
    let keys: Vec<_> = entries
        .iter()
        .map(|(k, _)| match &k.value {
            Value::Text(t) => t.to_string(),
            other => panic!("unexpected key {other:?}"),
        })
        .collect();
    assert_eq!(keys, ["b", "a"]);
}

#[test]
fn duplicate_keys_are_preserved() {
    assert_eq!(decode_diag("a2 01 00 01 01"), "{1: 0, 1: 1}");
    assert_eq!(
        decode_diag("a3 6161 01 6162 02 6161 03"),
        "{\"a\": 1, \"b\": 2, \"a\": 3}"
    );
    // Deterministic keeps both entries, in arrival order among themselves.
    assert_eq!(det("a3 01 00 00 00 01 01"), "a3000001000101");
}

#[test]
fn deterministic_sorts_keys_bytewise() {
    // RFC 8949 §4.2.1 example order: 10, 100, -1, "z", "aa", [100], [-1], false
    let shuffled = "a8 f4 08 626161 05 8120 07 0a 01 617a 04 1864 02 811864 06 20 03";
    assert_eq!(
        det(shuffled),
        "a8 0a01 186402 2003 617a04 62616105 81186406 812007 f408".replace(' ', "")
    );
}

#[test]
fn deterministic_sorts_by_deterministic_key_encoding() {
    // Key 3 encoded as 0x1803 sorts by its preferred form 0x03.
    assert_eq!(det("a2 1803 00 02 00"), "a20200 0300".replace(' ', ""));
    // Key 1 encoded as 0x1801 is already first once shortened.
    assert_eq!(det("a2 1801 00 02 00"), "a2010002 00".replace(' ', ""));
}

#[test]
fn deterministic_sorts_nested_maps() {
    // map inside array, inside tag, as a map value, and as a map key
    assert_eq!(det("81 a2 02 00 01 00"), "81a201000200");
    assert_eq!(det("c1 a2 02 00 01 00"), "c1a201000200");
    assert_eq!(det("a1 00 a2 02 00 01 00"), "a100a201000200");
    assert_eq!(det("a1 a2 02 00 01 00 00"), "a1a20100020000");
}

#[test]
fn preserve_keeps_unsorted_maps() {
    assert_eq!(decode_diag("a2 02 00 01 00"), "{2: 0, 1: 0}");
}

#[test]
fn preferred_plus_keeps_arrival_order() {
    assert_eq!(plus("a2 02 00 01 00"), "a202000100");
    assert_eq!(plus("bf 02 00 01 00 ff"), "a202000100");
    assert_eq!(plus("a2 1802 00 01 00"), "a202000100");
    assert_eq!(
        plus("81 a2 626161 00 617a 00"),
        "81a26261610061 7a00".replace(' ', "")
    );
    // Duplicates are kept, in arrival order.
    assert_eq!(plus("a3 01 00 00 00 01 01"), "a3010000000101");
    // Keys that become equal after rewriting are kept too.
    assert_eq!(plus("a2 c24101 00 01 01"), "a201000101");
    assert_eq!(det("a2 01 01 c24101 00"), "a201010100");
}

#[test]
fn preferred_plus_equals_deterministic_without_maps() {
    // draft-ietf-cbor-serialization-11 §5.3.2
    for input in [
        "9f 1801 9f fa3fc00000 ff c240 ff",
        "83 5f4101ff 7f6161ff fb7ff8000000000001",
        "d9 0001 c3 4100",
    ] {
        assert_eq!(plus(input), det(input), "{input}");
    }
}

// ---------------------------------------------------------------- sequences

#[test]
fn decode_seq_round_trips() {
    let input = h("01 1903e8 6161 9f00ff 1800");
    let items = decode_seq(&input).unwrap();
    assert_eq!(items.len(), 5);
    let mut out = Vec::new();
    for item in &items {
        out.extend(enc(item, EncodeMode::Preserve));
    }
    assert_eq!(hex(&out), hex(&input));
}

#[test]
fn decode_seq_of_nothing_is_empty() {
    assert!(decode_seq(&[]).unwrap().is_empty());
}

#[test]
fn decode_seq_of_one_item() {
    let input = h("83010203");
    assert_eq!(decode_seq(&input).unwrap().len(), 1);
}

// ----------------------------------------------------------------- builders

#[test]
fn builders_produce_preferred_encoding() {
    let cases: Vec<(Item, &str)> = vec![
        (Item::int(0), "00"),
        (Item::int(23), "17"),
        (Item::int(24), "1818"),
        (Item::int(1000), "1903e8"),
        (Item::int(-1), "20"),
        (Item::int(-1000), "3903e7"),
        (Item::int(i64::MAX), "1b7fffffffffffffff"),
        (Item::int(i64::MIN), "3b7fffffffffffffff"),
        (Item::new(Value::Uint(u64::MAX)), "1bffffffffffffffff"),
        (Item::new(Value::Nint(u64::MAX)), "3bffffffffffffffff"),
        (Item::bytes(vec![1u8, 2, 3, 4]), "4401020304"),
        (Item::text("IETF"), "6449455446"),
        (Item::text(String::from("a")), "6161"),
        (Item::array(vec![Item::int(1), Item::int(2)]), "820102"),
        (
            Item::map(vec![
                (Item::int(1), Item::int(0)),
                (Item::int(2), Item::int(0)),
            ]),
            "a201000200",
        ),
        (Item::tag(1, Item::int(0)), "c100"),
        (Item::tag(1000, Item::int(0)), "d903e800"),
        (Item::float(1.5), "f93e00"),
        (Item::float(1.1), "fb3ff199999999999a"),
        (Item::float(100000.0), "fa47c35000"),
        (Item::float(f64::NAN), "f97e00"),
        (Item::float(f64::INFINITY), "f97c00"),
        (Item::float(-0.0), "f98000"),
        (Item::simple(16), "f0"),
        (Item::simple(59), "f83b"),
        (Item::simple(255), "f8ff"),
        (Item::simple(20), "f4"),
        (Item::simple(21), "f5"),
        (Item::simple(22), "f6"),
        (Item::simple(23), "f7"),
        (Item::new(Value::Bool(true)), "f5"),
        (Item::new(Value::Null), "f6"),
        (Item::new(Value::Undefined), "f7"),
    ];
    for (item, expected) in &cases {
        assert_eq!(preserve(item), *expected, "{item:?}");
        assert_eq!(deterministic(item), *expected, "{item:?}");
    }
    // Map entries stay in the given order; only Deterministic sorts them.
    let unsorted = Item::map(vec![
        (Item::int(2), Item::int(0)),
        (Item::int(1), Item::int(0)),
    ]);
    assert_eq!(preserve(&unsorted), "a202000100");
    assert_eq!(deterministic(&unsorted), "a201000200");
    let long = Item::bytes(&[0u8; 24][..]);
    assert_eq!(preserve(&long), format!("5818{}", "00".repeat(24)));
}

#[test]
fn builder_simple_maps_to_named_values() {
    assert_eq!(Item::simple(20).value, Value::Bool(false));
    assert_eq!(Item::simple(21).value, Value::Bool(true));
    assert_eq!(Item::simple(22).value, Value::Null);
    assert_eq!(Item::simple(23).value, Value::Undefined);
    assert_eq!(Item::simple(59).value, Value::Simple(59));
}

#[test]
fn builder_widths() {
    assert_eq!(Item::int(1000).width, Width::U16);
    assert_eq!(Item::text("a").width, Width::Immediate);
    assert_eq!(Item::float(1.5).value, Value::Float(1.5, FloatWidth::F16));
    assert_eq!(
        Item::float(100000.0).value,
        Value::Float(100000.0, FloatWidth::F32)
    );
    assert_eq!(Item::float(1.1).value, Value::Float(1.1, FloatWidth::F64));
    assert_eq!(Width::preferred_for(0), Width::Immediate);
    assert_eq!(Width::preferred_for(23), Width::Immediate);
    assert_eq!(Width::preferred_for(24), Width::U8);
    assert_eq!(Width::preferred_for(255), Width::U8);
    assert_eq!(Width::preferred_for(256), Width::U16);
    assert_eq!(Width::preferred_for(65535), Width::U16);
    assert_eq!(Width::preferred_for(65536), Width::U32);
    assert_eq!(Width::preferred_for(u64::from(u32::MAX)), Width::U32);
    assert_eq!(Width::preferred_for(u64::from(u32::MAX) + 1), Width::U64);
}

#[test]
fn with_width_forces_non_preferred_encoding() {
    let item = Item::int(1).with_width(Width::U32);
    assert_eq!(preserve(&item), "1a00000001");
    assert_eq!(deterministic(&item), "01");

    let item = Item::text("a").with_width(Width::U8);
    assert_eq!(preserve(&item), "780161");

    let item = Item::tag(1, Item::int(0)).with_width(Width::U16);
    assert_eq!(preserve(&item), "d9000100");
}

#[test]
fn indefinite_width_on_containers_and_strings() {
    let item = Item::array(vec![Item::int(1)]).with_width(Width::Indefinite);
    assert_eq!(preserve(&item), "9f01ff");
    assert_eq!(deterministic(&item), "8101");

    let item = Item::map(vec![(Item::int(1), Item::int(2))]).with_width(Width::Indefinite);
    assert_eq!(preserve(&item), "bf0102ff");

    // A string marked indefinite without chunks is one chunk.
    let item = Item::bytes(vec![1u8, 2]).with_width(Width::Indefinite);
    assert_eq!(preserve(&item), "5f420102ff");
    let item = Item::text("ab").with_width(Width::Indefinite);
    assert_eq!(preserve(&item), "7f626162ff");
}

#[test]
fn indefinite_string_builder() {
    let item = Item::indefinite_string(vec![
        Item::bytes(vec![1u8, 2]),
        Item::bytes(vec![3u8, 4, 5]),
    ]);
    assert_eq!(item.width, Width::Indefinite);
    assert_eq!(item.value, Value::Bytes(Cow::Owned(vec![1, 2, 3, 4, 5])));
    assert_eq!(preserve(&item), "5f42010243030405ff");
    assert_eq!(deterministic(&item), "450102030405");

    let item = Item::indefinite_string(vec![Item::text("strea"), Item::text("ming")]);
    assert_eq!(preserve(&item), "7f657374726561646d696e67ff");

    let item = Item::indefinite_string(vec![Item::bytes(vec![1u8]).with_width(Width::U8)]);
    assert_eq!(preserve(&item), "5f580101ff");

    assert_eq!(preserve(&Item::indefinite_string(vec![])), "5fff");
}

#[test]
fn too_narrow_width_falls_back_to_preferred() {
    let item = Item::int(1000).with_width(Width::Immediate);
    assert_eq!(preserve(&item), "1903e8");
    let item = Item::int(1000).with_width(Width::U8);
    assert_eq!(preserve(&item), "1903e8");
    // Indefinite makes no sense for an integer.
    let item = Item::int(1).with_width(Width::Indefinite);
    assert_eq!(preserve(&item), "01");
}

#[test]
fn inexact_float_width_widens() {
    let item = Item::new(Value::Float(1.1, FloatWidth::F16));
    assert_eq!(preserve(&item), "fb3ff199999999999a");
    let item = Item::new(Value::Float(100000.0, FloatWidth::F16));
    assert_eq!(preserve(&item), "fa47c35000");
    // An exact but wider width is honored.
    let item = Item::new(Value::Float(1.5, FloatWidth::F64));
    assert_eq!(preserve(&item), "fb3ff8000000000000");
}

#[test]
fn into_owned_outlives_input() {
    let item = {
        let input = h("a2 6161 4401020304 6162 7f6161ff");
        decode(&input).unwrap().into_owned()
    };
    assert_eq!(
        preserve(&item),
        "a2616144010203046162 7f6161ff".replace(' ', "")
    );
    let Value::Map(entries) = &item.value else {
        panic!("not a map");
    };
    assert!(matches!(&entries[0].1.value, Value::Bytes(Cow::Owned(_))));
}

// -------------------------------------------------------------------- edits

#[test]
fn editing_one_value_keeps_other_bytes() {
    let input = h("a2 1801 1802 03 04");
    let mut item = decode(&input).unwrap();
    let Value::Map(entries) = &mut item.value else {
        panic!("not a map");
    };
    entries[1].1.value = Value::Uint(5);
    assert_eq!(preserve(&item), "a21801180203 05".replace(' ', ""));
}

#[test]
fn editing_an_indefinite_string_drops_stale_chunks() {
    let input = h("5f42010243030405ff");
    let mut item = decode(&input).unwrap();
    item.value = Value::Bytes(Cow::Borrowed(b"xyz"));
    assert_eq!(preserve(&item), "5f4378797aff");
}

#[test]
fn appending_to_a_decoded_array() {
    let input = h("9f01ff");
    let mut item = decode(&input).unwrap();
    let Value::Array(items) = &mut item.value else {
        panic!("not an array");
    };
    items.push(Item::int(2));
    assert_eq!(preserve(&item), "9f0102ff");

    let input = h("9801 01");
    let mut item = decode(&input).unwrap();
    let Value::Array(items) = &mut item.value else {
        panic!("not an array");
    };
    items.push(Item::int(2));
    assert_eq!(preserve(&item), "98020102");
}

// ------------------------------------------------------------ encode errors

#[test]
fn invalid_simple_values_fail_in_every_mode() {
    for n in 24u8..=31 {
        let item = Item::new(Value::Simple(n));
        for mode in [
            EncodeMode::Preserve,
            EncodeMode::PreferredPlus,
            EncodeMode::Deterministic,
        ] {
            assert_eq!(
                encode(&item, mode),
                Err(EncodeError::InvalidSimple(n)),
                "simple({n}) {mode:?}"
            );
        }
    }
}

#[test]
fn nested_invalid_simple_values_fail() {
    let bad = || Item::new(Value::Simple(24));
    let cases = [
        Item::array(vec![Item::int(1), bad()]),
        Item::map(vec![(bad(), Item::int(0))]),
        Item::map(vec![(Item::int(0), bad())]),
        Item::tag(1, bad()),
        Item::array(vec![Item::array(vec![bad()])]).with_width(Width::Indefinite),
    ];
    for item in &cases {
        for mode in [
            EncodeMode::Preserve,
            EncodeMode::PreferredPlus,
            EncodeMode::Deterministic,
        ] {
            assert_eq!(
                encode(item, mode),
                Err(EncodeError::InvalidSimple(24)),
                "{item:?} {mode:?}"
            );
        }
    }
}

#[test]
fn valid_simple_values_encode_in_every_mode() {
    for n in (0u8..24).chain(32..=255) {
        let item = Item::new(Value::Simple(n));
        for mode in [
            EncodeMode::Preserve,
            EncodeMode::PreferredPlus,
            EncodeMode::Deterministic,
        ] {
            assert!(encode(&item, mode).is_ok(), "simple({n}) {mode:?}");
        }
    }
    // Simple(20..=23) built directly encode like false/true/null/undefined.
    assert_eq!(preserve(&Item::new(Value::Simple(20))), "f4");
    assert_eq!(preserve(&Item::new(Value::Simple(23))), "f7");
}
