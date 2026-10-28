//! Tags and simple values are kept verbatim, known or not.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::{decode_diag, det, h};
use tokenator_cbor::{Value, decode, preferred_findings};

#[test]
fn tags_are_preserved() {
    let cases: &[(&str, &str)] = &[
        ("c000", "0(0)"),
        ("d74401020304", "23(h'01020304')"),
        ("d8184100", "24(h'00')"),
        ("d83d 8100", "61([0])"),
        ("d2 8440a0f640", "18([h'', {}, null, h''])"),
        ("d9d9f7 00", "55799(0)"),
        ("d9ffff 00", "65535(0)"),
        ("dafffffffe 00", "4294967294(0)"),
        ("dbffffffffffffffff 00", "18446744073709551615(0)"),
        ("c1c1c100", "1(1(1(0)))"),
        ("d903ec 6a323032302d30312d3031", "1004(\"2020-01-01\")"),
        ("d864 19 4a37", "100(18999)"),
    ];
    for (input, expected) in cases {
        assert_eq!(decode_diag(input), *expected, "{input}");
        assert_eq!(det(input), input.replace(' ', ""), "{input}");
    }
}

#[test]
fn tag_content_is_not_validated() {
    // tag 1 must hold a number and tag 0 a string, but this is a generic
    // decoder: semantic validity is the caller's business.
    assert_eq!(decode_diag("c1 a1616100"), "1({\"a\": 0})");
    assert_eq!(decode_diag("c0 a1616100"), "0({\"a\": 0})");
    assert_eq!(decode_diag("c2 6161"), "2(\"a\")");
    assert_eq!(decode_diag("d818 00"), "24(0)");
}

#[test]
fn bignums_are_not_rewritten() {
    for input in [
        "c240",
        "c24100",
        "c24101",
        "c3420001",
        "c249010000000000000000",
    ] {
        let bytes = h(input);
        let item = decode(&bytes).unwrap();
        assert!(matches!(item.value, Value::Tag(2 | 3, _)), "{input}");
        assert_eq!(det(input), input, "{input}");
        assert_eq!(preferred_findings(&item), vec![], "{input}");
    }
}

#[test]
fn embedded_cbor_is_just_a_byte_string() {
    let bytes = h("d818 43 1903e8");
    let item = decode(&bytes).unwrap();
    let Value::Tag(24, inner) = &item.value else {
        panic!("not tag 24");
    };
    assert!(matches!(&inner.value, Value::Bytes(b) if b.as_ref() == [0x19, 0x03, 0xe8]));
}

#[test]
fn all_one_byte_simple_values() {
    for n in 0u8..20 {
        let byte = 0xe0 | n;
        let bytes = [byte];
        let item = decode(&bytes).unwrap();
        assert_eq!(item.value, Value::Simple(n), "{byte:#04x}");
        assert_eq!(decode_diag(&format!("{byte:02x}")), format!("simple({n})"));
    }
    assert_eq!(decode(&[0xf4]).unwrap().value, Value::Bool(false));
    assert_eq!(decode(&[0xf5]).unwrap().value, Value::Bool(true));
    assert_eq!(decode(&[0xf6]).unwrap().value, Value::Null);
    assert_eq!(decode(&[0xf7]).unwrap().value, Value::Undefined);
}

#[test]
fn all_two_byte_simple_values() {
    for n in 32u8..=255 {
        let bytes = [0xf8, n];
        let item = decode(&bytes).unwrap();
        assert_eq!(item.value, Value::Simple(n), "f8 {n:02x}");
        let input = format!("f8{n:02x}");
        assert_eq!(decode_diag(&input), format!("simple({n})"));
        assert_eq!(det(&input), input);
    }
}

#[test]
fn sd_cwt_redacted_claim_key_simple_value() {
    // SD-CWT uses an unassigned simple value as the map key for redacted
    // claim digests; it must survive as a key, in both encodings.
    let input = "a2 01 6161 f83b 81 4401020304";
    assert_eq!(decode_diag(input), "{1: \"a\", simple(59): [h'01020304']}");
    assert_eq!(det(input), input.replace(' ', ""));
}

#[test]
fn simple_values_as_map_keys_sort_after_other_types() {
    // 0xf83b sorts after text (0x61..) and arrays (0x81..)
    assert_eq!(
        det("a2 f83b 00 6161 00"),
        "a26161 00f83b00".replace(' ', "")
    );
}
