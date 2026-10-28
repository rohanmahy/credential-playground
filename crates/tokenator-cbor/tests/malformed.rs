//! Malformed input must be rejected with the right error, never a panic,
//! stack overflow, or large allocation.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::h;
use tokenator_cbor::{DecodeError, DecodeErrorKind, MAX_DEPTH, decode, decode_seq};

use DecodeErrorKind::{
    DepthLimit, InvalidChunk, InvalidIndefinite, InvalidSimple, InvalidUtf8,
    ReservedAdditionalInfo, TrailingBytes, UnexpectedBreak, UnexpectedEof,
};

fn err(hex_in: &str) -> DecodeError {
    let input = h(hex_in);
    match decode(&input) {
        Ok(item) => panic!("{hex_in} decoded as {item:?}"),
        Err(e) => e,
    }
}

fn kind(hex_in: &str) -> DecodeErrorKind {
    err(hex_in).kind
}

#[test]
fn empty_input() {
    assert_eq!(decode(&[]).unwrap_err().kind, UnexpectedEof);
}

#[test]
fn truncated_heads() {
    for input in [
        "18",
        "19",
        "1900",
        "1a",
        "1a000000",
        "1b",
        "1b00000000000000",
        "38",
        "39ff",
        "3a",
        "3b",
        "58",
        "5900",
        "78",
        "98",
        "b8",
        "d8",
        "d900",
        "f8",
        "f9",
        "f900",
        "fa",
        "fa000000",
        "fb",
        "fb00000000000000",
    ] {
        assert_eq!(kind(input), UnexpectedEof, "{input}");
    }
}

#[test]
fn truncated_content() {
    for input in [
        "41",
        "44010203",
        "6261",
        "7432303133",
        "81",
        "8201",
        "8181818181",
        "a1",
        "a101",
        "a20102",
        "c1",
        "c1c1",
        "9f",
        "9f01",
        "bf",
        "bf01",
        "bf0102",
        "5f",
        "5f41",
        "5f4101",
        "7f",
        "7f6161",
        "5801",
    ] {
        assert_eq!(kind(input), UnexpectedEof, "{input}");
    }
}

#[test]
fn truncated_offset_points_at_the_incomplete_item() {
    let e = err("8201 1900");
    assert_eq!(e.kind, UnexpectedEof);
    assert_eq!(e.offset, 2);
}

#[test]
fn reserved_additional_info() {
    for major in 0u8..8 {
        for ai in [28u8, 29, 30] {
            let byte = (major << 5) | ai;
            let e = decode(&[byte]).unwrap_err();
            assert_eq!(e.kind, ReservedAdditionalInfo(ai), "{byte:#04x}");
            assert_eq!(e.offset, 0, "{byte:#04x}");
        }
    }
    let e = err("82 01 1c");
    assert_eq!(e.kind, ReservedAdditionalInfo(28));
    assert_eq!(e.offset, 2);
    assert_eq!(kind("a1 fe 01"), ReservedAdditionalInfo(30));
    assert_eq!(kind("9f fd ff"), ReservedAdditionalInfo(29));
}

#[test]
fn indefinite_length_on_wrong_major_types() {
    assert_eq!(kind("1f"), InvalidIndefinite);
    assert_eq!(kind("3f"), InvalidIndefinite);
    assert_eq!(kind("df00"), InvalidIndefinite);
    let e = err("81 1f");
    assert_eq!(e.kind, InvalidIndefinite);
    assert_eq!(e.offset, 1);
}

#[test]
fn break_outside_indefinite_item() {
    for (input, offset) in [
        ("ff", 0),
        ("81ff", 1),
        ("91ff", 1),
        ("a1ff", 1),
        ("a100ff", 2),
        ("c1ff", 1),
        ("82 9fff ff", 3),
    ] {
        let e = err(input);
        assert_eq!(e.kind, UnexpectedBreak, "{input}");
        assert_eq!(e.offset, offset, "{input}");
    }
    let input = h("01 ff");
    assert_eq!(decode_seq(&input).unwrap_err().kind, UnexpectedBreak);
}

#[test]
fn break_in_place_of_a_map_value() {
    assert_eq!(kind("bf 00 ff"), UnexpectedBreak);
    assert_eq!(kind("bf 00 01 03 ff"), UnexpectedBreak);
}

#[test]
fn invalid_chunks() {
    for input in [
        "5f 01 ff",
        "5f 6161 ff",
        "7f 4100 ff",
        "7f 01 ff",
        "5f 5fff ff",
        "7f 7fff ff",
        "5f 80 ff",
        "5f c14100 ff",
        "5f f6 ff",
    ] {
        assert_eq!(kind(input), InvalidChunk, "{input}");
    }
    assert_eq!(err("5f 4101 01 ff").offset, 3);
}

#[test]
fn invalid_utf8() {
    for input in [
        "62c0ae",
        "6180",
        "63eda080",   // UTF-16 surrogate
        "64f4908080", // above U+10FFFF
        "62c328",
        "7f 61c3 61a9 ff", // character split across chunks
    ] {
        assert_eq!(kind(input), InvalidUtf8, "{input}");
    }
    let e = err("82 6161 6180");
    assert_eq!(e.kind, InvalidUtf8);
    assert_eq!(e.offset, 3);
    // A text string inside a byte string is not checked.
    assert!(decode(&h("4280ff")).is_ok());
}

#[test]
fn two_byte_simple_values_below_32() {
    for n in 0u8..32 {
        let e = decode(&[0xf8, n]).unwrap_err();
        assert_eq!(e.kind, InvalidSimple(n), "f8 {n:02x}");
        assert_eq!(e.offset, 0);
    }
    assert!(decode(&[0xf8, 32]).is_ok());
}

#[test]
fn trailing_bytes() {
    let e = err("00 00");
    assert_eq!(e.kind, TrailingBytes);
    assert_eq!(e.offset, 1);
    let e = err("8101 ff");
    assert_eq!(e.kind, TrailingBytes);
    assert_eq!(e.offset, 2);
    assert_eq!(decode_seq(&h("00 00")).unwrap().len(), 2);
}

#[test]
fn decode_seq_reports_the_failing_item() {
    let input = h("01 02 18");
    let e = decode_seq(&input).unwrap_err();
    assert_eq!(e.kind, UnexpectedEof);
    assert_eq!(e.offset, 2);
}

fn nested(prefix: &[u8], depth: usize, leaf: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut v = prefix.repeat(depth);
    v.extend_from_slice(leaf);
    v.extend(suffix.repeat(depth));
    v
}

#[test]
fn depth_limit_is_exact() {
    for prefix in [&[0x81u8][..], &[0xc1], &[0xa1, 0x00]] {
        let ok = nested(prefix, MAX_DEPTH, &[0x00], &[]);
        assert!(decode(&ok).is_ok(), "{prefix:02x?} x {MAX_DEPTH}");
        let bad = nested(prefix, MAX_DEPTH + 1, &[0x00], &[]);
        assert_eq!(decode(&bad).unwrap_err().kind, DepthLimit, "{prefix:02x?}");
    }
    // indefinite arrays need their breaks
    let ok = nested(&[0x9f], MAX_DEPTH, &[0x00], &[0xff]);
    assert!(decode(&ok).is_ok());
    let bad = nested(&[0x9f], MAX_DEPTH + 1, &[0x00], &[0xff]);
    assert_eq!(decode(&bad).unwrap_err().kind, DepthLimit);
    // nesting through map keys
    let ok = nested(&[0xa1], MAX_DEPTH, &[0x00], &[0x00]);
    assert!(decode(&ok).is_ok());
    let bad = nested(&[0xa1], MAX_DEPTH + 1, &[0x00], &[0x00]);
    assert_eq!(decode(&bad).unwrap_err().kind, DepthLimit);
}

#[test]
fn depth_bombs_error_without_overflowing_the_stack() {
    for prefix in [
        &[0x81u8][..],
        &[0x9f],
        &[0xa1],
        &[0xbf],
        &[0xc1],
        &[0xd9, 0xff, 0xff],
    ] {
        let bomb = prefix.repeat(1_000_000 / prefix.len());
        assert!(decode(&bomb).is_err(), "{prefix:02x?}");
        assert!(decode_seq(&bomb).is_err(), "{prefix:02x?}");
    }
}

#[test]
fn indefinite_strings_do_not_add_depth() {
    let mut v = vec![0x81u8; MAX_DEPTH];
    v.extend(h("5f 4101 4102 ff"));
    assert!(decode(&v).is_ok());
}

#[test]
fn huge_declared_lengths_fail_fast() {
    for input in [
        "5bffffffffffffffff",
        "7bffffffffffffffff",
        "9bffffffffffffffff",
        "bbffffffffffffffff",
        "5b7fffffffffffffff00",
        "5affffffff00",
        "7affffffff00",
        "9affffffff00",
        "baffffffff00",
        "9b00000000ffffffff 00",
        "bb00000000ffffffff 0000",
        "5f 5bffffffffffffffff ff",
        "7f 7affffffff ff",
        "82 5affffffff",
    ] {
        assert_eq!(kind(input), UnexpectedEof, "{input}");
    }
}

#[test]
fn huge_array_count_with_real_content_fails_fast() {
    // 2^32 - 1 elements declared, 64 KiB present: must not reserve 4 G slots.
    let mut v = h("9affffffff");
    v.extend(std::iter::repeat_n(0u8, 65536));
    assert_eq!(decode(&v).unwrap_err().kind, UnexpectedEof);
    let mut v = h("bbffffffffffffffff");
    v.extend(std::iter::repeat_n(0u8, 65536));
    assert_eq!(decode(&v).unwrap_err().kind, UnexpectedEof);
}

#[test]
fn rfc8949_appendix_f_not_well_formed_examples() {
    // RFC 8949 Appendix F.1 examples of not-well-formed data.
    for input in [
        // End of input in a head
        "18",
        "19",
        "1a",
        "1b",
        "1901",
        "1a0102",
        "1b01020304050607",
        "38",
        "58",
        "78",
        "98",
        "9a01ff00",
        "b8",
        "d8",
        "f8",
        "f900",
        "fa0000",
        "fb000000",
        // Definite-length strings with short data
        "41",
        "61",
        "5affffffff00",
        "5bffffffffffffffff010203",
        "7affffffff00",
        "7b7fffffffffffffff010203",
        // Definite-length maps and arrays not closed with enough items
        "81",
        "818181818181818181",
        "8200",
        "a1",
        "a20102",
        "a100",
        "a2000000",
        // Tag number not followed by tag content
        "c0",
        // Indefinite-length strings not closed by a break
        "5f4100",
        "7f6100",
        // Indefinite-length maps and arrays not closed by a break
        "9f",
        "9f0102",
        "bf",
        "bf01020102",
        "819f",
        "9f8000",
        "9f9f9f9f9fffffffff",
        "9f819f819f9fffffff",
        // Reserved additional information values
        "1c",
        "1d",
        "1e",
        "3c",
        "3d",
        "3e",
        "5c",
        "5d",
        "5e",
        "7c",
        "7d",
        "7e",
        "9c",
        "9d",
        "9e",
        "bc",
        "bd",
        "be",
        "dc",
        "dd",
        "de",
        "fc",
        "fd",
        "fe",
        // Reserved two-byte encodings of simple values
        "f800",
        "f801",
        "f818",
        "f81f",
        // Indefinite-length string chunks not of the correct type
        "5f00ff",
        "5f21ff",
        "5f6100ff",
        "5f80ff",
        "5fa0ff",
        "5fc000ff",
        "5fe0ff",
        "7f4100ff",
        // Indefinite-length string chunks not definite length
        "5f5f4100ffff",
        "7f7f6100ffff",
        // Break occurring on its own outside of an indefinite-length item
        "ff",
        // Break occurring in a definite-length array or map or a tag
        "81ff",
        "8200ff",
        "a1ff",
        "a1ff00",
        "a100ff",
        "a20000ff",
        "9f81ff",
        "9f829f819f9fffffffff",
        // Break in an indefinite-length map that would lead to an odd number of items
        "bf00ff",
        "bf000000ff",
        // Major type 0, 1, 6 with additional information 31
        "1f",
        "3f",
        "df",
    ] {
        let bytes = h(input);
        assert!(decode(&bytes).is_err(), "{input} should be malformed");
    }
}
