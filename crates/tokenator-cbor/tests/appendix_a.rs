//! RFC 8949 Appendix A examples, hand-transcribed.
//!
//! Each example must decode to the expected value, re-encode byte for byte in
//! Preserve mode, satisfy the span invariants, and (for preferred inputs)
//! produce no findings and an identical Deterministic encoding.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::{decode_diag, det, h};
use tokenator_cbor::{decode, deterministic_findings, preferred_findings};

/// (encoded, expected diag) for examples already in deterministic encoding.
const DETERMINISTIC: &[(&str, &str)] = &[
    // Integers
    ("00", "0"),
    ("01", "1"),
    ("0a", "10"),
    ("17", "23"),
    ("1818", "24"),
    ("1819", "25"),
    ("1864", "100"),
    ("1903e8", "1000"),
    ("1a000f4240", "1000000"),
    ("1b000000e8d4a51000", "1000000000000"),
    ("1bffffffffffffffff", "18446744073709551615"),
    ("c249010000000000000000", "2(h'010000000000000000')"),
    ("3bffffffffffffffff", "-18446744073709551616"),
    ("c349010000000000000000", "3(h'010000000000000000')"),
    ("20", "-1"),
    ("29", "-10"),
    ("3863", "-100"),
    ("3903e7", "-1000"),
    // Floats
    ("f90000", "0.0_1"),
    ("f98000", "-0.0_1"),
    ("f93c00", "1.0_1"),
    ("fb3ff199999999999a", "1.1_3"),
    ("f93e00", "1.5_1"),
    ("f97bff", "65504.0_1"),
    ("fa47c35000", "100000.0_2"),
    ("fa7f7fffff", "3.4028234663852886e38_2"),
    ("fb7e37e43c8800759c", "1e300_3"),
    ("f90001", "5.960464477539063e-8_1"),
    ("f90400", "6.103515625e-5_1"),
    ("f9c400", "-4.0_1"),
    ("fbc010666666666666", "-4.1_3"),
    ("f97c00", "Infinity_1"),
    ("f97e00", "NaN_1"),
    ("f9fc00", "-Infinity_1"),
    // Simple values
    ("f4", "false"),
    ("f5", "true"),
    ("f6", "null"),
    ("f7", "undefined"),
    ("f0", "simple(16)"),
    ("f8ff", "simple(255)"),
    // Tags
    (
        "c074323031332d30332d32315432303a30343a30305a",
        "0(\"2013-03-21T20:04:00Z\")",
    ),
    ("c11a514b67b0", "1(1363896240)"),
    ("c1fb41d452d9ec200000", "1(1363896240.5_3)"),
    ("d74401020304", "23(h'01020304')"),
    ("d818456449455446", "24(h'6449455446')"),
    (
        "d82076687474703a2f2f7777772e6578616d706c652e636f6d",
        "32(\"http://www.example.com\")",
    ),
    // Strings
    ("40", "h''"),
    ("4401020304", "h'01020304'"),
    ("60", "\"\""),
    ("6161", "\"a\""),
    ("6449455446", "\"IETF\""),
    ("62225c", "\"\\\"\\\\\""),
    ("62c3bc", "\"\u{fc}\""),
    ("63e6b0b4", "\"\u{6c34}\""),
    ("64f0908591", "\"\u{10151}\""),
    // Arrays and maps
    ("80", "[]"),
    ("83010203", "[1, 2, 3]"),
    ("8301820203820405", "[1, [2, 3], [4, 5]]"),
    (
        "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
        "[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]",
    ),
    ("a0", "{}"),
    ("a201020304", "{1: 2, 3: 4}"),
    ("a26161016162820203", "{\"a\": 1, \"b\": [2, 3]}"),
    ("826161a161626163", "[\"a\", {\"b\": \"c\"}]"),
    (
        "a56161614161626142616361436164614461656145",
        "{\"a\": \"A\", \"b\": \"B\", \"c\": \"C\", \"d\": \"D\", \"e\": \"E\"}",
    ),
];

/// (encoded, expected diag, deterministic encoding) for examples that are
/// not in preferred serialization.
const NON_PREFERRED: &[(&str, &str, &str)] = &[
    ("fa7f800000", "Infinity_2", "f97c00"),
    ("fa7fc00000", "NaN_2", "f97e00"),
    ("faff800000", "-Infinity_2", "f9fc00"),
    ("fb7ff0000000000000", "Infinity_3", "f97c00"),
    ("fb7ff8000000000000", "NaN_3", "f97e00"),
    ("fbfff0000000000000", "-Infinity_3", "f9fc00"),
    (
        "5f42010243030405ff",
        "(_ h'0102', h'030405')",
        "450102030405",
    ),
    (
        "7f657374726561646d696e67ff",
        "(_ \"strea\", \"ming\")",
        "6973747265616d696e67",
    ),
    ("9fff", "[_ ]", "80"),
    (
        "9f018202039f0405ffff",
        "[_ 1, [2, 3], [_ 4, 5]]",
        "8301820203820405",
    ),
    (
        "9f01820203820405ff",
        "[_ 1, [2, 3], [4, 5]]",
        "8301820203820405",
    ),
    (
        "83018202039f0405ff",
        "[1, [2, 3], [_ 4, 5]]",
        "8301820203820405",
    ),
    (
        "83019f0203ff820405",
        "[1, [_ 2, 3], [4, 5]]",
        "8301820203820405",
    ),
    (
        "9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff",
        "[_ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]",
        "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
    ),
    (
        "bf61610161629f0203ffff",
        "{_ \"a\": 1, \"b\": [_ 2, 3]}",
        "a26161016162820203",
    ),
    (
        "826161bf61626163ff",
        "[\"a\", {_ \"b\": \"c\"}]",
        "826161a161626163",
    ),
    (
        "bf6346756ef563416d7421ff",
        "{_ \"Fun\": true, \"Amt\": -2}",
        "a26346756ef563416d7421",
    ),
];

#[test]
fn deterministic_examples_decode_and_round_trip() {
    for (input, expected) in DETERMINISTIC {
        assert_eq!(decode_diag(input), *expected, "decoding {input}");
    }
}

#[test]
fn deterministic_examples_encode_unchanged() {
    for (input, _) in DETERMINISTIC {
        assert_eq!(det(input), *input, "Deterministic encoding of {input}");
    }
}

#[test]
fn deterministic_examples_have_no_findings() {
    for (input, _) in DETERMINISTIC {
        let bytes = h(input);
        let item = decode(&bytes).unwrap();
        assert_eq!(preferred_findings(&item), vec![], "{input}");
        assert_eq!(deterministic_findings(&item), vec![], "{input}");
    }
}

#[test]
fn non_preferred_examples_decode_and_round_trip() {
    for (input, expected, _) in NON_PREFERRED {
        assert_eq!(decode_diag(input), *expected, "decoding {input}");
    }
}

#[test]
fn non_preferred_examples_encode_deterministically() {
    for (input, _, deterministic) in NON_PREFERRED {
        assert_eq!(
            det(input),
            *deterministic,
            "Deterministic encoding of {input}"
        );
    }
}

#[test]
fn non_preferred_examples_have_findings() {
    for (input, _, _) in NON_PREFERRED {
        let bytes = h(input);
        let item = decode(&bytes).unwrap();
        assert!(!preferred_findings(&item).is_empty(), "{input}");
        assert!(!deterministic_findings(&item).is_empty(), "{input}");
    }
}
