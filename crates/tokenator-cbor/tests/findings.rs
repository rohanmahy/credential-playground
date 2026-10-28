//! preferred_findings and deterministic_findings.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::{h, hex, sem};
use tokenator_cbor::{
    EncodeMode, EncodingFinding, FindingKind, Item, Span, Width, decode, deterministic_findings,
    encode, preferred_findings,
};

use FindingKind::{IndefiniteLength, MapKeyOrder, NonPreferredArgument, NonPreferredFloat};

/// A finding as (start, end, head_len, kind, preferred hex), for compact
/// expectations.
type F = (usize, usize, usize, FindingKind, &'static str);

fn simplify(findings: Vec<EncodingFinding>) -> Vec<(usize, usize, usize, FindingKind, String)> {
    findings
        .into_iter()
        .map(|f| {
            (
                f.span.start,
                f.span.end,
                f.span.head_len,
                f.kind,
                hex(&f.preferred_bytes),
            )
        })
        .collect()
}

fn expect(findings: Vec<EncodingFinding>, expected: &[F]) -> Result<(), String> {
    let got = simplify(findings);
    let want: Vec<_> = expected
        .iter()
        .map(|(s, e, hl, k, p)| (*s, *e, *hl, *k, p.replace(' ', "")))
        .collect();
    if got == want {
        Ok(())
    } else {
        Err(format!("got {got:?}\nwant {want:?}"))
    }
}

fn preferred(hex_in: &str, expected: &[F]) {
    let input = h(hex_in);
    let item = decode(&input).unwrap();
    expect(preferred_findings(&item), expected).unwrap_or_else(|e| panic!("{hex_in}: {e}"));
}

fn deterministic(hex_in: &str, expected: &[F]) {
    let input = h(hex_in);
    let item = decode(&input).unwrap();
    expect(deterministic_findings(&item), expected).unwrap_or_else(|e| panic!("{hex_in}: {e}"));
}

#[test]
fn preferred_input_has_no_findings() {
    for input in [
        "00",
        "17",
        "1818",
        "18ff",
        "190100",
        "1a00010000",
        "1b0000000100000000",
        "20",
        "37",
        "3818",
        "40",
        "57", /* 23-byte string */
        "6161",
        "80",
        "a0",
        "c100",
        "d818 00",
        "f4",
        "f0",
        "f820",
        "f8ff",
        "f93c00",
        "fa47c35000",
        "fb3ff199999999999a",
        "f97e00",
        "f97e01",
        "fa7f800001",
        "f90001",
        "8301820203820405",
        "a26161016162820203",
    ] {
        // Pad the 23-byte string case with its content.
        let full = if input == "57" {
            format!("57{}", "00".repeat(23))
        } else {
            input.to_string()
        };
        preferred(&full, &[]);
        deterministic(&full, &[]);
    }
}

#[test]
fn non_preferred_integer_arguments() {
    preferred("1800", &[(0, 2, 2, NonPreferredArgument, "00")]);
    preferred("1817", &[(0, 2, 2, NonPreferredArgument, "17")]);
    preferred("190001", &[(0, 3, 3, NonPreferredArgument, "01")]);
    preferred("1900ff", &[(0, 3, 3, NonPreferredArgument, "18ff")]);
    preferred("1a0000ffff", &[(0, 5, 5, NonPreferredArgument, "19ffff")]);
    preferred(
        "1b00000000ffffffff",
        &[(0, 9, 9, NonPreferredArgument, "1affffffff")],
    );
    preferred("3800", &[(0, 2, 2, NonPreferredArgument, "20")]);
    preferred(
        "3b00000000000000ff",
        &[(0, 9, 9, NonPreferredArgument, "38ff")],
    );
}

#[test]
fn non_preferred_lengths_cover_only_the_head() {
    preferred("5801aa", &[(0, 2, 2, NonPreferredArgument, "41")]);
    preferred(
        "5b0000000000000001aa",
        &[(0, 9, 9, NonPreferredArgument, "41")],
    );
    preferred("780161", &[(0, 2, 2, NonPreferredArgument, "61")]);
    preferred("980100", &[(0, 2, 2, NonPreferredArgument, "81")]);
    preferred("b8010000", &[(0, 2, 2, NonPreferredArgument, "a1")]);
}

#[test]
fn non_preferred_tag_numbers() {
    preferred("d80100", &[(0, 2, 2, NonPreferredArgument, "c1")]);
    preferred("d9001800", &[(0, 3, 3, NonPreferredArgument, "d818")]);
}

#[test]
fn non_preferred_floats() {
    preferred("fa3fc00000", &[(0, 5, 5, NonPreferredFloat, "f93e00")]);
    preferred(
        "fb3ff8000000000000",
        &[(0, 9, 9, NonPreferredFloat, "f93e00")],
    );
    preferred(
        "fb40f86a0000000000",
        &[(0, 9, 9, NonPreferredFloat, "fa47c35000")],
    );
    preferred("fa80000000", &[(0, 5, 5, NonPreferredFloat, "f98000")]);
    preferred("fa33800000", &[(0, 5, 5, NonPreferredFloat, "f90001")]);
    preferred("fa7f800000", &[(0, 5, 5, NonPreferredFloat, "f97c00")]);
    preferred("fa7fc00000", &[(0, 5, 5, NonPreferredFloat, "f97e00")]);
    preferred(
        "fb7ff8000000000000",
        &[(0, 9, 9, NonPreferredFloat, "f97e00")],
    );
    // NaN payloads shrink only when no payload bit is lost.
    preferred("fa7fc02000", &[(0, 5, 5, NonPreferredFloat, "f97e01")]);
    preferred(
        "fb7ff8040000000000",
        &[(0, 9, 9, NonPreferredFloat, "f97e01")],
    );
    preferred("fb7ff0000000000001", &[]);
}

#[test]
fn indefinite_lengths() {
    preferred("9fff", &[(0, 2, 1, IndefiniteLength, "80")]);
    preferred("bfff", &[(0, 2, 1, IndefiniteLength, "a0")]);
    preferred("5fff", &[(0, 2, 1, IndefiniteLength, "40")]);
    preferred("7fff", &[(0, 2, 1, IndefiniteLength, "60")]);
    preferred(
        "5f42010243030405ff",
        &[(0, 9, 1, IndefiniteLength, "450102030405")],
    );
    preferred(
        "7f657374726561646d696e67ff",
        &[(0, 13, 1, IndefiniteLength, "6973747265616d696e67")],
    );
    preferred("bf616101ff", &[(0, 5, 1, IndefiniteLength, "a1616101")]);
}

#[test]
fn indefinite_replacement_is_fully_preferred_and_nested_findings_follow() {
    preferred(
        "9f1801ff",
        &[
            (0, 4, 1, IndefiniteLength, "8101"),
            (1, 3, 2, NonPreferredArgument, "01"),
        ],
    );
    // chunk with a long length
    preferred(
        "5f5801aaff",
        &[
            (0, 5, 1, IndefiniteLength, "41aa"),
            (1, 3, 2, NonPreferredArgument, "41"),
        ],
    );
    // [_ 1, [2, 3], [_ 4, 5]]
    preferred(
        "9f018202039f0405ffff",
        &[
            (0, 10, 1, IndefiniteLength, "8301820203820405"),
            (5, 9, 1, IndefiniteLength, "820405"),
        ],
    );
}

#[test]
fn findings_in_nested_positions() {
    // inside an array
    preferred(
        "83 01 82 1800 02 03",
        &[(3, 5, 2, NonPreferredArgument, "00")],
    );
    // in a tag's content
    preferred("c1 fa3fc00000", &[(1, 6, 5, NonPreferredFloat, "f93e00")]);
    // map key and map value, in document order
    preferred(
        "a1 1801 190002",
        &[
            (1, 3, 2, NonPreferredArgument, "01"),
            (3, 6, 3, NonPreferredArgument, "02"),
        ],
    );
    // outer before inner when they start at the same place? They cannot; but
    // a container's own head comes before its children.
    preferred(
        "9801 1800",
        &[
            (0, 2, 2, NonPreferredArgument, "81"),
            (2, 4, 2, NonPreferredArgument, "00"),
        ],
    );
}

#[test]
fn preferred_findings_ignore_key_order() {
    preferred("a2 02 00 01 00", &[]);
}

#[test]
fn deterministic_findings_flag_key_order() {
    deterministic(
        "a2 02 00 01 00",
        &[(0, 5, 1, MapKeyOrder, "a2 01 00 02 00")],
    );
    // RFC 8949 §4.2.1: "z" (617a) sorts before "aa" (626161).
    deterministic(
        "a2 626161 00 617a 00",
        &[(0, 8, 1, MapKeyOrder, "a2 617a 00 626161 00")],
    );
    deterministic("a2 617a 00 626161 00", &[]);
    // nested map
    deterministic(
        "81 a2 02 00 01 00",
        &[(1, 6, 1, MapKeyOrder, "a2 01 00 02 00")],
    );
}

#[test]
fn deterministic_findings_include_preferred_findings() {
    // a2 | 02 : 18 00 | 01 : 00
    deterministic(
        "a2 02 1800 01 00",
        &[
            (0, 6, 1, MapKeyOrder, "a2 01 00 02 00"),
            (2, 4, 2, NonPreferredArgument, "00"),
        ],
    );
    deterministic("9fff", &[(0, 2, 1, IndefiniteLength, "80")]);
}

#[test]
fn key_order_uses_deterministic_key_encoding() {
    // 0x1801 > 0x02 as written, but key 1 < key 2 once preferred.
    deterministic("a2 1801 00 02 00", &[(1, 3, 2, NonPreferredArgument, "01")]);
    // 0x1803 is key 3, which belongs after key 2.
    deterministic(
        "a2 1803 00 02 00",
        &[
            (0, 6, 1, MapKeyOrder, "a2 02 00 03 00"),
            (1, 3, 2, NonPreferredArgument, "03"),
        ],
    );
}

#[test]
fn duplicate_keys_are_not_an_order_violation() {
    deterministic("a2 01 00 01 01", &[]);
    // ... but keys out of order around a duplicate are; duplicates keep
    // arrival order in the replacement.
    deterministic(
        "a3 01 00 00 00 01 01",
        &[(0, 7, 1, MapKeyOrder, "a3 00 00 01 00 01 01")],
    );
}

#[test]
fn indefinite_unsorted_map_reports_both() {
    deterministic(
        "bf 02 00 01 00 ff",
        &[
            (0, 6, 1, IndefiniteLength, "a2 02 00 01 00"),
            (0, 6, 1, MapKeyOrder, "a2 01 00 02 00"),
        ],
    );
}

#[test]
fn findings_on_built_items() {
    let item = Item::int(1).with_width(Width::U8);
    let findings = preferred_findings(&item);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind, NonPreferredArgument);
    assert_eq!(findings[0].preferred_bytes, [0x01]);
    assert_eq!(findings[0].span, Span::default());
    assert!(preferred_findings(&Item::int(1000)).is_empty());
}

/// Applying a single argument or float finding to the input gives
/// well-formed CBOR with the same meaning and one finding fewer.
#[test]
fn applying_a_finding_fixes_it() {
    for hex_in in [
        "83 01 82 1800 02 03",
        "a1 1801 190002",
        "c1 fa3fc00000",
        "5f5801aaff",
        "9f018202039f0405ffff",
        "d80100",
        "9801 1800",
    ] {
        let input = h(hex_in);
        let item = decode(&input).unwrap();
        let findings = preferred_findings(&item);
        assert!(!findings.is_empty(), "{hex_in}");
        for f in &findings {
            let mut fixed = input[..f.span.start].to_vec();
            fixed.extend_from_slice(&f.preferred_bytes);
            fixed.extend_from_slice(&input[f.span.end..]);
            let fixed_item = decode(&fixed)
                .unwrap_or_else(|e| panic!("{hex_in}: applying {f:?} gave malformed CBOR: {e}"));
            assert_eq!(sem(&fixed_item), sem(&item), "{hex_in}: {f:?}");
            assert!(
                preferred_findings(&fixed_item).len() < findings.len(),
                "{hex_in}: {f:?}"
            );
        }
    }
}

#[test]
fn deterministic_output_has_no_findings() {
    for hex_in in [
        "a2 02 1800 01 00",
        "bf 02 00 01 00 ff",
        "9f018202039f0405ffff",
        "a3 01 00 00 00 01 01",
        "a1 a2 02 00 01 00 00",
        "c1 fa3fc00000",
    ] {
        let input = h(hex_in);
        let item = decode(&input).unwrap();
        let out = encode(&item, EncodeMode::Deterministic);
        let again = decode(&out).unwrap();
        assert_eq!(deterministic_findings(&again), vec![], "{hex_in}");
    }
}
