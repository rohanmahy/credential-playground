//! duplicate_keys: detection of repeated map keys (#7). Keys are compared
//! by their deterministic serialization (draft-ietf-cbor-serialization-11
//! §5), so encodings of the same value count as the same key.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::{decode_diag, h};
use tokenator_cbor::{DuplicateKey, Item, PathStep, Span, decode, duplicate_keys};

use PathStep::{Index, Key, TagContent, Value as Val};

fn sp(start: usize, end: usize, head_len: usize) -> Span {
    Span {
        start,
        end,
        head_len,
    }
}

fn dups(hex_in: &str) -> Vec<DuplicateKey> {
    let input = h(hex_in);
    let item = decode(&input).unwrap();
    duplicate_keys(&item)
}

fn dup(
    path: Vec<PathStep>,
    map: Span,
    first: usize,
    duplicate: usize,
    first_key: Span,
    duplicate_key: Span,
) -> DuplicateKey {
    DuplicateKey {
        path,
        map,
        first,
        duplicate,
        first_key,
        duplicate_key,
    }
}

#[test]
fn no_duplicates() {
    for input in [
        "a0",
        "a1 01 00",
        "a2 01 00 02 00",
        "a2 6161 00 6162 00",
        "82 a1 01 00 a1 01 00", // same key in different maps
        "83 01 01 01",
        "00",
    ] {
        assert_eq!(dups(input), vec![], "{input}");
    }
}

#[test]
fn simple_duplicate() {
    assert_eq!(
        dups("a2 01 00 01 01"),
        [dup(vec![], sp(0, 5, 1), 0, 1, sp(1, 2, 1), sp(3, 4, 1))]
    );
}

#[test]
fn decoding_still_keeps_duplicates() {
    assert_eq!(decode_diag("a2 01 00 01 01"), "{1: 0, 1: 1}");
}

#[test]
fn each_later_occurrence_pairs_with_the_first() {
    // {"a": 0, "a": 1, "a": 2}
    assert_eq!(
        dups("a3 6161 00 6161 01 6161 02"),
        [
            dup(vec![], sp(0, 10, 1), 0, 1, sp(1, 3, 1), sp(4, 6, 1)),
            dup(vec![], sp(0, 10, 1), 0, 2, sp(1, 3, 1), sp(7, 9, 1)),
        ]
    );
    // two different duplicated keys, interleaved
    let found: Vec<(usize, usize)> = dups("a4 01 00 02 00 01 00 02 00")
        .iter()
        .map(|d| (d.first, d.duplicate))
        .collect();
    assert_eq!(found, [(0, 2), (1, 3)]);
}

#[test]
fn keys_compare_by_deterministic_encoding() {
    for input in [
        "a2 01 00 1801 00",                       // non-preferred argument
        "a2 01 00 c24101 00",                     // bignum that fits major type 0
        "a2 20 00 c340 00",                       // negative bignum
        "a2 f97e00 00 fa7fc00000 00",             // NaN in two widths
        "a2 f97e00 00 f97e01 00",                 // every NaN is the canonical NaN
        "a2 f93c00 00 fb3ff0000000000000 00",     // 1.0 in two widths
        "a2 4161 00 5f4161ff 00",                 // indefinite vs definite bytes
        "a2 6161 00 7f6161ff 00",                 // indefinite vs definite text
        "a2 8101 00 9f01ff 00",                   // indefinite vs definite array
        "a2 a2 01 00 02 00 00 a2 02 00 01 00 00", // maps sort before comparing
        "a2 c1 01 00 d801 01 00",                 // non-preferred tag head
    ] {
        let found = dups(input);
        assert_eq!(found.len(), 1, "{input}: {found:?}");
        assert_eq!((found[0].first, found[0].duplicate), (0, 1), "{input}");
    }
}

#[test]
fn different_values_are_not_duplicates() {
    for input in [
        "a2 f90000 00 f98000 00", // 0.0 and -0.0
        "a2 01 00 f93c00 00",     // 1 and 1.0
        "a2 6161 00 4161 00",     // "a" and h'61'
        "a2 01 00 c101 00",       // 1 and 1(1)
        "a2 f4 00 f6 00",         // false and null
        "a2 f6 00 f7 00",         // null and undefined
        "a2 c24101 00 c34100 00", // 1 and -2
    ] {
        assert_eq!(dups(input), vec![], "{input}");
    }
}

#[test]
fn nested_maps_report_their_path() {
    // [0, {0: {1: 0, 1: 0}}]
    assert_eq!(
        dups("82 00 a1 00 a2 01 00 01 00"),
        [dup(
            vec![Index(1), Val(0)],
            sp(4, 9, 1),
            0,
            1,
            sp(5, 6, 1),
            sp(7, 8, 1)
        )]
    );
    // {{1: 0, 1: 0}: 0}: the map is a key
    assert_eq!(
        dups("a1 a2 01 00 01 00 00"),
        [dup(
            vec![Key(0)],
            sp(1, 6, 1),
            0,
            1,
            sp(2, 3, 1),
            sp(4, 5, 1)
        )]
    );
    // 1({1: 0, 1: 0})
    assert_eq!(
        dups("c1 a2 01 00 01 00"),
        [dup(
            vec![TagContent],
            sp(1, 6, 1),
            0,
            1,
            sp(2, 3, 1),
            sp(4, 5, 1)
        )]
    );
}

#[test]
fn outer_map_before_inner_map() {
    // {1: {2: 0, 2: 0}, 1: 0}
    assert_eq!(
        dups("a2 01 a2 02 00 02 00 01 00"),
        [
            dup(vec![], sp(0, 9, 1), 0, 1, sp(1, 2, 1), sp(7, 8, 1)),
            dup(vec![Val(0)], sp(2, 7, 1), 0, 1, sp(3, 4, 1), sp(5, 6, 1)),
        ]
    );
}

#[test]
fn indefinite_maps() {
    assert_eq!(
        dups("bf 01 00 01 00 ff"),
        [dup(vec![], sp(0, 6, 1), 0, 1, sp(1, 2, 1), sp(3, 4, 1))]
    );
}

#[test]
fn built_items() {
    let item = Item::array(vec![Item::map(vec![
        (Item::text("a"), Item::int(0)),
        (Item::text("b"), Item::int(1)),
        (Item::text("a"), Item::int(2)),
    ])]);
    let found = duplicate_keys(&item);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path, [Index(0)]);
    assert_eq!((found[0].first, found[0].duplicate), (0, 2));
    assert_eq!(found[0].map, Span::default());
}

#[test]
fn deep_nesting_does_not_overflow() {
    // MAX_DEPTH maps nested through values, the innermost with a duplicate
    let depth = tokenator_cbor::MAX_DEPTH - 1;
    let mut input = "a100".repeat(depth);
    input.push_str("a2 01 00 01 00");
    let found = dups(&input);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path.len(), depth);
}
