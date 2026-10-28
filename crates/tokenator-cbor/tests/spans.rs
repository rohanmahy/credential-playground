//! Span { start, end, head_len } of decoded items.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::{check_spans, h};
use tokenator_cbor::{Item, Span, Value, decode, decode_seq};

fn sp(start: usize, end: usize, head_len: usize) -> Span {
    Span {
        start,
        end,
        head_len,
    }
}

fn root(hex_in: &str) -> Span {
    let input = h(hex_in);
    let item = decode(&input).unwrap();
    check_spans(&item, &input).unwrap();
    item.span
}

fn array<'i, 'a>(item: &'i Item<'a>) -> &'i [Item<'a>] {
    match &item.value {
        Value::Array(a) => a,
        other => panic!("not an array: {other:?}"),
    }
}

#[test]
fn scalar_spans() {
    let cases: &[(&str, Span)] = &[
        ("00", sp(0, 1, 1)),
        ("17", sp(0, 1, 1)),
        ("1818", sp(0, 2, 2)),
        ("1903e8", sp(0, 3, 3)),
        ("1a000f4240", sp(0, 5, 5)),
        ("1b000000e8d4a51000", sp(0, 9, 9)),
        ("3903e7", sp(0, 3, 3)),
        ("f4", sp(0, 1, 1)),
        ("f0", sp(0, 1, 1)),
        ("f8ff", sp(0, 2, 2)),
        ("f93c00", sp(0, 3, 3)),
        ("fa47c35000", sp(0, 5, 5)),
        ("fb3ff199999999999a", sp(0, 9, 9)),
    ];
    for (input, expected) in cases {
        assert_eq!(root(input), *expected, "{input}");
    }
}

#[test]
fn string_spans() {
    let cases: &[(&str, Span)] = &[
        ("40", sp(0, 1, 1)),
        ("6449455446", sp(0, 5, 1)),
        ("5803616263", sp(0, 5, 2)),
        ("5b0000000000000001aa", sp(0, 10, 9)),
        ("5fff", sp(0, 2, 1)),
        ("5f42010243030405ff", sp(0, 9, 1)),
    ];
    for (input, expected) in cases {
        assert_eq!(root(input), *expected, "{input}");
    }
}

#[test]
fn chunk_spans() {
    let input = h("5f 420102 43030405 ff");
    let item = decode(&input).unwrap();
    let chunks: Vec<Span> = item.chunks.iter().map(|c| c.span).collect();
    assert_eq!(chunks, [sp(1, 4, 1), sp(4, 8, 1)]);

    let input = h("7f 780161 ff");
    let item = decode(&input).unwrap();
    assert_eq!(item.chunks[0].span, sp(1, 4, 2));
}

#[test]
fn nested_array_spans() {
    // [1, [2, 3], [4, 5]]
    let input = h("83 01 82 02 03 82 04 05");
    let item = decode(&input).unwrap();
    assert_eq!(item.span, sp(0, 8, 1));
    let a = array(&item);
    assert_eq!(a[0].span, sp(1, 2, 1));
    assert_eq!(a[1].span, sp(2, 5, 1));
    assert_eq!(array(&a[1])[0].span, sp(3, 4, 1));
    assert_eq!(array(&a[1])[1].span, sp(4, 5, 1));
    assert_eq!(a[2].span, sp(5, 8, 1));
    assert_eq!(array(&a[2])[1].span, sp(7, 8, 1));
}

#[test]
fn indefinite_spans_include_break() {
    // [_ 1, [2, 3], [_ 4, 5]]
    let input = h("9f 01 82 02 03 9f 04 05 ff ff");
    let item = decode(&input).unwrap();
    assert_eq!(item.span, sp(0, 10, 1));
    let a = array(&item);
    assert_eq!(a[1].span, sp(2, 5, 1));
    assert_eq!(a[2].span, sp(5, 9, 1));
    assert_eq!(array(&a[2])[0].span, sp(6, 7, 1));
}

#[test]
fn map_spans() {
    // {_ "a": 1, "b": [_ 2, 3]}
    let input = h("bf 6161 01 6162 9f 02 03 ff ff");
    let item = decode(&input).unwrap();
    assert_eq!(item.span, sp(0, 11, 1));
    let Value::Map(entries) = &item.value else {
        panic!("not a map");
    };
    assert_eq!(entries[0].0.span, sp(1, 3, 1));
    assert_eq!(entries[0].1.span, sp(3, 4, 1));
    assert_eq!(entries[1].0.span, sp(4, 6, 1));
    assert_eq!(entries[1].1.span, sp(6, 10, 1));

    // {1000: h'aa'} with a two-byte map length
    let input = h("b90001 1903e8 41aa");
    let item = decode(&input).unwrap();
    assert_eq!(item.span, sp(0, 8, 3));
    let Value::Map(entries) = &item.value else {
        panic!("not a map");
    };
    assert_eq!(entries[0].0.span, sp(3, 6, 3));
    assert_eq!(entries[0].1.span, sp(6, 8, 1));
}

#[test]
fn tag_spans() {
    let input = h("c1 1a514b67b0");
    let item = decode(&input).unwrap();
    assert_eq!(item.span, sp(0, 6, 1));
    let Value::Tag(1, inner) = &item.value else {
        panic!("not tag 1");
    };
    assert_eq!(inner.span, sp(1, 6, 5));

    let input = h("d818 456449455446");
    let item = decode(&input).unwrap();
    assert_eq!(item.span, sp(0, 8, 2));
    let Value::Tag(24, inner) = &item.value else {
        panic!("not tag 24");
    };
    assert_eq!(inner.span, sp(2, 8, 1));

    // nested tags: 55799(1(0)) with a 2-byte tag head
    let input = h("d9d9f7 c1 00");
    let item = decode(&input).unwrap();
    assert_eq!(item.span, sp(0, 5, 3));
    let Value::Tag(55799, inner) = &item.value else {
        panic!("not tag 55799");
    };
    assert_eq!(inner.span, sp(3, 5, 1));
    let Value::Tag(1, innermost) = &inner.value else {
        panic!("not tag 1");
    };
    assert_eq!(innermost.span, sp(4, 5, 1));
}

#[test]
fn sequence_spans_are_absolute() {
    let input = h("01 1903e8 6161 9f00ff");
    let items = decode_seq(&input).unwrap();
    let spans: Vec<Span> = items.iter().map(|i| i.span).collect();
    assert_eq!(spans, [sp(0, 1, 1), sp(1, 4, 3), sp(4, 6, 1), sp(6, 9, 1)]);
    for item in &items {
        check_spans(item, &input).unwrap();
    }
    let Value::Array(a) = &items[3].value else {
        panic!("not an array");
    };
    assert_eq!(a[0].span, sp(7, 8, 1));
}

#[test]
fn span_invariants_on_a_mixed_document() {
    // A COSE_Sign1-like structure with assorted encodings.
    let input = h(concat!(
        "d2",                                   // tag 18
        "84",                                   // array(4)
        "43a10126",                             // bstr << {1: -7} >>
        "bf 04 5801aa 1818 9f f4 f97e00 ff ff", // {_ 4: h'aa'_0, 24: [_ false, NaN]}
        "5f 4101 4102 ff",                      // (_ h'01', h'02')
        "5840",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
    ));
    let item = decode(&input).unwrap();
    check_spans(&item, &input).unwrap();
}
