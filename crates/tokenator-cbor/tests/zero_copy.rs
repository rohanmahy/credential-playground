//! Definite-length strings borrow from the input; indefinite ones are owned.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::borrow::Cow;

use common::h;
use tokenator_cbor::{Item, Value, decode, decode_seq};

fn points_into(slice: &[u8], input: &[u8]) -> bool {
    let range = input.as_ptr_range();
    let s = slice.as_ptr_range();
    range.start <= s.start && s.end <= range.end
}

fn assert_borrowed(item: &Item, input: &[u8]) {
    match &item.value {
        Value::Bytes(b) => {
            assert!(matches!(b, Cow::Borrowed(_)), "bytes not borrowed");
            assert!(points_into(b, input), "bytes borrowed from elsewhere");
        }
        Value::Text(t) => {
            assert!(matches!(t, Cow::Borrowed(_)), "text not borrowed");
            assert!(
                points_into(t.as_bytes(), input),
                "text borrowed from elsewhere"
            );
        }
        other => panic!("not a string: {other:?}"),
    }
}

#[test]
fn definite_bytes_and_text_borrow() {
    let input = h("4401020304");
    let item = decode(&input).unwrap();
    assert_borrowed(&item, &input);
    assert_eq!(item.value, Value::Bytes(Cow::Borrowed(&input[1..])));

    let input = h("6449455446");
    let item = decode(&input).unwrap();
    assert_borrowed(&item, &input);
    assert!(matches!(&item.value, Value::Text(Cow::Borrowed("IETF"))));
}

#[test]
fn empty_and_long_headed_strings_borrow() {
    for hex_in in ["40", "60", "5801aa", "5b0000000000000001aa", "780161"] {
        let input = h(hex_in);
        let item = decode(&input).unwrap();
        assert!(
            matches!(
                &item.value,
                Value::Bytes(Cow::Borrowed(_)) | Value::Text(Cow::Borrowed(_))
            ),
            "{hex_in}"
        );
    }
}

#[test]
fn nested_strings_borrow() {
    // {"a": [h'0102', {"b": "c"}], 1(h'ff'): "d"}
    let input = h("a2 6161 82 420102 a1 6162 6163 c1 41ff 6164");
    let item = decode(&input).unwrap();
    let Value::Map(entries) = &item.value else {
        panic!("not a map");
    };
    assert_borrowed(&entries[0].0, &input);
    let Value::Array(arr) = &entries[0].1.value else {
        panic!("not an array");
    };
    assert_borrowed(&arr[0], &input);
    let Value::Map(inner) = &arr[1].value else {
        panic!("not a map");
    };
    assert_borrowed(&inner[0].0, &input);
    assert_borrowed(&inner[0].1, &input);
    let Value::Tag(1, tagged) = &entries[1].0.value else {
        panic!("not tag 1");
    };
    assert_borrowed(tagged, &input);
    assert_borrowed(&entries[1].1, &input);
}

#[test]
fn indefinite_strings_are_owned_but_chunks_borrow() {
    let input = h("5f42010243030405ff");
    let item = decode(&input).unwrap();
    assert!(matches!(&item.value, Value::Bytes(Cow::Owned(_))));
    for chunk in &item.chunks {
        assert_borrowed(chunk, &input);
    }

    let input = h("7f657374726561646d696e67ff");
    let item = decode(&input).unwrap();
    assert!(matches!(&item.value, Value::Text(Cow::Owned(_))));
    for chunk in &item.chunks {
        assert_borrowed(chunk, &input);
    }
}

#[test]
fn sequence_items_borrow() {
    let input = h("6161 4101");
    let items = decode_seq(&input).unwrap();
    for item in &items {
        assert_borrowed(item, &input);
    }
}
