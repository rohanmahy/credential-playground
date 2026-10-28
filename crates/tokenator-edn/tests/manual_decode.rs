//! `decode_embedded`: decoding a byte string the user picked by hand
//! (issue #15). The first data item is decoded; trailing bytes are a
//! warning; empty, truncated, or malformed content is an error. Spans are
//! absolute in the outer input, so the printer's `SpanMap` and the hex rows
//! of the decoded view line up with the original bytes.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::borrow::Cow;

use common::{h, p};
use tokenator_cbor::{DecodeErrorKind, Span, Value, decode};
use tokenator_edn::{
    EmbeddedCbor, EmbeddedWarning, HexOptions, HexRowKind, Path, PathSegment::*, PrintOptions,
    annotated_hex, decode_embedded, print,
};

/// [1, h'820102'] — the byte string's content [1, 2] is at 3..6.
const DOC: &str = "82 01 43 820102";

#[test]
fn exact_content() {
    let outer = h(DOC);
    let view = decode_embedded(&outer, 3..6).unwrap();
    assert!(view.warnings.is_empty());
    assert_eq!(
        view.item.span,
        Span {
            start: 3,
            end: 6,
            head_len: 1
        }
    );
    let Value::Array(items) = &view.item.value else {
        panic!("{:?}", view.item)
    };
    assert_eq!(items[0].span.start, 4);
    assert_eq!(items[1].span.start, 5);
    assert_eq!(items[1].value, Value::Uint(2));
}

#[test]
fn trailing_bytes_are_a_warning() {
    // h'0102': the content holds two items.
    let outer = h("42 01 02");
    let view = decode_embedded(&outer, 1..3).unwrap();
    assert_eq!(view.item.value, Value::Uint(1));
    assert_eq!(view.item.span.start, 1);
    assert_eq!(
        view.warnings,
        [EmbeddedWarning::TrailingBytes { offset: 2, len: 1 }]
    );
    // Trailing garbage that is not CBOR at all.
    let outer = h("43 01 ff ff");
    let view = decode_embedded(&outer, 1..4).unwrap();
    assert_eq!(
        view.warnings,
        [EmbeddedWarning::TrailingBytes { offset: 2, len: 2 }]
    );
    // Several trailing items.
    let outer = h("01 02 03");
    let view = decode_embedded(&outer, 0..3).unwrap();
    assert_eq!(
        view.warnings,
        [EmbeddedWarning::TrailingBytes { offset: 1, len: 2 }]
    );
}

#[test]
fn malformed_content_is_an_error_with_absolute_offsets() {
    // Truncated array: [1, ?]
    let outer = h("42 82 01");
    let e = decode_embedded(&outer, 1..3).unwrap_err();
    assert_eq!(e.kind, DecodeErrorKind::UnexpectedEof);
    assert_eq!(e.offset, 1);
    // Reserved additional information.
    let outer = h("41 1c");
    let e = decode_embedded(&outer, 1..2).unwrap_err();
    assert_eq!(e.kind, DecodeErrorKind::ReservedAdditionalInfo(28));
    assert_eq!(e.offset, 1);
    // A stray break.
    let outer = h("41 ff");
    assert_eq!(
        decode_embedded(&outer, 1..2).unwrap_err().kind,
        DecodeErrorKind::UnexpectedBreak
    );
    // Truncated string inside: the item does not fit in the content even if
    // the outer input continues.
    let outer = h("42 62 61 61");
    let e = decode_embedded(&outer, 1..3).unwrap_err();
    assert_eq!(e.kind, DecodeErrorKind::UnexpectedEof);
}

#[test]
fn empty_and_out_of_range_content() {
    let outer = h(DOC);
    let e = decode_embedded(&outer, 3..3).unwrap_err();
    assert_eq!((e.kind, e.offset), (DecodeErrorKind::UnexpectedEof, 3));
    let e = decode_embedded(&outer, 3..99).unwrap_err();
    assert_eq!(
        (e.kind, e.offset),
        (DecodeErrorKind::UnexpectedEof, outer.len())
    );
    #[allow(clippy::reversed_empty_ranges)]
    let reversed = 5..3;
    assert!(decode_embedded(&outer, reversed).is_err());
}

#[test]
fn decoded_view_borrows_the_input() {
    // h'6449455446' = bstr holding "IETF"
    let outer = h("45 6449455446");
    let view = decode_embedded(&outer, 1..6).unwrap();
    let Value::Text(Cow::Borrowed(t)) = &view.item.value else {
        panic!("{:?}", view.item.value)
    };
    assert_eq!(*t, "IETF");
    let range = outer.as_ptr_range();
    assert!(range.contains(&t.as_ptr()));
}

#[test]
fn printing_the_view_reports_absolute_spans() {
    let outer = h(DOC);
    let view = decode_embedded(&outer, 3..6).unwrap();
    let r = print(&view.item, &PrintOptions::new());
    assert_eq!(r.text, "[1, 2]");
    let starts: Vec<_> = r
        .spans
        .iter()
        .map(|(path, s)| (path.to_string(), s.cbor.map(|c| c.start..c.end)))
        .collect();
    assert_eq!(
        starts,
        [
            ("".to_string(), Some(3..6)),
            ("0".to_string(), Some(4..5)),
            ("1".to_string(), Some(5..6)),
        ]
    );
}

#[test]
fn hex_rows_of_the_view_use_the_outer_bytes() {
    let outer = h(DOC);
    let view = decode_embedded(&outer, 3..6).unwrap();
    let rows = annotated_hex(&view.item, &outer, &HexOptions::default()).rows;
    let got: Vec<_> = rows
        .iter()
        .map(|r| (r.path.clone(), r.head.clone(), r.description.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            (Path::root(), 3..4, "array(2)"),
            (p([Index(0)]), 4..5, "unsigned(1)"),
            (p([Index(1)]), 5..6, "unsigned(2)"),
        ]
    );
    assert!(rows.iter().all(|r| r.kind == HexRowKind::Item));
}

#[test]
fn view_with_trailing_bytes_still_prints_and_has_rows() {
    let outer = h("43 81 07 ff");
    let view = decode_embedded(&outer, 1..4).unwrap();
    assert_eq!(view.warnings.len(), 1);
    assert_eq!(print(&view.item, &PrintOptions::new()).text, "[7]");
    let rows = annotated_hex(&view.item, &outer, &HexOptions::default()).rows;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].head, 2..3);
}

#[test]
fn matches_the_inline_view_when_there_are_no_warnings() {
    // Once a manual decode comes back clean, listing the path shows the
    // same item inline, with the same text and the same CBOR spans.
    let outer = h(DOC);
    let doc = decode(&outer).unwrap();
    let view = decode_embedded(&outer, 3..6).unwrap();
    assert!(view.warnings.is_empty());
    let alone = print(&view.item, &PrintOptions::new());
    let paths = [p([Index(1)])];
    let inline = print(
        &doc,
        &PrintOptions {
            embedded_cbor: EmbeddedCbor::at(&paths),
            ..PrintOptions::new()
        },
    );
    assert_eq!(inline.text, format!("[1, <<{}>>]", alone.text));
    let inner = p([Index(1), Embedded(0)]);
    assert_eq!(
        inline.spans.get(&inner).unwrap().cbor,
        alone.spans.get(&Path::root()).unwrap().cbor
    );
}

#[test]
fn concatenated_content_of_an_indefinite_byte_string() {
    // (_ h'82', h'0102'): content is not contiguous; decode the concatenation.
    let outer = h("5f 4182 420102 ff");
    let doc = decode(&outer).unwrap();
    let Value::Bytes(content) = &doc.value else {
        panic!()
    };
    let view = decode_embedded(content, 0..content.len()).unwrap();
    assert!(view.warnings.is_empty());
    assert_eq!(print(&view.item, &PrintOptions::new()).text, "[1, 2]");
}
