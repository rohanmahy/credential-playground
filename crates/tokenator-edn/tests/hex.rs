//! `annotated_hex`: one row per data item (plus break rows), aligned with
//! the indented printer's `SpanMap` by path.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::ops::Range;

use common::{enc, h, p};
use tokenator_cbor::{Item, decode};
use tokenator_edn::{
    EmbeddedCbor, HexOptions, HexRow, HexRowKind, HexRows, Path, PathSegment::*, PrintOptions,
    annotated_hex, print,
};

fn rows(bytes: &[u8], opts: &HexOptions) -> HexRows {
    annotated_hex(&decode(bytes).unwrap(), bytes, opts)
}

fn row(
    kind: HexRowKind,
    path: Path,
    depth: usize,
    head: Range<usize>,
    payload: Range<usize>,
    description: &str,
) -> HexRow {
    HexRow {
        kind,
        path,
        depth,
        head,
        payload,
        description: description.into(),
        comment: None,
    }
}

/// Rows cover the input exactly once, in order.
fn check_coverage(r: &HexRows, len: usize) {
    let mut at = 0;
    for row in &r.rows {
        assert_eq!(row.head.start, at, "gap or overlap before {row:?}");
        assert!(row.head.end > row.head.start, "empty head in {row:?}");
        assert_eq!(row.payload.start, row.head.end, "{row:?}");
        at = row.payload.end;
    }
    assert_eq!(at, len);
}

#[test]
fn nested_map_rows() {
    use HexRowKind::Item as I;
    let bytes = h("a1 6161 820102");
    let r = rows(&bytes, &HexOptions::default());
    assert_eq!(
        r.rows,
        [
            row(I, Path::root(), 0, 0..1, 1..1, "map(1)"),
            row(I, p([Key(0)]), 1, 1..2, 2..3, "text(1)"),
            row(I, p([Value(0)]), 1, 3..4, 4..4, "array(2)"),
            row(I, p([Value(0), Index(0)]), 2, 4..5, 5..5, "unsigned(1)"),
            row(I, p([Value(0), Index(1)]), 2, 5..6, 6..6, "unsigned(2)"),
        ]
    );
    check_coverage(&r, bytes.len());
}

#[test]
fn break_rows() {
    use HexRowKind::{Break as B, Item as I};
    let bytes = h("9f 01 bf ff ff");
    let r = rows(&bytes, &HexOptions::default());
    assert_eq!(
        r.rows,
        [
            row(I, Path::root(), 0, 0..1, 1..1, "array(*)"),
            row(I, p([Index(0)]), 1, 1..2, 2..2, "unsigned(1)"),
            row(I, p([Index(1)]), 1, 2..3, 3..3, "map(*)"),
            row(B, p([Index(1)]), 1, 3..4, 4..4, "break"),
            row(B, Path::root(), 0, 4..5, 5..5, "break"),
        ]
    );
}

#[test]
fn chunk_rows() {
    use HexRowKind::{Break as B, Item as I};
    let bytes = h("5f 420102 43030405 ff");
    let r = rows(&bytes, &HexOptions::default());
    assert_eq!(
        r.rows,
        [
            row(I, Path::root(), 0, 0..1, 1..1, "bytes(*)"),
            row(I, p([Chunk(0)]), 1, 1..2, 2..4, "bytes(2)"),
            row(I, p([Chunk(1)]), 1, 4..5, 5..8, "bytes(3)"),
            row(B, Path::root(), 0, 8..9, 9..9, "break"),
        ]
    );
    let r = rows(&h("7fff"), &HexOptions::default());
    assert_eq!(r.rows[0].description, "text(*)");
    assert_eq!(r.rows.len(), 2);
}

#[test]
fn head_descriptions() {
    for (hex, head, payload, description) in [
        ("00", 0..1, 1..1, "unsigned(0)"),
        ("1818", 0..2, 2..2, "unsigned(24)"),
        ("1b0000000000000001", 0..9, 9..9, "unsigned(1)"),
        ("20", 0..1, 1..1, "negative(0)"),
        ("3903e7", 0..3, 3..3, "negative(999)"),
        ("4401020304", 0..1, 1..5, "bytes(4)"),
        ("5900020102", 0..3, 3..5, "bytes(2)"),
        ("6449455446", 0..1, 1..5, "text(4)"),
        ("40", 0..1, 1..1, "bytes(0)"),
        ("80", 0..1, 1..1, "array(0)"),
        ("a0", 0..1, 1..1, "map(0)"),
        ("f4", 0..1, 1..1, "false"),
        ("f5", 0..1, 1..1, "true"),
        ("f6", 0..1, 1..1, "null"),
        ("f7", 0..1, 1..1, "undefined"),
        ("f0", 0..1, 1..1, "simple(16)"),
        ("f8ff", 0..2, 2..2, "simple(255)"),
        ("f93c00", 0..3, 3..3, "float16"),
        ("fa47c35000", 0..5, 5..5, "float32"),
        ("fb3ff199999999999a", 0..9, 9..9, "float64"),
    ] {
        let r = rows(&h(hex), &HexOptions::default());
        assert_eq!(r.rows.len(), 1, "{hex}");
        let row = &r.rows[0];
        assert_eq!(
            (
                row.head.clone(),
                row.payload.clone(),
                row.description.as_str()
            ),
            (head, payload, description),
            "{hex}"
        );
    }
}

#[test]
fn tag_rows() {
    use HexRowKind::Item as I;
    let bytes = h("c1 1a514b67b0");
    let r = rows(&bytes, &HexOptions::default());
    assert_eq!(
        r.rows,
        [
            row(I, Path::root(), 0, 0..1, 1..1, "tag(1)"),
            row(I, p([TagContent]), 1, 1..6, 6..6, "unsigned(1363896240)"),
        ]
    );
    let r = rows(&h("d818 456449455446"), &HexOptions::default());
    assert_eq!(r.rows[0].head, 0..2);
    assert_eq!(r.rows[0].description, "tag(24)");
}

#[test]
fn annotator_comments_on_rows() {
    let ann = |path: &Path, _: &Item| match path.segments() {
        [Key(0)] => Some("iss".to_string()),
        _ => None,
    };
    let opts = HexOptions {
        annotator: Some(&ann),
        ..HexOptions::default()
    };
    let r = rows(&h("bf 01 6178 ff"), &opts);
    let comments: Vec<_> = r.rows.iter().map(|r| r.comment.as_deref()).collect();
    assert_eq!(comments, [None, Some("iss"), None, None]);
}

#[test]
fn embedded_rows_use_absolute_offsets() {
    use HexRowKind::Item as I;
    // [1, 24(<<[2, 3]>>)]
    let bytes = h("82 01 d818 43 820203");
    let opts = HexOptions {
        embedded_cbor: EmbeddedCbor::tagged(),
        ..HexOptions::default()
    };
    let r = rows(&bytes, &opts);
    let t = |segs: &[tokenator_edn::PathSegment]| {
        let mut v = vec![Index(1), TagContent];
        v.extend_from_slice(segs);
        Path(v)
    };
    assert_eq!(
        r.rows,
        [
            row(I, Path::root(), 0, 0..1, 1..1, "array(2)"),
            row(I, p([Index(0)]), 1, 1..2, 2..2, "unsigned(1)"),
            row(I, p([Index(1)]), 1, 2..4, 4..4, "tag(24)"),
            // The payload is shown as rows of its own.
            row(I, t(&[]), 2, 4..5, 5..5, "bytes(3)"),
            row(I, t(&[Embedded(0)]), 3, 5..6, 6..6, "array(2)"),
            row(I, t(&[Embedded(0), Index(0)]), 4, 6..7, 7..7, "unsigned(2)"),
            row(I, t(&[Embedded(0), Index(1)]), 4, 7..8, 8..8, "unsigned(3)"),
        ]
    );
    check_coverage(&r, bytes.len());
    // Without the option the byte string is a single row.
    let r = rows(&bytes, &HexOptions::default());
    assert_eq!(r.rows.len(), 4);
    assert_eq!(r.rows[3].payload, 5..8);
}

#[test]
fn built_items_and_foreign_bytes_do_not_panic() {
    let built = Item::array(vec![Item::int(1)]);
    assert!(
        annotated_hex(&built, &[], &HexOptions::default())
            .rows
            .is_empty()
    );
    let bytes = h("82 01 6568656c6c6f");
    let item = decode(&bytes).unwrap();
    let _ = annotated_hex(&item, &bytes[..3], &HexOptions::default());
    let _ = annotated_hex(&item, &[], &HexOptions::default());
}

/// Hex rows and the indented printer's span map list the same nodes in the
/// same order, and agree on where each node starts in the bytes.
fn check_alignment(bytes: &[u8], embedded: EmbeddedCbor<'_>) {
    let item = decode(bytes).unwrap();
    let r = annotated_hex(
        &item,
        bytes,
        &HexOptions {
            embedded_cbor: embedded,
            ..HexOptions::default()
        },
    );
    let rendered = print(
        &item,
        &PrintOptions {
            embedded_cbor: embedded,
            ..PrintOptions::indented(2)
        },
    );
    let item_rows: Vec<_> = r
        .rows
        .iter()
        .filter(|row| row.kind == HexRowKind::Item)
        .collect();
    let spans: Vec<_> = rendered.spans.iter().collect();
    assert_eq!(item_rows.len(), spans.len(), "{}", rendered.text);
    for (row, (path, span)) in item_rows.iter().zip(spans) {
        assert_eq!(&row.path, path);
        assert_eq!(row.depth, path.depth(), "{path}");
        assert_eq!(span.cbor.map(|s| s.start), Some(row.head.start), "{path}");
    }
    // Every break row closes an item that the printer shows.
    for row in r.rows.iter().filter(|r| r.kind == HexRowKind::Break) {
        assert!(rendered.spans.get(&row.path).is_some());
    }
    check_coverage(&r, bytes.len());
}

#[test]
fn rows_align_with_printed_lines() {
    for edn in [
        "{\"a\": [1, 2], \"b\": 3(h'00')}",
        "[_ 1, [2, 3], {_ \"x\": (_ \"a\", \"b\")}]",
        "{1: 24(<<{1: 2, 3: [4]}>>), 2: <<[5]>>}",
        "[]",
        "7",
        "[[[[1]]]]",
        "{1: 1_1(2), [3]: {}}",
    ] {
        check_alignment(&enc(edn), EmbeddedCbor::OFF);
    }
}

const ALIGN_EMBEDDED: &[&str] = &[
    "{1: 24(<<{1: 2, 3: [4]}>>), 2: <<[5]>>}",
    "[<<1, [2]>>, 63(<<3, 4>>), <<[<<5>>]>>, h'ff', h'']",
    "18([<<{1: -7}>>, {}, <<{1: \"iss\"}>>, h'00'])",
];

#[test]
fn rows_align_with_embedded_views() {
    for edn in ALIGN_EMBEDDED {
        let bytes = enc(edn);
        let item = decode(&bytes).unwrap();
        let paths = common::all_bstr_paths(&item);
        check_alignment(&bytes, EmbeddedCbor::tagged());
        check_alignment(&bytes, EmbeddedCbor::at(&paths));
        check_alignment(&bytes, EmbeddedCbor::at(&paths[..1]));
    }
}

#[test]
fn listed_sequence_rows() {
    use HexRowKind::Item as I;
    // {1: <<1, [2]>>}
    let bytes = h("a1 01 43 01 81 02");
    let paths = [p([Value(0)])];
    let opts = HexOptions {
        embedded_cbor: EmbeddedCbor::at(&paths),
        ..HexOptions::default()
    };
    let r = rows(&bytes, &opts);
    assert_eq!(
        r.rows,
        [
            row(I, Path::root(), 0, 0..1, 1..1, "map(1)"),
            row(I, p([Key(0)]), 1, 1..2, 2..2, "unsigned(1)"),
            row(I, p([Value(0)]), 1, 2..3, 3..3, "bytes(3)"),
            row(I, p([Value(0), Embedded(0)]), 2, 3..4, 4..4, "unsigned(1)"),
            row(I, p([Value(0), Embedded(1)]), 2, 4..5, 5..5, "array(1)"),
            row(
                I,
                p([Value(0), Embedded(1), Index(0)]),
                3,
                5..6,
                6..6,
                "unsigned(2)"
            ),
        ]
    );
    check_coverage(&r, bytes.len());
    // Unlisted, the same bytes are one row.
    assert_eq!(rows(&bytes, &HexOptions::default()).rows.len(), 3);
}
