//! `SpanMap`: text ranges, line ranges, and CBOR spans of printed nodes;
//! `Path` display and parsing; source spans from `parse_with`.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::str::FromStr;

use common::{check_span_map, deep, enc, h, p};
use tokenator_cbor::{Item, Span, decode};
use tokenator_edn::{
    EmbeddedCbor, EncodingIndicators, ParseOptions, Path, PathSegment, PathSegment::*,
    PrintOptions, Rendered, parse_with, print,
};

fn slice<'t>(r: &'t Rendered, path: &Path) -> &'t str {
    let span = r
        .spans
        .get(path)
        .unwrap_or_else(|| panic!("no entry for {path}"));
    &r.text[span.text.clone()]
}

fn sp(start: usize, end: usize, head_len: usize) -> Option<Span> {
    Some(Span {
        start,
        end,
        head_len,
    })
}

const DOC: &str = "a2 6161 820102 6162 c3 4100"; // {"a": [1, 2], "b": 3(h'00')}

#[test]
fn compact_text_ranges_and_cbor_spans() {
    let bytes = h(DOC);
    let item = decode(&bytes).unwrap();
    let r = print(&item, &PrintOptions::new());
    assert_eq!(r.text, "{\"a\": [1, 2], \"b\": 3(h'00')}");
    let expect: &[(Path, &str, std::ops::Range<usize>, Option<Span>)] = &[
        (
            Path::root(),
            "{\"a\": [1, 2], \"b\": 3(h'00')}",
            0..28,
            sp(0, 11, 1),
        ),
        (p([Key(0)]), "\"a\"", 1..4, sp(1, 3, 1)),
        (p([Value(0)]), "[1, 2]", 6..12, sp(3, 6, 1)),
        (p([Value(0), Index(0)]), "1", 7..8, sp(4, 5, 1)),
        (p([Value(0), Index(1)]), "2", 10..11, sp(5, 6, 1)),
        (p([Key(1)]), "\"b\"", 14..17, sp(6, 8, 1)),
        (p([Value(1)]), "3(h'00')", 19..27, sp(8, 11, 1)),
        (p([Value(1), TagContent]), "h'00'", 21..26, sp(9, 11, 1)),
    ];
    assert_eq!(r.spans.len(), expect.len());
    for ((path, text, range, cbor), (gpath, gspan)) in expect.iter().zip(r.spans.iter()) {
        assert_eq!(path, gpath, "pre-order");
        assert_eq!(&r.text[gspan.text.clone()], *text, "{path}");
        assert_eq!(gspan.text, *range, "{path}");
        assert_eq!(gspan.lines, 0..1, "{path}");
        assert_eq!(gspan.cbor, *cbor, "{path}");
    }
    check_span_map(&item, Some(&bytes), &r).unwrap();
}

#[test]
fn indented_line_ranges() {
    let bytes = h(DOC);
    let item = decode(&bytes).unwrap();
    let r = print(&item, &PrintOptions::indented(2));
    assert_eq!(
        r.text,
        "{\n  \"a\": [\n    1,\n    2\n  ],\n  \"b\": 3(h'00')\n}"
    );
    for (path, lines) in [
        (Path::root(), 0..7),
        (p([Key(0)]), 1..2),
        (p([Value(0)]), 1..5),
        (p([Value(0), Index(0)]), 2..3),
        (p([Value(0), Index(1)]), 3..4),
        (p([Key(1)]), 5..6),
        (p([Value(1)]), 5..6),
        (p([Value(1), TagContent]), 5..6),
    ] {
        assert_eq!(r.spans.get(&path).unwrap().lines, lines, "{path}");
    }
    assert_eq!(slice(&r, &p([Value(0)])), "[\n    1,\n    2\n  ]");
    check_span_map(&item, Some(&bytes), &r).unwrap();
}

#[test]
fn indicators_are_inside_ranges_and_comments_outside() {
    let r = print(&decode(&h("82 1801 9f01ff")).unwrap(), &PrintOptions::new());
    assert_eq!(r.text, "[1_0, [_ 1]]");
    assert_eq!(slice(&r, &p([Index(0)])), "1_0");
    assert_eq!(slice(&r, &p([Index(1)])), "[_ 1]");

    let ann = |path: &Path, _: &Item| (path.depth() == 1).then(|| "c".to_string());
    let opts = PrintOptions {
        annotator: Some(&ann),
        ..PrintOptions::new()
    };
    let bytes = h("a1 01 6178");
    let item = decode(&bytes).unwrap();
    let r = print(&item, &opts);
    assert_eq!(r.text, "{/ c / 1: / c / \"x\"}");
    assert_eq!(slice(&r, &p([Key(0)])), "1");
    assert_eq!(slice(&r, &p([Value(0)])), "\"x\"");
    assert_eq!(slice(&r, &Path::root()), r.text);
    check_span_map(&item, Some(&bytes), &r).unwrap();
}

#[test]
fn embedded_cbor_spans_are_absolute() {
    // [1, 24(<<[2, 3]>>)]
    let bytes = h("82 01 d818 43 820203");
    let item = decode(&bytes).unwrap();
    let opts = PrintOptions {
        embedded_cbor: EmbeddedCbor::tagged(),
        ..PrintOptions::new()
    };
    let r = print(&item, &opts);
    assert_eq!(r.text, "[1, 24(<<[2, 3]>>)]");
    let e = |segs: &[PathSegment]| {
        let mut v = vec![Index(1), TagContent];
        v.extend_from_slice(segs);
        Path(v)
    };
    let expect = [
        (Path::root(), sp(0, 8, 1)),
        (p([Index(0)]), sp(1, 2, 1)),
        (p([Index(1)]), sp(2, 8, 2)),
        (e(&[]), sp(4, 8, 1)),
        (e(&[Embedded(0)]), sp(5, 8, 1)),
        (e(&[Embedded(0), Index(0)]), sp(6, 7, 1)),
        (e(&[Embedded(0), Index(1)]), sp(7, 8, 1)),
    ];
    let got: Vec<_> = r.spans.iter().map(|(p, s)| (p.clone(), s.cbor)).collect();
    assert_eq!(got, expect);
    assert_eq!(slice(&r, &e(&[])), "<<[2, 3]>>");
    assert_eq!(slice(&r, &e(&[Embedded(0)])), "[2, 3]");
    assert_eq!(slice(&r, &e(&[Embedded(0), Index(1)])), "3");
}

#[test]
fn embedded_sequence_items_are_indexed() {
    // {1: 24(<<{1: 2, 3: 4}>>)}
    let bytes = h("a1 01 d818 45 a2 01 02 03 04");
    let item = decode(&bytes).unwrap();
    let opts = PrintOptions {
        embedded_cbor: EmbeddedCbor::tagged(),
        ..PrintOptions::indented(2)
    };
    let r = print(&item, &opts);
    let base = vec![Value(0), TagContent, Embedded(0)];
    let k1 = Path([base.clone(), vec![Key(1)]].concat());
    assert_eq!(slice(&r, &k1), "3");
    assert_eq!(r.spans.get(&k1).unwrap().cbor, sp(8, 9, 1));
}

#[test]
fn listed_sequence_spans() {
    // {1: <<1, [2]>>}: a listed byte string holding a two-item sequence.
    let bytes = h("a1 01 43 01 81 02");
    let item = decode(&bytes).unwrap();
    let paths = [p([Value(0)])];
    let opts = PrintOptions {
        embedded_cbor: EmbeddedCbor::at(&paths),
        ..PrintOptions::new()
    };
    let r = print(&item, &opts);
    assert_eq!(r.text, "{1: <<1, [2]>>}");
    let got: Vec<_> = r
        .spans
        .iter()
        .map(|(p, s)| (p.to_string(), s.cbor))
        .collect();
    assert_eq!(
        got,
        [
            ("".to_string(), sp(0, 6, 1)),
            ("k0".to_string(), sp(1, 2, 1)),
            ("v0".to_string(), sp(2, 6, 1)),
            ("v0/e0".to_string(), sp(3, 4, 1)),
            ("v0/e1".to_string(), sp(4, 6, 1)),
            ("v0/e1/0".to_string(), sp(5, 6, 1)),
        ]
    );
    assert_eq!(slice(&r, &p([Value(0), Embedded(1)])), "[2]");
}

#[test]
fn unlisted_paths_get_no_embedded_entries() {
    let bytes = h("a1 01 43 01 81 02");
    let item = decode(&bytes).unwrap();
    let r = print(&item, &PrintOptions::new());
    assert!(
        r.spans
            .iter()
            .all(|(p, _)| !p.segments().iter().any(|s| matches!(s, Embedded(_))))
    );
    check_span_map(&item, Some(&bytes), &r).unwrap();
}

#[test]
fn chunk_spans() {
    let bytes = h("7f 657374726561 646d696e67 ff");
    let item = decode(&bytes).unwrap();
    let r = print(&item, &PrintOptions::new());
    assert_eq!(r.text, "ilts<<\"strea\", \"ming\">>");
    assert_eq!(slice(&r, &p([Chunk(0)])), "\"strea\"");
    assert_eq!(slice(&r, &p([Chunk(1)])), "\"ming\"");
    assert_eq!(r.spans.get(&p([Chunk(0)])).unwrap().cbor, sp(1, 7, 1));
    assert_eq!(r.spans.get(&p([Chunk(1)])).unwrap().cbor, sp(7, 12, 1));
    assert_eq!(r.spans.get(&Path::root()).unwrap().cbor, sp(0, 13, 1));
    check_span_map(&item, Some(&bytes), &r).unwrap();
}

#[test]
fn arrival_order_is_kept() {
    let bytes = enc("{3: \"c\", 1: \"a\", 2: \"b\"}");
    let item = decode(&bytes).unwrap();
    let r = print(&item, &PrintOptions::new());
    assert_eq!(r.text, "{3: \"c\", 1: \"a\", 2: \"b\"}");
    assert_eq!(slice(&r, &p([Key(0)])), "3");
    assert_eq!(slice(&r, &p([Key(1)])), "1");
    assert_eq!(slice(&r, &p([Value(2)])), "\"b\"");
    let keys: Vec<_> = r
        .spans
        .iter()
        .filter(|(p, _)| p.depth() == 1)
        .map(|(p, _)| p.to_string())
        .collect();
    assert_eq!(keys, ["k0", "v0", "k1", "v1", "k2", "v2"]);
}

#[test]
fn built_items_have_no_cbor_spans() {
    let item = Item::array(vec![Item::int(1), Item::text("a")]);
    let r = print(&item, &PrintOptions::new());
    assert!(r.spans.iter().all(|(_, s)| s.cbor.is_none()));
    check_span_map(&item, None, &r).unwrap();
}

#[test]
fn innermost_at() {
    let r = print(&decode(&h(DOC)).unwrap(), &PrintOptions::new());
    assert_eq!(r.spans.innermost_at(0), Some(&Path::root()));
    assert_eq!(r.spans.innermost_at(5), Some(&Path::root()));
    assert_eq!(r.spans.innermost_at(7), Some(&p([Value(0), Index(0)])));
    assert_eq!(r.spans.innermost_at(8), Some(&p([Value(0)])));
    assert_eq!(r.spans.innermost_at(22), Some(&p([Value(1), TagContent])));
    assert_eq!(r.spans.innermost_at(28), None);
}

#[test]
fn span_maps_hold_for_many_documents_and_options() {
    let docs = [
        "[1, [2, 3], {4: [5, {6: 7}]}]",
        "{_ \"a\": [_ 1, 2], 1_1(2): h'00'_0}",
        "[(_ \"a\", \"b\"), (_ h'01'), ''_, \"\"_]",
        "{1: 1(1363896240), 2: 0(\"2013-03-21T20:04:00Z\"), 3: [1.5_3, NaN, float'7d00']}",
        "[cri'x', foo<<1, 2>>, 999(1)]",
        "{\"k\": 54([64, h'20010db8']), \"d\": 1(1363896240.5)}",
        "[]",
        "{}",
        "0",
        "\"\u{fc}\u{1F600}\\n\"",
    ];
    let ann = |path: &Path, _: &Item| (path.depth() % 2 == 1).then(|| format!("n{path}"));
    let option_sets = [
        PrintOptions::new(),
        PrintOptions::indented(2),
        PrintOptions {
            encoding_indicators: EncodingIndicators::Always,
            annotator: Some(&ann),
            ..PrintOptions::indented(3)
        },
        PrintOptions {
            dt_literals: true,
            ip_literals: true,
            ascii: true,
            ..PrintOptions::new()
        },
    ];
    for doc in docs {
        let bytes = enc(doc);
        let item = decode(&bytes).unwrap();
        for opts in &option_sets {
            let r = print(&item, opts);
            check_span_map(&item, Some(&bytes), &r)
                .unwrap_or_else(|e| panic!("{doc} with {opts:?}:\n{}\n{e}", r.text));
        }
    }
}

#[test]
fn deep_nesting_spans() {
    deep(|| {
        let edn = format!("{}0{}", "[".repeat(500), "]".repeat(500));
        let bytes = enc(&edn);
        let item = decode(&bytes).unwrap();
        let r = print(&item, &PrintOptions::indented(1));
        assert_eq!(r.spans.len(), 501);
        let leaf = Path(vec![Index(0); 500]);
        assert_eq!(r.spans.get(&leaf).unwrap().lines, 500..501);
    });
}

// ---------------------------------------------------------------- Path

#[test]
fn path_display_and_parse() {
    let path = p([
        Index(3),
        Key(1),
        Value(2),
        TagContent,
        Embedded(0),
        Chunk(4),
    ]);
    assert_eq!(path.to_string(), "3/k1/v2/t/e0/c4");
    assert_eq!(Path::from_str("3/k1/v2/t/e0/c4").unwrap(), path);
    assert_eq!(Path::root().to_string(), "");
    assert_eq!(Path::from_str("").unwrap(), Path::root());
    assert_eq!(p([Index(12)]).to_string(), "12");
    for bad in [
        "x",
        "k",
        "3//4",
        "-1",
        "/3",
        "3/",
        "e",
        "t1",
        "k1x",
        " 3",
        "99999999999999999999999",
    ] {
        assert!(Path::from_str(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn path_helpers() {
    let a = p([Index(1)]);
    let b = a.child(Key(0));
    assert_eq!(b, p([Index(1), Key(0)]));
    assert!(a.is_prefix_of(&b));
    assert!(Path::root().is_prefix_of(&a));
    assert!(!b.is_prefix_of(&a));
    assert_eq!(b.depth(), 2);
}

// ---------------------------------------------------------------- parse_with spans

fn parsed_slice<'t>(text: &'t str, parsed: &tokenator_edn::Parsed, path: &Path) -> &'t str {
    let span = parsed
        .spans
        .get(path)
        .unwrap_or_else(|| panic!("no entry for {path}"));
    assert!(span.cbor.is_none());
    &text[span.text.clone()]
}

#[test]
fn source_spans() {
    let text = "[1, /c/ {\"a\": h'00'}]";
    let parsed = parse_with(text, &ParseOptions::default()).unwrap();
    assert_eq!(parsed_slice(text, &parsed, &Path::root()), text);
    assert_eq!(parsed_slice(text, &parsed, &p([Index(0)])), "1");
    assert_eq!(
        parsed_slice(text, &parsed, &p([Index(1)])),
        "{\"a\": h'00'}"
    );
    assert_eq!(parsed_slice(text, &parsed, &p([Index(1), Key(0)])), "\"a\"");
    assert_eq!(
        parsed_slice(text, &parsed, &p([Index(1), Value(0)])),
        "h'00'"
    );
    assert_eq!(parsed.spans.len(), 5);
}

#[test]
fn source_spans_exclude_surrounding_comments() {
    let text = "/c/ 1_0 # c";
    let parsed = parse_with(text, &ParseOptions::default()).unwrap();
    assert_eq!(parsed.spans.get(&Path::root()).unwrap().text, 4..7);
}

#[test]
fn source_spans_of_sequences() {
    let text = "1\n[2]";
    let opts = ParseOptions {
        sequence: true,
        ..ParseOptions::default()
    };
    let parsed = parse_with(text, &opts).unwrap();
    assert_eq!(parsed.items.len(), 2);
    let paths: Vec<_> = parsed.spans.iter().map(|(p, _)| p.to_string()).collect();
    assert_eq!(paths, ["0", "1", "1/0"]);
    assert_eq!(parsed.spans.get(&p([Index(1)])).unwrap().lines, 1..2);
    assert_eq!(parsed_slice(text, &parsed, &p([Index(1), Index(0)])), "2");
}

#[test]
fn source_spans_of_embedded_chunks_and_extensions() {
    let text = "[<<1, [2]>>, (_ \"a\", \"b\"), DT'2013-03-21T20:04:00Z']";
    let parsed = parse_with(text, &ParseOptions::default()).unwrap();
    assert_eq!(
        parsed_slice(text, &parsed, &p([Index(0), Embedded(1), Index(0)])),
        "2"
    );
    assert_eq!(
        parsed_slice(text, &parsed, &p([Index(0), Embedded(0)])),
        "1"
    );
    assert_eq!(
        parsed_slice(text, &parsed, &p([Index(1), Chunk(1)])),
        "\"b\""
    );
    let dt = "DT'2013-03-21T20:04:00Z'";
    assert_eq!(parsed_slice(text, &parsed, &p([Index(2)])), dt);
    assert_eq!(parsed_slice(text, &parsed, &p([Index(2), TagContent])), dt);
}

#[test]
fn source_spans_multiline() {
    let text = "{\r\n  1: [\r\n    2\r\n  ]\r\n}";
    let parsed = parse_with(text, &ParseOptions::default()).unwrap();
    assert_eq!(parsed.spans.get(&Path::root()).unwrap().lines, 0..5);
    assert_eq!(parsed.spans.get(&p([Value(0)])).unwrap().lines, 1..4);
    assert_eq!(
        parsed.spans.get(&p([Value(0), Index(0)])).unwrap().lines,
        2..3
    );
}
