//! Nesting up to `MAX_DEPTH` fits in a 1 MiB stack (the WebAssembly
//! default) in release builds, and deeper input fails cleanly.
//!
//! `EDN_TEST_STACK=<bytes>` overrides the stack size, to measure the
//! minimum (about 165 KiB on aarch64 at the time of writing).

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use tokenator_cbor::{EncodeMode, Item, MAX_DEPTH, decode, encode};
use tokenator_edn::{
    EdnErrorKind, EmbeddedCbor, EncodingIndicators, HexOptions, ParseOptions, Path, PrintOptions,
    annotated_hex, parse, parse_with, print,
};

fn nested(open: &str, leaf: &str, close: &str, n: usize) -> String {
    format!("{}{leaf}{}", open.repeat(n), close.repeat(n))
}

fn deepest_cases() {
    let ann = |p: &Path, _: &Item| p.depth().is_multiple_of(100).then(|| "c".to_string());
    // Every byte string of the `<<` nesting below, listed explicitly (#15).
    let nested_bstrs: Vec<Path> = (0..MAX_DEPTH)
        .map(|k| Path(vec![tokenator_edn::PathSegment::Embedded(0); k]))
        .collect();
    let print_options = [
        PrintOptions::new(),
        PrintOptions {
            encoding_indicators: EncodingIndicators::Always,
            embedded_cbor: EmbeddedCbor::at(&nested_bstrs),
            annotator: Some(&ann),
            ..PrintOptions::indented(1)
        },
    ];
    for (open, close) in [
        ("[", "]"),
        ("{0: ", "}"),
        ("{", ": 0}"),
        ("1(", ")"),
        ("[_ ", "]"),
        ("<<", ">>"),
        ("h<<", ">>"),
    ] {
        let text = nested(open, "\"x\"", close, MAX_DEPTH);
        if open == "h<<" {
            // Fails in the innermost extension, after reaching full depth.
            let e = parse(&text).unwrap_err();
            assert!(matches!(e.kind, EdnErrorKind::Extension { .. }), "{e:?}");
            continue;
        }
        let item = parse(&text).unwrap_or_else(|e| panic!("{open}: {e:?}"));
        let bytes = encode(&item, EncodeMode::Preserve);
        let decoded = decode(&bytes).unwrap();
        for opts in &print_options {
            let rendered = print(&decoded, opts);
            let back = parse(&rendered.text).unwrap_or_else(|e| panic!("{open}: {e:?}"));
            assert_eq!(encode(&back, EncodeMode::Preserve), bytes, "{open}");
            let rows = annotated_hex(
                &decoded,
                &bytes,
                &HexOptions {
                    embedded_cbor: opts.embedded_cbor,
                    annotator: opts.annotator,
                },
            );
            assert!(!rows.rows.is_empty());
        }
        let parsed = parse_with(&text, &ParseOptions::default()).unwrap();
        assert!(parsed.spans.len() > MAX_DEPTH);
        let too_deep = nested(open, "0", close, MAX_DEPTH + 1);
        assert_eq!(
            parse(&too_deep).unwrap_err().kind,
            EdnErrorKind::DepthLimit,
            "{open}"
        );
    }
    // Unresolved extensions nest three levels per literal.
    let n = MAX_DEPTH / 3;
    let text = nested("foo<<", "1", ">>", n);
    let item = parse(&text).unwrap();
    let bytes = encode(&item, EncodeMode::Preserve);
    let rendered = print(&decode(&bytes).unwrap(), &PrintOptions::indented(2));
    assert_eq!(
        encode(&parse(&rendered.text).unwrap(), EncodeMode::Preserve),
        bytes
    );
    assert_eq!(
        parse(&nested("foo<<", "1", ">>", n + 1)).unwrap_err().kind,
        EdnErrorKind::DepthLimit
    );
    for open in ["[", "{", "1(", "<<", "(_ <<", "foo<<"] {
        let bomb = open.repeat(1_000_000);
        assert_eq!(parse(&bomb).unwrap_err().kind, EdnErrorKind::DepthLimit);
    }
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "stack use is only bounded in release builds"
)]
fn max_depth_fits_in_one_mib_of_stack() {
    let size = std::env::var("EDN_TEST_STACK")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1 << 20);
    std::thread::Builder::new()
        .stack_size(size)
        .spawn(deepest_cases)
        .unwrap()
        .join()
        .unwrap();
}
