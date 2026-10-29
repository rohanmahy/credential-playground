//! JSON parse, then print: Original must copy the root's source bytes
//! exactly, and Compact/Pretty output must parse again to a fixed point.
#![no_main]

use libfuzzer_sys::fuzz_target;
use tokenator_json::{
    InsertedLayout, ParseOptions, PrintOptions, PrintStyle, parse, parse_with_options, print_bytes,
};

fn options(style: PrintStyle) -> PrintOptions {
    PrintOptions {
        style,
        inserted: InsertedLayout::Compact,
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = parse_with_options(data, &ParseOptions { max_depth: 8 });
    let Ok(root) = parse(data) else {
        return;
    };
    let raw = root.raw_bytes().expect("a parsed root has source bytes");
    assert_eq!(print_bytes(&root, &options(PrintStyle::Original)), raw);
    assert!(root.is_original());

    for style in [PrintStyle::Compact, PrintStyle::Pretty] {
        let once = print_bytes(&root, &options(style));
        let again = parse(&once).unwrap_or_else(|e| {
            panic!(
                "reparse {style:?} {:?}: {e}",
                String::from_utf8_lossy(&once)
            )
        });
        assert_eq!(print_bytes(&again, &options(style)), once);
    }
    let _ = root.pointer("/a/0");
    let _ = root.get_all("");
});
