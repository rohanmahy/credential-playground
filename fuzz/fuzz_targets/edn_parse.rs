//! EDN parse (single item and sequence, lenient and strict), then
//! print → parse: the reparsed item must encode to the same bytes, in every
//! layout that keeps encoding indicators.
#![no_main]

use libfuzzer_sys::fuzz_target;
use tokenator_cbor::{EncodeMode, Item, encode};
use tokenator_edn::{
    EncodingIndicators, Extensions, ParseOptions, PrintOptions, parse, parse_with, print,
};

fn round_trip(item: &Item<'_>) {
    // simple(24..=31) parses but cannot be encoded; nothing to compare.
    let Ok(bytes) = encode(item, EncodeMode::Preserve) else {
        return;
    };
    for mut options in [PrintOptions::new(), PrintOptions::indented(2)] {
        for indicators in [EncodingIndicators::NonPreferred, EncodingIndicators::Always] {
            options.encoding_indicators = indicators;
            let text = print(item, &options).text;
            let again = parse(&text).unwrap_or_else(|e| panic!("reparse {text:?}: {e}"));
            assert_eq!(
                encode(&again, EncodeMode::Preserve).unwrap(),
                bytes,
                "{text}"
            );
        }
        options.encoding_indicators = EncodingIndicators::Never;
        let text = print(item, &options).text;
        parse(&text).unwrap_or_else(|e| panic!("reparse {text:?}: {e}"));
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(item) = parse(text) {
        round_trip(&item);
    }
    for (sequence, strict) in [(true, false), (false, true)] {
        let options = ParseOptions {
            extensions: Extensions::builtin(),
            sequence,
            strict,
            ..ParseOptions::default()
        };
        if let Ok(parsed) = parse_with(text, &options) {
            for item in &parsed.items {
                round_trip(item);
            }
        }
    }
});
