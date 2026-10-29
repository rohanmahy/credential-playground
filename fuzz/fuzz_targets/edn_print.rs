//! CBOR → EDN → CBOR. The first byte picks the print options; the rest is
//! decoded as CBOR. With encoding indicators, the printed text must parse
//! back to exactly the input bytes; without them it must still parse.
#![no_main]

use libfuzzer_sys::fuzz_target;
use tokenator_cbor::{EncodeMode, decode, encode};
use tokenator_edn::{
    ByteStyle, EmbeddedCbor, EncodingIndicators, HexOptions, IndefiniteStringStyle, PrintOptions,
    annotated_hex, parse, print,
};

fuzz_target!(|data: &[u8]| {
    let Some((&flags, cbor)) = data.split_first() else {
        return;
    };
    let Ok(item) = decode(cbor) else {
        return;
    };
    let bit = |n: u8| flags & (1 << n) != 0;
    let mut options = if bit(0) {
        PrintOptions::indented(2)
    } else {
        PrintOptions::new()
    };
    options.encoding_indicators = match (flags >> 1) & 3 {
        0 | 1 => EncodingIndicators::NonPreferred,
        2 => EncodingIndicators::Always,
        _ => EncodingIndicators::Never,
    };
    options.bytes = if bit(3) {
        ByteStyle::Base64
    } else {
        ByteStyle::Hex
    };
    options.indefinite_strings = if bit(4) {
        IndefiniteStringStyle::Streamstring
    } else {
        IndefiniteStringStyle::AppExtension
    };
    options.ascii = bit(5);
    options.dt_literals = bit(6);
    options.ip_literals = bit(6);
    options.unresolved_as_prefixed = bit(7);
    options.embedded_cbor = if bit(7) {
        EmbeddedCbor::tagged()
    } else {
        EmbeddedCbor::OFF
    };

    let rendered = print(&item, &options);
    let again =
        parse(&rendered.text).unwrap_or_else(|e| panic!("reparse {:?}: {e}", rendered.text));
    if options.encoding_indicators != EncodingIndicators::Never {
        assert_eq!(
            encode(&again, EncodeMode::Preserve).unwrap(),
            cbor,
            "{}",
            rendered.text
        );
    }
    let hex = HexOptions {
        embedded_cbor: options.embedded_cbor,
        annotator: None,
    };
    let _ = annotated_hex(&item, cbor, &hex);
});
