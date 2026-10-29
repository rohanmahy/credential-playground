//! Detection never panics, every candidate's layers replay on the input,
//! positional-only candidates point at their payload, and rewrap is the
//! inverse of unwrap for the payload found.
#![no_main]

use libfuzzer_sys::fuzz_target;
use tokenator_detect::{Layer, detect, json_pointer, rewrap, unwrap_layers};

fn positional(layer: &Layer) -> bool {
    matches!(
        layer,
        Layer::Trim { .. }
            | Layer::Quotes { .. }
            | Layer::AuthorizationHeader { .. }
            | Layer::BearerPrefix { .. }
            | Layer::CborTag(_)
    )
}

fuzz_target!(|data: &[u8]| {
    for candidate in detect(data) {
        let payload = unwrap_layers(data, &candidate.layers)
            .unwrap_or_else(|e| panic!("{candidate:?} does not unwrap: {e}"));
        assert!(candidate.payload_range.end <= data.len(), "{candidate:?}");
        if candidate.layers.iter().all(positional) {
            assert_eq!(
                &data[candidate.payload_range.clone()],
                &payload[..],
                "{candidate:?}"
            );
        }
        let wrapped = rewrap(&payload, &candidate.layers);
        let back = unwrap_layers(&wrapped, &candidate.layers)
            .unwrap_or_else(|e| panic!("{candidate:?} does not unwrap after rewrap: {e}"));
        assert_eq!(back, payload, "{candidate:?}");
        for layer in &candidate.layers {
            if let Layer::JsonField { path } = layer {
                let _ = json_pointer(path);
            }
        }
    }
});
