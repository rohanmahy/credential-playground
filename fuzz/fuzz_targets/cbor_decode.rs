//! CBOR decode, then encode every decoded item in Preserve mode (which must
//! give back its bytes exactly) and in the two canonical modes (which must
//! decode again, to a fixed point).
#![no_main]

use libfuzzer_sys::fuzz_target;
use tokenator_cbor::{
    EncodeMode, decode, decode_seq, deterministic_findings, duplicate_keys, encode,
    preferred_plus_findings,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(item) = decode(data) {
        assert_eq!(encode(&item, EncodeMode::Preserve).unwrap(), data);
    }
    let Ok(items) = decode_seq(data) else {
        return;
    };
    for item in &items {
        let bytes = &data[item.span.start..item.span.end];
        assert_eq!(encode(item, EncodeMode::Preserve).unwrap(), bytes);
        let _ = preferred_plus_findings(item);
        let _ = deterministic_findings(item);
        let _ = duplicate_keys(item);
        let _ = item.clone().into_owned();
        for mode in [EncodeMode::PreferredPlus, EncodeMode::Deterministic] {
            // Canonical encoding may refuse (for example an unsortable map),
            // but what it produces must decode and be stable.
            let Ok(once) = encode(item, mode) else {
                continue;
            };
            let again = decode(&once).expect("canonical output decodes");
            assert_eq!(encode(&again, mode).unwrap(), once);
            let findings = match mode {
                EncodeMode::Deterministic => deterministic_findings(&again),
                _ => preferred_plus_findings(&again),
            };
            assert!(
                findings.is_empty(),
                "{mode:?} output has findings: {findings:?}"
            );
        }
    }
});
