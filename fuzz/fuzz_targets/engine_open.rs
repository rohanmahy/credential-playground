//! The Engine on arbitrary bytes, as the UI drives it: detect, open every
//! candidate, then validate and lint each opened document with a few keys.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tokenator_core::{
    DocRef, Engine, KeyRef, LintRequest, RenderRequest, ValidateRequest, ViewOptions,
};

fn engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| Engine::new().unwrap())
}

/// The RFC 7515 A.3 P-256 key and the RFC 8392 A.2.3 COSE_Key.
fn keys() -> Vec<KeyRef> {
    vec![
        KeyRef::new(
            &br#"{"kty":"EC","crv":"P-256",
                "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#[..],
        ),
        KeyRef::new(&include_bytes!("../../testdata/keys/rfc8392-a2.3-ec-p256.cosekey.cbor")[..]),
    ]
}

fuzz_target!(|data: &[u8]| {
    let engine = engine();
    let view = ViewOptions::default();
    for candidate in engine.detect(data).iter().take(8) {
        let Ok(doc) = engine.open(data, candidate, &view) else {
            continue;
        };
        let doc_ref = DocRef::from(&doc);
        let mut req = ValidateRequest::new(doc_ref.clone(), 1_800_000_000);
        req.keys = keys();
        let _ = engine.validate(&req);
        let _ = engine.lint(&LintRequest {
            doc: doc_ref.clone(),
            keys: Vec::new(),
        });
        let _ = engine.render(&RenderRequest {
            doc: doc_ref,
            layers: doc.layers.clone(),
            view: view.clone(),
        });
    }
});
