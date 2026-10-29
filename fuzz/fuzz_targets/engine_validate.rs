//! Engine `validate` on arbitrary bytes claimed to be a given kind, without
//! going through detection: the first byte picks the kind.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tokenator_core::{DocRef, Engine, KeyRef, Kind, Nonce, ValidateRequest};

fn engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| Engine::new().unwrap())
}

/// The kinds `validate` accepts, indexed by the first input byte.
const KINDS: [Kind; 13] = [
    Kind::Jwt,
    Kind::JwsCompact,
    Kind::SdJwt { kb: false },
    Kind::SdJwt { kb: true },
    Kind::JwsJson { general: false },
    Kind::JwsJson { general: true },
    Kind::SdJwtJson {
        general: false,
        kb: true,
    },
    Kind::SdJwtJson {
        general: true,
        kb: true,
    },
    Kind::CoseSign1,
    Kind::Cwt,
    Kind::SdCwt,
    Kind::SdKbt,
    Kind::JsonClaims,
];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, bytes)) = data.split_first() else {
        return;
    };
    let kind = KINDS[usize::from(selector) % KINDS.len()].clone();
    let mut req = ValidateRequest::new(DocRef::new(kind, bytes.to_vec()), 1_800_000_000);
    req.keys = vec![KeyRef::new(
        &include_bytes!("../../testdata/keys/rfc8392-a2.3-ec-p256.cosekey.cbor")[..],
    )];
    req.expected_aud = Some("https://verifier.example".into());
    req.expected_nonce = Some(Nonce::Text { value: "n".into() });
    req.max_kb_age = Some(300);
    let _ = engine().validate(&req);
});
