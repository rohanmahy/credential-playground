//! COSE parse and process: COSE_Sign1, CWT, SD-CWT, and SD-KBT. Every parsed
//! message has its headers read, its claims checked, its disclosures
//! matched, its signature checked against a fixed key, and is linted,
//! reassembled, and verified as an SD-KBT.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tokenator_cose::claims::{TimeOptions, check_times, claim, parse_cnf, resolve_cnf};
use tokenator_cose::kbt::{KbtOptions, verify_kbt};
use tokenator_cose::lint::{LintOptions, lint};
use tokenator_cose::sd::{SdCwt, match_disclosures};
use tokenator_cose::{
    CborBackend, Key, Label, Sign1Backend, Sign1Parts, VerifyOptions, codepoints,
};

/// The RFC 8392 A.2.3 P-256 key.
fn key() -> &'static Key {
    static KEY: OnceLock<Key> = OnceLock::new();
    KEY.get_or_init(|| {
        let cbor = include_bytes!("../../testdata/keys/rfc8392-a2.3-ec-p256.cosekey.cbor");
        tokenator_keys::import(cbor, None).unwrap().remove(0)
    })
}

fuzz_target!(|data: &[u8]| {
    let backend = CborBackend;
    let Ok(msg) = backend.parse(data) else {
        return;
    };
    let _ = msg.kind();
    let _ = msg.alg();
    let _ = msg.kid();
    let _ = msg.typ();
    let _ = msg.content_type();
    let _ = msg.crit();
    let _ = msg.header(codepoints::HDR_KCWT);
    let _ = backend.verify(&msg, key(), &VerifyOptions::default());
    if let Some(claims) = msg.payload_item() {
        let _ = check_times(
            claims,
            &TimeOptions {
                now: 1_800_000_000,
                skew: 60,
            },
        );
        if let Some(c) = claim(claims, &Label::Int(8)) {
            if let Ok(c) = parse_cnf(c) {
                let _ = resolve_cnf(&c, std::slice::from_ref(key()));
            }
        }
    }
    if let Ok(parts) = Sign1Parts::from_sign1(&msg) {
        if let Ok(bytes) = backend.assemble(&parts) {
            backend
                .parse(&bytes)
                .unwrap_or_else(|e| panic!("reassembled {bytes:02x?}: {e}"));
        }
    }

    let sd = SdCwt::from_sign1(msg);
    let _ = match_disclosures(&sd);
    let _ = lint(&backend, data, &LintOptions::default());
    let opts = KbtOptions {
        now: 1_800_000_000,
        skew: 60,
        holder_keys: vec![key().clone()],
        ..KbtOptions::default()
    };
    let _ = verify_kbt(&backend, data, Some(key()), &opts);
});
