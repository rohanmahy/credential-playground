//! Key import in every format. The first byte picks the format hint (or
//! detection); the rest is the key text or CBOR, also tried as an X.509
//! certificate. Every imported key is exported to every format that
//! applies, and each export must import again as the same key material.
#![no_main]

use libfuzzer_sys::fuzz_target;
use tokenator_keys::{
    HashAlg, Key, KeyFormat, PemEncoding, ThumbprintKind, Visibility, export, import_certificate,
    import_each, thumbprint, to_cwk, to_jwk, to_public,
};

fn exports(key: &Key) {
    let _ = thumbprint(key, ThumbprintKind::Jwk, HashAlg::Sha256);
    let _ = thumbprint(key, ThumbprintKind::Cose, HashAlg::Sha256);
    let _ = to_jwk(key, Visibility::Public);
    let _ = to_cwk(key, Visibility::Public);
    let public = to_public(key);
    let formats = [
        KeyFormat::Jwk,
        KeyFormat::JwkSet,
        KeyFormat::CoseKey,
        KeyFormat::CoseKeySet,
        KeyFormat::Pem(PemEncoding::Auto),
        KeyFormat::Pem(PemEncoding::Pkcs1),
        KeyFormat::Pem(PemEncoding::Sec1),
    ];
    for visibility in [Visibility::Public, Visibility::Private] {
        for format in formats {
            let Ok(bytes) = export(key, format, visibility) else {
                continue;
            };
            let back = import_each(&bytes, Some(format))
                .unwrap_or_else(|e| panic!("{format:?} {visibility:?} re-import: {e}"));
            let [Ok(back)] = &back[..] else {
                panic!("{format:?} {visibility:?} re-import: {back:?}");
            };
            let expected = match visibility {
                Visibility::Public => &public,
                Visibility::Private => key,
            };
            assert!(back.same_material(expected), "{format:?} {visibility:?}");
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&hint, input)) = data.split_first() else {
        return;
    };
    let hint = match hint % 4 {
        0 => None,
        1 => Some(KeyFormat::Jwk),
        2 => Some(KeyFormat::CoseKey),
        _ => Some(KeyFormat::Pem(PemEncoding::Auto)),
    };
    if let Ok(keys) = import_each(input, hint) {
        for key in keys.iter().flatten() {
            exports(key);
        }
    }
    if let Ok(key) = import_certificate(input) {
        exports(&key);
    }
});
