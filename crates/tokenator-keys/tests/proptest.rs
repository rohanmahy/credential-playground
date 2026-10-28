//! Property tests: parsers never panic on arbitrary or mutated input, and
//! conversions are stable.

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use proptest::prelude::*;
use tokenator_cbor::{EncodeMode, Item};
use tokenator_keys::{
    CoseKey, HashAlg, Jwk, KeyFormat, Kid, PemEncoding, Visibility, cose_thumbprint, export,
    from_cwk, from_jwk, import, import_each, jwk_thumbprint, params_from_cwk, params_from_jwk,
};

const HINTS: [Option<KeyFormat>; 6] = [
    None,
    Some(KeyFormat::Jwk),
    Some(KeyFormat::JwkSet),
    Some(KeyFormat::CoseKey),
    Some(KeyFormat::CoseKeySet),
    Some(KeyFormat::Pem(PemEncoding::Auto)),
];

fn exercise(input: &[u8]) {
    for hint in HINTS {
        let _ = import(input, hint);
        let _ = import_each(input, hint);
    }
    if let Ok(jwk) = Jwk::parse(input) {
        let _ = from_jwk(&jwk);
        let _ = params_from_jwk(&jwk);
        let _ = jwk_thumbprint(&jwk, HashAlg::Sha256);
    }
    if let Ok(cwk) = CoseKey::decode(input) {
        let _ = from_cwk(&cwk);
        let _ = params_from_cwk(&cwk);
        let _ = cose_thumbprint(&cwk, HashAlg::Sha256);
    }
}

/// Small valid inputs of every format to mutate.
fn seeds() -> Vec<Vec<u8>> {
    vec![
        fixture("rfc8037/ed25519-private.json"),
        fixture("rfc7517/a2-private-set.json"),
        fixture("rfc9679/ec2-p256.cbor"),
        fixture("rfc8152/c7-1-public-keyset.cbor"),
        fixture("openssl/p256-sec1.pem"),
        fixture("openssl/ed25519-spki.pem"),
        fixture("openssl/rsa2048-pkcs1-pub.pem"),
        fixture("openssl/mldsa44-seed.pem"),
        fixture("rfc8410/ed25519-private-v2.pem"),
    ]
}

/// A JSON string literal (escaped by serde_json).
fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

fn json_scalar() -> impl Strategy<Value = String> {
    prop_oneof![
        "[A-Za-z0-9_-]{0,90}".prop_map(|s| json_str(&s)),
        any::<String>().prop_map(|s| json_str(&s)),
        any::<i64>().prop_map(|n| n.to_string()),
        Just("null".to_string()),
        Just("true".to_string()),
        Just("[]".to_string()),
        Just("{}".to_string()),
        Just("1.5e300".to_string()),
    ]
}

fn jwk_name() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("kty"),
        Just("crv"),
        Just("x"),
        Just("y"),
        Just("d"),
        Just("n"),
        Just("e"),
        Just("p"),
        Just("q"),
        Just("dp"),
        Just("dq"),
        Just("qi"),
        Just("pub"),
        Just("priv"),
        Just("alg"),
        Just("kid"),
        Just("use"),
        Just("key_ops"),
        Just("keys"),
        Just("x5c"),
    ]
    .prop_map(str::to_string)
}

fn jwk_value(name: String) -> BoxedStrategy<(String, String)> {
    let specific: BoxedStrategy<String> = match name.as_str() {
        "kty" => prop_oneof![
            Just("EC"),
            Just("OKP"),
            Just("RSA"),
            Just("AKP"),
            Just("oct")
        ]
        .prop_map(json_str)
        .boxed(),
        "crv" => prop_oneof![
            Just("P-256"),
            Just("P-384"),
            Just("P-521"),
            Just("Ed25519"),
            Just("X25519")
        ]
        .prop_map(json_str)
        .boxed(),
        "alg" => prop_oneof![
            Just("ES256"),
            Just("EdDSA"),
            Just("RS256"),
            Just("ML-DSA-44"),
            Just("ML-DSA-87")
        ]
        .prop_map(json_str)
        .boxed(),
        _ => proptest::collection::vec(any::<u8>(), 0..80)
            .prop_map(|b| json_str(&b64u(&b)))
            .boxed(),
    };
    prop_oneof![3 => specific, 1 => json_scalar()]
        .prop_map(move |v| (name.clone(), v))
        .boxed()
}

fn jwk_text() -> impl Strategy<Value = String> {
    proptest::collection::vec(jwk_name().prop_flat_map(jwk_value), 0..10).prop_map(|members| {
        let body: Vec<String> = members
            .iter()
            .map(|(k, v)| format!("{}:{v}", json_str(k)))
            .collect();
        format!("{{{}}}", body.join(","))
    })
}

fn cbor_value() -> impl Strategy<Value = Item<'static>> {
    prop_oneof![
        any::<i64>().prop_map(Item::int),
        (-10i64..10).prop_map(Item::int),
        proptest::collection::vec(any::<u8>(), 0..80).prop_map(Item::bytes),
        Just(Item::bytes(vec![0x11; 32])),
        Just(Item::bytes(vec![0; 1312])),
        "[a-z]{0,8}".prop_map(Item::text),
        Just(Item::array(vec![Item::int(1), Item::int(2)])),
        Just(Item::new(tokenator_cbor::Value::Bool(true))),
        Just(Item::new(tokenator_cbor::Value::Null)),
    ]
}

fn cose_bytes() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec((-9i64..6, cbor_value()), 0..10).prop_map(|entries| {
        let item = Item::map(
            entries
                .into_iter()
                .map(|(k, v)| (Item::int(k), v))
                .collect(),
        );
        tokenator_cbor::encode(&item, EncodeMode::Preserve).unwrap()
    })
}

const LABELS: [&str; 8] = [
    "PUBLIC KEY",
    "PRIVATE KEY",
    "EC PRIVATE KEY",
    "RSA PRIVATE KEY",
    "RSA PUBLIC KEY",
    "ENCRYPTED PRIVATE KEY",
    "EC PARAMETERS",
    "CERTIFICATE",
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn random_bytes_never_panic(input in proptest::collection::vec(any::<u8>(), 0..512)) {
        exercise(&input);
    }

    #[test]
    fn random_text_never_panics(input in "\\PC{0,300}") {
        exercise(input.as_bytes());
    }

    #[test]
    fn mutated_fixtures_never_panic(
        which in 0usize..9,
        flips in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
        cut in any::<prop::sample::Index>(),
        truncate in any::<bool>(),
    ) {
        let mut input = seeds().swap_remove(which);
        for (i, b) in flips {
            let idx = i.index(input.len());
            input[idx] ^= b;
        }
        if truncate {
            input.truncate(cut.index(input.len() + 1));
        }
        exercise(&input);
    }

    #[test]
    fn jwk_like_objects_never_panic(text in jwk_text()) {
        exercise(text.as_bytes());
        let set = format!(r#"{{"keys":[{text},{text}]}}"#);
        exercise(set.as_bytes());
    }

    #[test]
    fn cose_like_maps_never_panic(bytes in cose_bytes()) {
        exercise(&bytes);
        let mut set = vec![0x82];
        set.extend(&bytes);
        set.extend(&bytes);
        exercise(&set);
    }

    #[test]
    fn pem_with_random_der_never_panics(
        label in proptest::sample::select(LABELS.to_vec()),
        der in proptest::collection::vec(any::<u8>(), 0..300),
    ) {
        let text = pem_rfc7468::encode_string(label, pem_rfc7468::LineEnding::LF, &der).unwrap();
        exercise(text.as_bytes());
    }

    #[test]
    fn pem_with_mutated_der_never_panics(
        which in 0usize..4,
        flips in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..6),
    ) {
        let rel = ["openssl/p256-pkcs8.pem", "openssl/p384-sec1.pem", "openssl/rsa2048-pkcs1.pem", "rfc9881/ml-dsa-44-both.pem"][which];
        let original = fixture(rel);
        let (label, mut der) = pem_rfc7468::decode_vec(&original).unwrap();
        for (i, b) in flips {
            let idx = i.index(der.len());
            der[idx] ^= b;
        }
        let text = pem_rfc7468::encode_string(label, pem_rfc7468::LineEnding::LF, &der).unwrap();
        exercise(text.as_bytes());
    }

    #[test]
    fn kid_to_jose_string_is_reversible(bytes in proptest::collection::vec(any::<u8>(), 0..40)) {
        let s = Kid::Bytes(bytes.clone()).to_jose_string();
        match std::str::from_utf8(&bytes) {
            Ok(text) => prop_assert_eq!(s, text),
            Err(_) => prop_assert_eq!(unb64u(&s), bytes),
        }
    }

    #[test]
    fn seeded_keys_round_trip_through_every_format(seed in any::<[u8; 32]>(), which in 0usize..5) {
        let spec = [
            tokenator_crypto::KeySpec::P256,
            tokenator_crypto::KeySpec::P384,
            tokenator_crypto::KeySpec::P521,
            tokenator_crypto::KeySpec::Ed25519,
            tokenator_crypto::KeySpec::MlDsa(tokenator_crypto::MlDsaParams::MlDsa44),
        ][which];
        let key = tokenator_keys::generate(spec, None, Some(&seed), &mut rng(0)).unwrap();
        for fmt in [KeyFormat::Jwk, KeyFormat::CoseKey, KeyFormat::Pem(PemEncoding::Auto)] {
            let bytes = export(&key, fmt, Visibility::Private).unwrap();
            let back = import(&bytes, None).unwrap();
            prop_assert_eq!(back.len(), 1);
            prop_assert!(back[0].same_material(&key));
        }
    }
}
