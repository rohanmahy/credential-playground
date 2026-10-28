//! Keys: JWK, JWK Set, COSE_Key, COSE_KeySet, PEM.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_detect::{Kind, Layer};

fn pem(labels: &[&str]) -> Kind {
    Kind::Pem {
        labels: labels.iter().map(|s| (*s).to_owned()).collect(),
    }
}

// ------------------------------------------------------------------ JWK / JWK Set

#[test]
fn rfc9901_a5_public_jwk() {
    let input = key("rfc9901-a5-ec-p256-public.jwk.json");
    let c = top(&input);
    assert_eq!(c.kind, Kind::Jwk);
    assert_eq!(c.layers, vec![trim("", "\n")]);
}

#[test]
fn draft08_private_jwk() {
    assert_eq!(
        top(&key("sd-cwt-08-c1-holder-private.jwk.json")).kind,
        Kind::Jwk
    );
}

#[test]
fn rfc7517_jwk_sets() {
    for name in [
        "rfc7517-a1-public.jwks.json",
        "rfc7517-a2-private.jwks.json",
        "rfc7517-a3-symmetric.jwks.json",
    ] {
        assert_eq!(top(&key(name)).kind, Kind::JwkSet, "{name}");
    }
}

#[test]
fn minimal_jwks() {
    assert_eq!(
        top(br#"{"keys":[{"kty":"oct","k":"AAAA"}]}"#).kind,
        Kind::JwkSet
    );
}

#[test]
fn empty_jwk_set() {
    let cands = run(br#"{"keys":[]}"#);
    expect_kind(&cands, &Kind::JwkSet);
}

#[test]
fn object_with_non_string_kty_is_not_a_jwk() {
    let cands = run(br#"{"kty":1,"x":"abc"}"#);
    assert!(find(&cands, &Kind::Jwk).is_none(), "{}", summary(&cands));
    expect_kind(&cands, &Kind::JsonClaims);
}

#[test]
fn keys_member_that_is_not_an_array_of_jwks_is_not_a_set() {
    for input in [
        &br#"{"keys":"abc"}"#[..],
        br#"{"keys":[1,2]}"#,
        br#"{"keys":[{"a":1}]}"#,
    ] {
        let cands = run(input);
        assert!(find(&cands, &Kind::JwkSet).is_none(), "{}", summary(&cands));
    }
}

#[test]
fn jwk_as_base64url() {
    let raw = key_text("rfc9901-a5-ec-p256-public.jwk.json");
    let input = b64url(raw.as_bytes());
    let c = top(input.as_bytes());
    assert_eq!(c.kind, Kind::Jwk);
    assert_eq!(
        c.layers,
        vec![Layer::Base64Url {
            padded: false,
            wrap: None
        }]
    );
}

// ------------------------------------------------------------------ COSE_Key / COSE_KeySet

#[test]
fn rfc8392_a2_3_ec_cose_key() {
    let input = key("rfc8392-a2.3-ec-p256.cosekey.cbor");
    let c = top(&input);
    assert_eq!(c.kind, Kind::CoseKey);
    assert!(c.layers.is_empty());
    assert_eq!(c.payload_range, 0..input.len());
}

#[test]
fn draft08_holder_cose_key() {
    assert_eq!(
        top(&key("sd-cwt-08-c1-holder-private.cosekey.cbor")).kind,
        Kind::CoseKey
    );
}

#[test]
fn binary_cose_key_ending_in_newline_byte_is_not_trimmed() {
    let input = key("rfc8392-a2.1-symmetric128.cosekey.cbor");
    assert_eq!(*input.last().unwrap(), 0x0a);
    let c = top(&input);
    assert_eq!(c.kind, Kind::CoseKey);
    assert!(c.layers.is_empty(), "{c:?}");
    assert_eq!(c.payload_range, 0..input.len());
}

#[test]
fn rfc8152_c7_1_cose_key_set() {
    let input = key("rfc8152-c7.1-public.cosekeyset.cbor");
    let c = top(&input);
    assert_eq!(c.kind, Kind::CoseKeySet);
    assert!(c.layers.is_empty());
}

#[test]
fn cose_key_with_text_kty() {
    // kty may be a tstr in COSE.
    let input = cbor(&map(vec![(int(1), tstr("OKP")), (int(-1), int(6))]));
    let cands = run(&input);
    expect_kind(&cands, &Kind::CoseKey);
}

#[test]
fn array_of_non_keys_is_not_a_key_set() {
    let input = cbor(&arr(vec![map(vec![(tstr("a"), int(1))]), int(3)]));
    let cands = run(&input);
    assert!(
        find(&cands, &Kind::CoseKeySet).is_none(),
        "{}",
        summary(&cands)
    );
}

#[test]
fn cose_key_as_hex_text() {
    let raw = key("rfc8392-a2.3-ec-p256.cosekey.cbor");
    let input = hex(&raw);
    let c = top(input.as_bytes());
    assert_eq!(c.kind, Kind::CoseKey);
    assert_eq!(
        c.layers,
        vec![Layer::Hex {
            upper: false,
            separator: None,
            wrap: None
        }]
    );
}

// ------------------------------------------------------------------ PEM

#[test]
fn pem_public_keys() {
    for name in [
        "sd-cwt-08-c1-holder-public.pem",
        "rfc8410-s10.1-ed25519-public.pem",
    ] {
        let input = key(name);
        let c = top(&input);
        assert_eq!(c.kind, pem(&["PUBLIC KEY"]), "{name}");
        assert_eq!(c.layers, vec![trim("", "\n")]);
        assert_eq!(c.payload_range, 0..input.len() - 1);
    }
}

#[test]
fn pem_private_keys() {
    for name in [
        "sd-cwt-08-c1-holder-private.pem",
        "rfc8410-s10.3-ed25519-private.pem",
    ] {
        assert_eq!(top(&key(name)).kind, pem(&["PRIVATE KEY"]), "{name}");
    }
}

#[test]
fn pem_sec1_ec_private_key() {
    let c = top(&key("derived-sd-cwt-08-c1-holder-private.sec1.pem"));
    assert_eq!(c.kind, pem(&["EC PRIVATE KEY"]));
}

#[test]
fn pem_certificate() {
    let c = top(&key("rfc8410-s10.2-x25519-cert.pem"));
    assert_eq!(c.kind, pem(&["CERTIFICATE"]));
}

#[test]
fn pem_bundle_lists_every_label_in_order() {
    let mut input = key("rfc8410-s10.2-x25519-cert.pem");
    input.extend(key("rfc8410-s10.3-ed25519-private.pem"));
    input.extend(key("sd-cwt-08-c1-holder-public.pem"));
    let c = top(&input);
    assert_eq!(c.kind, pem(&["CERTIFICATE", "PRIVATE KEY", "PUBLIC KEY"]));
}

#[test]
fn pem_with_crlf_line_endings() {
    let text = key_text("sd-cwt-08-c1-holder-public.pem").replace('\n', "\r\n");
    assert_eq!(top(text.as_bytes()).kind, pem(&["PUBLIC KEY"]));
}

#[test]
fn pem_with_unknown_label_is_still_pem() {
    let text = "-----BEGIN ML-DSA-44 PRIVATE KEY-----\nAAAA\n-----END ML-DSA-44 PRIVATE KEY-----";
    assert_eq!(top(text.as_bytes()).kind, pem(&["ML-DSA-44 PRIVATE KEY"]));
}

#[test]
fn pem_with_mismatched_or_missing_end_is_not_pem() {
    for text in [
        "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PRIVATE KEY-----",
        "-----BEGIN PUBLIC KEY-----\nAAAA\n",
        "-----BEGIN PUBLIC KEY-----",
    ] {
        let cands = run(text.as_bytes());
        assert!(
            !cands.iter().any(|c| matches!(c.kind, Kind::Pem { .. })),
            "{text}: {}",
            summary(&cands)
        );
    }
}

// ------------------------------------------------------------------ Kind::is_key

#[test]
fn is_key_routes_to_key_panel() {
    for k in [
        Kind::Jwk,
        Kind::JwkSet,
        Kind::CoseKey,
        Kind::CoseKeySet,
        pem(&["PUBLIC KEY"]),
    ] {
        assert!(k.is_key(), "{k:?}");
    }
    for k in [
        Kind::JwsCompact,
        Kind::Jwt,
        Kind::SdJwt { kb: false },
        Kind::SdJwt { kb: true },
        Kind::JwsJson { general: true },
        Kind::SdJwtJson {
            general: false,
            kb: true,
        },
        Kind::CoseSign1,
        Kind::Cwt,
        Kind::SdCwt,
        Kind::SdKbt,
        Kind::JsonClaims,
        Kind::CborClaims,
        Kind::EdnText,
    ] {
        assert!(!k.is_key(), "{k:?}");
    }
}
