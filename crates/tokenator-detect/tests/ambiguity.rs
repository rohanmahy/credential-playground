//! Ranking, and surfacing several readings of the same input.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_detect::{Kind, Layer};

#[test]
fn token_field_outranks_its_container() {
    let t = token_text(SD_JWT);
    let input = format!(r#"{{"credential":"{t}"}}"#);
    let cands = run(input.as_bytes());
    assert_eq!(cands[0].kind, Kind::SdJwt { kb: false });
    let container = find_with(&cands, &Kind::JsonClaims, &[])
        .unwrap_or_else(|| panic!("container JsonClaims missing: {}", summary(&cands)));
    assert!(container.confidence < cands[0].confidence);
}

#[test]
fn several_token_fields_are_all_offered_above_the_container() {
    let a = token_text(JWT);
    let b = token_text(SD_JWT_KB);
    let c = b64url(&token(CWT_TAG18));
    let input = format!(r#"{{"a":"{a}","b":"{b}","c":"{c}"}}"#);
    let cands = run(input.as_bytes());
    let ra = find_with(&cands, &Kind::Jwt, &[field(&["a"])]).expect("a");
    let rb = find_with(&cands, &Kind::SdJwt { kb: true }, &[field(&["b"])]).expect("b");
    let rc = cands
        .iter()
        .find(|x| x.kind == Kind::Cwt && x.layers.first() == Some(&field(&["c"])))
        .expect("c");
    let container = find_with(&cands, &Kind::JsonClaims, &[]).expect("container");
    for x in [ra, rb, rc] {
        assert!(x.confidence > container.confidence, "{}", summary(&cands));
    }
}

#[test]
fn every_json_object_yields_json_claims() {
    for name in [
        "rfc7515-a7-jws-json-flattened.json",
        "rfc9901-s8.3-sd-jwt-kb-json-general.json",
    ] {
        let cands = run(&token(name));
        expect_kind(&cands, &Kind::JsonClaims);
    }
    for name in [
        "rfc9901-a5-ec-p256-public.jwk.json",
        "rfc7517-a1-public.jwks.json",
    ] {
        let cands = run(&key(name));
        expect_kind(&cands, &Kind::JsonClaims);
    }
}

#[test]
fn jws_json_outranks_json_claims() {
    let cands = run(&token("rfc7515-a6-jws-json-general.json"));
    assert_outranks(&cands, &Kind::JwsJson { general: true }, &Kind::JsonClaims);
    let cands = run(&token("rfc9901-s8.2-sd-jwt-json-flattened.json"));
    assert_outranks(
        &cands,
        &Kind::SdJwtJson {
            general: false,
            kb: false,
        },
        &Kind::JsonClaims,
    );
}

#[test]
fn jwk_outranks_json_claims() {
    let cands = run(&key("rfc9901-a5-ec-p256-public.jwk.json"));
    assert_outranks(&cands, &Kind::Jwk, &Kind::JsonClaims);
    let cands = run(&key("rfc7517-a2-private.jwks.json"));
    assert_outranks(&cands, &Kind::JwkSet, &Kind::JsonClaims);
}

#[test]
fn cose_key_also_offered_as_cbor_claims() {
    // A CBOR map with label 1 could be a COSE_Key (kty) or claims (iss).
    for name in [
        "rfc8392-a2.3-ec-p256.cosekey.cbor",
        "rfc8392-a2.1-symmetric128.cosekey.cbor",
        "sd-cwt-08-c1-holder-private.cosekey.cbor",
    ] {
        let cands = run(&key(name));
        assert_outranks(&cands, &Kind::CoseKey, &Kind::CborClaims);
        expect_kind(&cands, &Kind::CborClaims);
    }
}

#[test]
fn real_cwt_claims_outrank_a_cose_key_reading() {
    let cands = run(&token("rfc8392-a1-claims.cbor"));
    assert_outranks(&cands, &Kind::CborClaims, &Kind::CoseKey);
}

#[test]
fn ambiguous_small_map_offers_both() {
    // {1: 4, 2: h'...'} reads as a symmetric COSE_Key (kty 4, kid) or claims.
    let input = cbor(&map(vec![(int(1), int(4)), (int(2), bstr(b"kid-1"))]));
    let cands = run(&input);
    expect_kind(&cands, &Kind::CoseKey);
    expect_kind(&cands, &Kind::CborClaims);
}

#[test]
fn cose_key_set_outranks_other_array_readings() {
    let cands = run(&key("rfc8152-c7.1-public.cosekeyset.cbor"));
    assert_eq!(cands[0].kind, Kind::CoseKeySet);
}

#[test]
fn hex_reading_outranks_base64_reading() {
    // Lower-case hex is also valid base64. The hex reading must win.
    let raw = key("rfc8392-a2.1-symmetric128.cosekey.cbor");
    let input = hex(&raw);
    let cands = run(input.as_bytes());
    let c = &cands[0];
    assert_eq!(c.kind, Kind::CoseKey);
    assert!(
        matches!(c.layers[0], Layer::Hex { .. }),
        "{}",
        summary(&cands)
    );
    for other in &cands {
        if matches!(
            other.layers.first(),
            Some(Layer::Base64Std { .. } | Layer::Base64Url { .. })
        ) {
            assert!(other.confidence < c.confidence, "{}", summary(&cands));
        }
    }
}

#[test]
fn text_that_is_both_hex_and_base64_of_classifiable_things() {
    // "a0" is hex for the empty CBOR map {} ; as base64 it is 1.5 bytes and
    // invalid. "a0a0" is hex for {} {} (two items, not one) and base64 for
    // 0x6b 0x46 0xb4 (not CBOR). Whatever readings exist, they are ranked and
    // well-formed.
    for input in ["a0", "a0a0", "A0", "a1a1"] {
        run(input.as_bytes());
    }
    let cands = run(b"a0");
    let c = expect_kind(&cands, &Kind::CborClaims);
    assert!(
        matches!(c.layers[..], [Layer::Hex { .. }]),
        "{}",
        summary(&cands)
    );
}

#[test]
fn sign1_family_ranking() {
    let kbt = run(&token(SD_KBT));
    let sdcwt = run(&token(SD_CWT));
    let cwt = run(&token(CWT_TAG18));
    assert_eq!(kbt[0].kind, Kind::SdKbt);
    assert_eq!(sdcwt[0].kind, Kind::SdCwt);
    assert_eq!(cwt[0].kind, Kind::Cwt);
}

#[test]
fn json_outranks_edn_for_json_text() {
    let cands = run(&token("rfc9901-s5.1-input-claims.json"));
    assert_eq!(cands[0].kind, Kind::JsonClaims);
    if let Some(e) = find(&cands, &Kind::EdnText) {
        assert!(e.confidence < cands[0].confidence);
    }
}

#[test]
fn edn_is_ranked_below_structural_kinds_for_any_jose_json() {
    for name in [
        "rfc7515-a6-jws-json-general.json",
        "rfc9901-s8.2-sd-jwt-kb-json-flattened.json",
    ] {
        let cands = run(&token(name));
        let r_edn = rank(&cands, &Kind::EdnText);
        if let Some(r) = r_edn {
            assert!(r > 0, "{name}: {}", summary(&cands));
        }
    }
}

#[test]
fn candidates_are_unique() {
    for input in [
        token(JWT),
        token(SD_JWT_KB),
        token(SD_KBT),
        key("rfc8392-a2.3-ec-p256.cosekey.cbor"),
        format!(r#"{{"a":"{}","b":"{}"}}"#, token_text(JWT), token_text(JWT)).into_bytes(),
    ] {
        let cands = run(&input);
        for (i, a) in cands.iter().enumerate() {
            for b in &cands[i + 1..] {
                assert!(
                    !(a.kind == b.kind && a.layers == b.layers),
                    "duplicate candidate {a:?}"
                );
            }
        }
    }
}

#[test]
fn same_token_in_two_fields_yields_two_candidates() {
    let t = token_text(JWT);
    let input = format!(r#"{{"a":"{t}","b":"{t}"}}"#);
    let cands = run(input.as_bytes());
    assert!(
        find_with(&cands, &Kind::Jwt, &[field(&["a"])]).is_some(),
        "{}",
        summary(&cands)
    );
    assert!(
        find_with(&cands, &Kind::Jwt, &[field(&["b"])]).is_some(),
        "{}",
        summary(&cands)
    );
}

#[test]
fn ties_are_broken_deterministically_by_input_order() {
    // Two equally good fields: the first in the document ranks first.
    let t = token_text(JWT);
    let input = format!(r#"{{"first":"{t}","second":"{t}"}}"#);
    let cands = run(input.as_bytes());
    let a = cands
        .iter()
        .position(|c| c.layers == [field(&["first"])])
        .unwrap();
    let b = cands
        .iter()
        .position(|c| c.layers == [field(&["second"])])
        .unwrap();
    if cands[a].confidence == cands[b].confidence {
        assert!(a < b, "{}", summary(&cands));
    }
}
