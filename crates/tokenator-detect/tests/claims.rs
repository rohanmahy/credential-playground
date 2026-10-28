//! Unsigned claim sets (JSON objects, CBOR maps) and possible EDN text.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_detect::Kind;

// ------------------------------------------------------------------ JSON

#[test]
fn rfc7519_claims_with_crlf_like_layout() {
    let input = token("rfc7519-s3.1-claims.json");
    let c = top(&input);
    assert_eq!(c.kind, Kind::JsonClaims);
    assert_eq!(c.layers, vec![trim("", "\n")]);
}

#[test]
fn rfc7519_claims_with_real_crlf() {
    // The exact JWS payload bytes of RFC 7519 §3.1 use CRLF between members.
    let input =
        b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
    let c = top(input);
    assert_eq!(c.kind, Kind::JsonClaims);
    assert!(c.layers.is_empty());
    assert_eq!(c.payload_range, 0..input.len());
}

#[test]
fn rfc9901_input_claims() {
    let c = top(&token("rfc9901-s5.1-input-claims.json"));
    assert_eq!(c.kind, Kind::JsonClaims);
}

#[test]
fn empty_object_is_a_claim_set() {
    assert_eq!(top(b"{}").kind, Kind::JsonClaims);
}

#[test]
fn claim_set_with_leading_whitespace_and_bom_free_utf8() {
    let input = "  \t{\"name\":\"Zoë\",\"emoji\":\"\u{1F600}\"}\n\n".as_bytes();
    let c = top(input);
    assert_eq!(c.kind, Kind::JsonClaims);
    assert_eq!(c.layers, vec![trim("  \t", "\n\n")]);
    assert_eq!(c.payload_range, 3..input.len() - 2);
}

#[test]
fn json_arrays_and_scalars_are_not_claim_sets() {
    for input in [
        &b"[]"[..],
        b"[1,2,3]",
        b"42",
        b"true",
        b"null",
        br#""just a string""#,
    ] {
        let cands = run(input);
        assert!(
            find(&cands, &Kind::JsonClaims).is_none(),
            "{:?}: {}",
            input,
            summary(&cands)
        );
    }
}

#[test]
fn invalid_json_object_is_not_json_claims() {
    for input in [&br#"{"a":1,}"#[..], br#"{"a" 1}"#, br#"{'a':1}"#, b"{"] {
        let cands = run(input);
        assert!(
            find(&cands, &Kind::JsonClaims).is_none(),
            "{:?}: {}",
            input,
            summary(&cands)
        );
    }
}

#[test]
fn duplicate_keys_are_still_a_claim_set() {
    // Duplicates are linted later, not rejected by detection.
    assert_eq!(top(br#"{"iss":"a","iss":"b"}"#).kind, Kind::JsonClaims);
}

// ------------------------------------------------------------------ CBOR

#[test]
fn rfc8392_a1_cbor_claims() {
    let input = token("rfc8392-a1-claims.cbor");
    let c = top(&input);
    assert_eq!(c.kind, Kind::CborClaims);
    assert!(c.layers.is_empty());
    assert_eq!(c.payload_range, 0..input.len());
}

#[test]
fn cbor_claims_as_hex_and_base64() {
    let raw = token("rfc8392-a1-claims.cbor");
    for text in [hex(&raw), b64url(&raw), b64std(&raw)] {
        let cands = run(text.as_bytes());
        expect_kind(&cands, &Kind::CborClaims);
        assert_eq!(
            cands[0].kind,
            Kind::CborClaims,
            "{text}: {}",
            summary(&cands)
        );
    }
}

#[test]
fn every_cbor_map_yields_cbor_claims() {
    for entries in [
        vec![],
        vec![(int(1), tstr("x"))],
        vec![(tstr("name"), tstr("value"))],
        vec![(int(-70000), bstr(&[1, 2, 3]))],
    ] {
        let input = cbor(&map(entries));
        let cands = run(&input);
        expect_kind(&cands, &Kind::CborClaims);
    }
}

#[test]
fn cbor_non_maps_are_not_claim_sets() {
    for input in [
        cbor(&arr(vec![int(1)])),
        cbor(&int(5)),
        cbor(&tstr("hello")),
    ] {
        let cands = run(&input);
        assert!(
            find(&cands, &Kind::CborClaims).is_none(),
            "{}",
            summary(&cands)
        );
    }
}

// ------------------------------------------------------------------ EDN

#[test]
fn draft08_figure4_edn_claims() {
    let input = token("sd-cwt-08-fig4-claims.edn");
    let c = top(&input);
    assert_eq!(c.kind, Kind::EdnText);
    assert_eq!(c.layers, vec![trim("", "\n")]);
    // EDN with comments and integer keys is not JSON.
    assert!(find(&run(&input), &Kind::JsonClaims).is_none());
}

#[test]
fn edn_snippets_are_possible_edn() {
    for text in [
        r#"{1: "https://issuer.example", 6: 1725244200}"#,
        "{/ iss / 1: \"x\"}",
        "18([h'a10126', {}, h'', h''])",
        "61(18([<< {1: -7} >>, {}, << {1: \"x\"} >>, h'00']))",
        "[1, 2, simple(59)]",
        "{_ \"a\": 1}",
        "h'a10126'",
        "{1: 2, # comment\n 3: 4}",
    ] {
        let cands = run(text.as_bytes());
        expect_kind(&cands, &Kind::EdnText);
        assert!(
            find(&cands, &Kind::JsonClaims).is_none(),
            "{text} is not JSON: {}",
            summary(&cands)
        );
    }
}

#[test]
fn edn_confidence_is_below_json_claims() {
    // JSON is valid EDN; the JSON reading must win.
    let input = br#"{"iss":"joe","exp":1300819380}"#;
    let cands = run(input);
    assert_eq!(cands[0].kind, Kind::JsonClaims);
    if let Some(e) = find(&cands, &Kind::EdnText) {
        assert!(e.confidence < cands[0].confidence, "{}", summary(&cands));
    }
}

#[test]
fn edn_is_never_certain() {
    let cands = run(&token("sd-cwt-08-fig4-claims.edn"));
    let e = expect_kind(&cands, &Kind::EdnText);
    assert!(e.confidence < 100);
    // ...and strictly below what a structurally certain JWT gets.
    let jwt = top(&token(JWT));
    assert!(e.confidence < jwt.confidence);
}

#[test]
fn prose_is_not_edn_or_claims() {
    for text in [
        "Lorem ipsum dolor sit amet.",
        "hello world",
        "The token is in the attachment.",
        "SELECT * FROM users;",
    ] {
        let cands = run(text.as_bytes());
        assert!(cands.is_empty(), "{text}: {}", summary(&cands));
    }
}
