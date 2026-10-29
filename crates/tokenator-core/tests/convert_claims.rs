//! `convert_claims`: claim sets between JSON and EDN (#44).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_core::{
    ConvertClaimsRequest, ConvertClaimsResult, Kind, Language, Severity, ViewOptions,
};

fn convert(text: &str, from: Language, to: Language, map: bool) -> ConvertClaimsResult {
    engine().convert_claims(&ConvertClaimsRequest {
        text: text.into(),
        from,
        to,
        map_claim_labels: map,
        view: ViewOptions::default(),
    })
}

fn to_edn(text: &str, map: bool) -> String {
    let r = convert(text, Language::Json, Language::Edn, map);
    assert!(r.ok, "{:?}", r.diagnostics);
    assert_eq!(r.document.as_ref().unwrap().kind, Kind::EdnClaims);
    r.text.unwrap()
}

fn to_json(text: &str, map: bool) -> serde_json::Value {
    let r = convert(text, Language::Edn, Language::Json, map);
    assert!(r.ok, "{text}: {:?}", r.diagnostics);
    assert_eq!(r.document.as_ref().unwrap().kind, Kind::JsonClaims);
    serde_json::from_str(r.text.as_deref().unwrap()).unwrap()
}

/// The CBOR an EDN text encodes, as hex.
fn cbor_hex(text: &str) -> String {
    hex::encode(edn(text))
}

#[test]
fn json_to_edn_keeps_order_and_maps_registered_claims() {
    let json = r#"{"sub": "alice", "iss": "https://issuer.example", "x-custom": [true, null], "exp": 1893456000}"#;
    let mapped = to_edn(json, true);
    assert_eq!(
        cbor_hex(&mapped),
        cbor_hex(
            r#"{2: "alice", 1: "https://issuer.example", "x-custom": [true, null], 4: 1893456000}"#
        ),
        "{mapped}"
    );
    assert!(mapped.contains("/ iss /"), "registry comments: {mapped}");
    let plain = to_edn(json, false);
    assert_eq!(
        cbor_hex(&plain),
        cbor_hex(
            r#"{"sub": "alice", "iss": "https://issuer.example", "x-custom": [true, null], "exp": 1893456000}"#
        )
    );
    // Only the top level is mapped; duplicates are kept.
    assert_eq!(
        cbor_hex(&to_edn(r#"{"a": {"iss": 1}, "a": 2}"#, true)),
        cbor_hex(r#"{"a": {"iss": 1}, "a": 2}"#)
    );
}

#[test]
fn json_numbers_become_ints_when_they_fit_else_floats() {
    let cases = [
        ("0", "0"),
        ("-0", "0"),
        ("-1", "-1"),
        ("18446744073709551615", "18446744073709551615"),
        ("-18446744073709551616", "-18446744073709551616"),
        ("18446744073709551616", "18446744073709551616.0"),
        ("1.5", "1.5"),
        ("1.0", "1.0"),
        ("1e2", "100.0"),
        ("1e400", "Infinity"),
    ];
    for (json, edn) in cases {
        let got = to_edn(&format!(r#"{{"n": {json}}}"#), false);
        assert_eq!(
            cbor_hex(&got),
            cbor_hex(&format!(r#"{{"n": {edn}}}"#)),
            "{json} → {got}"
        );
    }
}

#[test]
fn edn_to_json_maps_labels_back() {
    let v = to_json(
        r#"{1: "https://issuer.example", 4: 1893456000, "n": [1.5, 2.0, -3, false, null]}"#,
        true,
    );
    assert_eq!(
        v,
        serde_json::json!({"iss": "https://issuer.example", "exp": 1893456000, "n": [1.5, 2.0, -3, false, null]})
    );
    let text = convert("{\"x\": 2.0}", Language::Edn, Language::Json, false)
        .text
        .unwrap();
    assert!(text.contains("2.0"), "floats stay floats: {text}");
}

#[test]
fn round_trips_through_edn() {
    let json = token_text("rfc9901-s5.1-input-claims.json");
    let edn_text = to_edn(&json, true);
    let back = to_json(&edn_text, true);
    let original: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(back, original);
}

#[test]
fn edn_without_a_json_form_names_the_node() {
    let cases = [
        ("{1: h'00'}", true, "1"),
        (r#"{"a": [1, h'00']}"#, false, "\"a\"/1"),
        (r#"{"t": 1(0)}"#, false, "\"t\""),
        (r#"{"u": undefined}"#, false, "\"u\""),
        (r#"{"s": simple(16)}"#, false, "\"s\""),
        (r#"{"f": NaN}"#, false, "\"f\""),
        ("{1: \"x\"}", false, "1/~k"),
        ("{9999: \"x\"}", true, "9999/~k"),
        ("{simple(59): [h'00']}", false, "simple(59)/~k"),
        ("{\"a\": 1, 2: h'00'}", false, "2/~k"),
    ];
    for (text, map, id) in cases {
        let r = convert(text, Language::Edn, Language::Json, map);
        assert!(!r.ok && r.text.is_none() && r.document.is_none(), "{text}");
        let d = &r.diagnostics[0];
        assert_eq!(d.code, "convert.not_representable", "{text}");
        assert_eq!(d.severity, Severity::Error);
        assert_eq!(
            d.node_id.as_ref().map(|n| n.as_str()),
            Some(id),
            "{text}: {}",
            d.message
        );
        assert!(d.main.is_some(), "{text}: located in the EDN text");
    }
}

#[test]
fn too_deep_for_json() {
    let deep = format!("{{\"a\": {}1{}}}", "[".repeat(130), "]".repeat(130));
    let r = convert(&deep, Language::Edn, Language::Json, false);
    assert_eq!(r.diagnostics[0].code, "convert.not_representable");
}

#[test]
fn texts_that_do_not_parse_are_located() {
    let r = convert(r#"{"a": "#, Language::Json, Language::Edn, true);
    assert!(!r.ok);
    assert_eq!(r.diagnostics[0].code, "json.syntax");
    assert!(r.diagnostics[0].main.is_some());
    let r = convert("{1: zzz}", Language::Edn, Language::Json, true);
    assert_eq!(r.diagnostics[0].code, "edn.syntax");
    assert!(r.diagnostics[0].main.is_some());
}

#[test]
fn same_language_is_checked_and_kept() {
    let r = convert("{\"a\": 1}", Language::Json, Language::Json, true);
    assert!(r.ok);
    assert_eq!(r.text.as_deref(), Some("{\"a\": 1}"));
    let r = convert("{1: h'00'} / c /", Language::Edn, Language::Edn, true);
    assert!(r.ok);
    assert_eq!(r.text.as_deref(), Some("{1: h'00'} / c /"));
}

#[test]
fn conversion_is_deterministic() {
    let json = token_text("rfc9901-s5.1-input-claims.json");
    let a = convert(&json, Language::Json, Language::Edn, true);
    let b = convert(&json, Language::Json, Language::Edn, true);
    assert_eq!(json_of(&a), json_of(&b));
}

fn json_of(r: &ConvertClaimsResult) -> String {
    serde_json::to_string(r).unwrap()
}
