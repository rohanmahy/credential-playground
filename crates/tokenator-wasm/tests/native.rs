//! The binding layer, compiled natively: the same `TokenatorEngine`
//! methods the wasm module exports, called with the same JSON text. This
//! catches mapping mistakes (wrong method, wrong envelope, wrong error
//! code) without a wasm build; `app/src/test/wasm/` checks the real module.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use base64ct::{Base64UrlUnpadded, Encoding};
use parity::{Arg, Case, Golden, parity_dir, read_cases, read_expected, testdata, with_big_stack};
use serde_json::Value;
use tokenator_wasm::TokenatorEngine;

/// Calls the binding method named by the case, as JS would.
fn call(engine: &TokenatorEngine, case: &Case) -> String {
    let bytes = |i: usize| match &case.args[i] {
        Arg::Bytes(b) => Base64UrlUnpadded::decode_vec(b).unwrap(),
        other => panic!("arg {i}: {other:?}"),
    };
    let text = |i: usize| match &case.args[i] {
        Arg::Json(v) => serde_json::to_string(v).unwrap(),
        other => panic!("arg {i}: {other:?}"),
    };
    match case.method.as_str() {
        "info" => engine.info(),
        "detect" => engine.detect(&bytes(0)),
        "open" => engine.open(&bytes(0), &text(1), &text(2)),
        "render" => engine.render(&text(0)),
        "parse_edit" => engine.parse_edit(&text(0)),
        "issue" => engine.issue(&text(0)),
        "redact" => engine.redact(&text(0)),
        "disclose" => engine.disclose(&text(0)),
        "present" => engine.present(&text(0)),
        "validate" => engine.validate(&text(0)),
        "lint" => engine.lint(&text(0)),
        "resign" => engine.resign(&text(0)),
        "tamper" => engine.tamper(&text(0)),
        "reencode" => engine.reencode(&text(0)),
        "edit_disclosures" => engine.edit_disclosures(&text(0)),
        "decode_embedded" => engine.decode_embedded(&text(0)),
        "key_import" => engine.key_import(&text(0)),
        "key_export" => engine.key_export(&text(0)),
        "key_public" => engine.key_public(&text(0)),
        "key_generate" => engine.key_generate(&text(0)),
        "key_thumbprint" => engine.key_thumbprint(&text(0)),
        "key_assign_kid" => engine.key_assign_kid(&text(0)),
        "key_to_jwk" => engine.key_to_jwk(&text(0)),
        "key_to_cwk" => engine.key_to_cwk(&text(0)),
        "datetime" => engine.datetime(&text(0)),
        "registry_lookup" => engine.registry_lookup(&text(0)),
        "registry_merge" => engine.registry_merge(&text(0)),
        other => panic!("unknown method {other}"),
    }
}

fn bundled() -> TokenatorEngine {
    TokenatorEngine::create(None).unwrap()
}

fn err_code(envelope: &str) -> String {
    let v: Value = serde_json::from_str(envelope).unwrap();
    assert_eq!(v.as_object().unwrap().len(), 1, "{envelope}");
    v["err"]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("not an error: {envelope}"))
        .to_owned()
}

#[test]
fn every_parity_case_through_the_binding_matches_its_golden() {
    let failures = with_big_stack(|| {
        let engine = bundled();
        let expected = read_expected(&parity_dir()).unwrap();
        let mut failures = Vec::new();
        for (id, case) in read_cases(&parity_dir()).unwrap() {
            if Golden::of(&call(&engine, &case)) != expected[&id] {
                failures.push(id);
            }
        }
        failures
    })
    .unwrap();
    assert!(failures.is_empty(), "binding output differs: {failures:?}");
}

#[test]
fn the_envelope_is_compact_json_with_ok_or_err() {
    let engine = bundled();
    let info = engine.info();
    assert!(info.starts_with(r#"{"ok":{"version":"#), "{info}");
    assert!(
        !info.contains('\n') && !info.contains(": "),
        "not compact: {info}"
    );
    assert_eq!(engine.detect(b""), r#"{"ok":[]}"#);
    let err = engine.render(r#"{"doc":{"kind":{"type":"cwt"},"bytes":""}}"#);
    assert_eq!(err_code(&err), "parse");
    let v: Value = serde_json::from_str(&err).unwrap();
    assert!(v["err"]["message"].is_string());
    assert!(v["err"]["node_id"].is_null());
}

#[test]
fn malformed_request_json_is_invalid_input() {
    let engine = bundled();
    for (name, out) in [
        ("not json", engine.render("{not json")),
        ("empty", engine.issue("")),
        ("wrong shape", engine.validate("{}")),
        (
            "wrong type",
            engine.key_generate(r#"{"spec":"p256","seed":{"type":"well_known"}}"#),
        ),
        (
            "unknown tag",
            engine.tamper(r#"{"doc":{"kind":{"type":"jwt"},"bytes":""},"op":{"type":"nope"}}"#),
        ),
        ("bad base64url", engine.key_import(r#"{"bytes":"a+b/"}"#)),
        ("bad candidate", engine.open(b"x", "[]", "{}")),
        (
            "bad view",
            engine.open(b"x", r#"{"kind":{"type":"jwt"}}"#, "7"),
        ),
    ] {
        assert_eq!(err_code(&out), "invalid_input", "{name}: {out}");
    }
}

#[test]
fn parse_edit_and_lookups_answer_ok_for_well_formed_requests() {
    let engine = bundled();
    let out = engine.parse_edit(r#"{"kind":{"type":"json_claims"},"base":"","text":"{"}"#);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["ok"]["ok"], false, "{out}");
    let out = engine.registry_lookup(r#"{"name":"iss"}"#);
    assert!(out.starts_with(r#"{"ok":["#), "{out}");
}

#[test]
fn a_bad_snapshot_is_a_registry_error() {
    let err = TokenatorEngine::create(Some(b"not a snapshot"))
        .err()
        .expect("must fail");
    assert_eq!(err_code(&err), "registry");
}

#[test]
fn a_merged_snapshot_is_used_by_the_new_engine() {
    let xml = std::fs::read_to_string(testdata().join("iana/cwt.xml"))
        .unwrap()
        .replacen(
            "<updated>2026-07-20</updated>",
            "<updated>2027-01-02</updated>",
            1,
        );
    let req = serde_json::json!({
        "xml": Base64UrlUnpadded::encode_string(xml.as_bytes()),
        "which": "cwt",
    });
    let out = bundled().registry_merge(&req.to_string());
    let v: Value = serde_json::from_str(&out).unwrap();
    let snapshot = Base64UrlUnpadded::decode_vec(v["ok"]["snapshot"].as_str().unwrap()).unwrap();
    let merged = TokenatorEngine::create(Some(&snapshot)).unwrap();
    let info: Value = serde_json::from_str(&merged.info()).unwrap();
    assert_eq!(info["ok"]["registry_updated"]["cwt"], "2027-01-02");
    let bundled_info: Value = serde_json::from_str(&bundled().info()).unwrap();
    assert_ne!(bundled_info["ok"]["registry_updated"]["cwt"], "2027-01-02");
}
