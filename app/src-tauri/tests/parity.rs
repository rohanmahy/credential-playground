//! Native/Tauri parity: the same Engine requests through the command layer
//! (IPC JSON) and through `tokenator-core` directly (`serde_json`) give
//! byte-identical JSON.
//!
//! The corpus is built here from `testdata/`. `feat/wasm` is adding
//! `testdata/parity/` goldens for the WASM side; once both land, this test
//! should read that corpus instead (see TEST-PLAN.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use common::*;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokenator_core::*;

/// One request as the webview sends it.
struct Case {
    name: String,
    cmd: &'static str,
    args: Value,
}

fn case(name: impl Into<String>, cmd: &'static str, args: Value) -> Case {
    Case {
        name: name.into(),
        cmd,
        args,
    }
}

fn arg<T: DeserializeOwned>(args: &Value, key: &str) -> T {
    serde_json::from_value(args[key].clone()).unwrap_or_else(|e| panic!("corpus arg {key}: {e}"))
}

/// The direct core call for an IPC request (the reference).
fn direct(engine: &Engine, cmd: &str, a: &Value) -> Result<String, Value> {
    let input = || arg::<Bytes>(a, "input").0;
    match cmd {
        "engine_info" => core_json(Ok(engine.info())),
        "engine_detect" => core_json(Ok(engine.detect(&input()))),
        "engine_open" => core_json(engine.open(&input(), &arg(a, "candidate"), &arg(a, "view"))),
        "engine_render" => core_json(engine.render(&arg(a, "req"))),
        "engine_parse_edit" => core_json(Ok(engine.parse_edit(&arg(a, "req")))),
        "engine_convert_claims" => core_json(Ok(engine.convert_claims(&arg(a, "req")))),
        "engine_issue" => core_json(engine.issue(&arg(a, "req"))),
        "engine_redact" => core_json(engine.redact(&arg(a, "req"))),
        "engine_disclose" => core_json(engine.disclose(&arg(a, "req"))),
        "engine_present" => core_json(engine.present(&arg(a, "req"))),
        "engine_validate" => core_json(engine.validate(&arg(a, "req"))),
        "engine_lint" => core_json(engine.lint(&arg(a, "req"))),
        "engine_resign" => core_json(engine.resign(&arg(a, "req"))),
        "engine_tamper" => core_json(engine.tamper(&arg(a, "req"))),
        "engine_reencode" => core_json(engine.reencode(&arg(a, "req"))),
        "engine_edit_disclosures" => core_json(engine.edit_disclosures(&arg(a, "req"))),
        "engine_decode_embedded" => core_json(engine.decode_embedded(&arg(a, "req"))),
        "engine_key_import" => core_json(engine.key_import(&arg(a, "req"))),
        "engine_key_export" => core_json(engine.key_export(&arg(a, "req"))),
        "engine_key_public" => core_json(engine.key_public(&arg(a, "key"))),
        "engine_key_generate" => core_json(engine.key_generate(&arg(a, "req"))),
        "engine_key_thumbprint" => core_json(engine.key_thumbprint(&arg(a, "req"))),
        "engine_key_assign_kid" => core_json(engine.key_assign_kid(&arg(a, "req"))),
        "engine_key_to_jwk" => core_json(engine.key_to_jwk(&arg(a, "req"))),
        "engine_key_to_cwk" => core_json(engine.key_to_cwk(&arg(a, "req"))),
        "engine_datetime" => core_json(engine.datetime(&arg(a, "req"))),
        "engine_registry_lookup" => core_json(Ok(engine.registry_lookup(&arg(a, "query")))),
        "engine_registry_merge" => core_json(engine.registry_merge(&arg(a, "req"))),
        other => panic!("no direct call for {other}"),
    }
}

fn token_files() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(testdata("tokens"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n != "README.md")
        .collect();
    names.sort();
    names
}

fn corpus(fx: &Fx) -> Vec<Case> {
    let e = &fx.engine;
    let mut cases = vec![case("info", "engine_info", json!({}))];

    // Every sample: detect, then open each candidate in two views.
    let compact = ViewOptions {
        layout: Layout::Compact,
        dt_literals: true,
        ..ViewOptions::default()
    };
    for name in token_files() {
        let bytes = read_testdata(&format!("tokens/{name}"));
        cases.push(case(
            format!("detect {name}"),
            "engine_detect",
            json!({ "input": b64u(&bytes) }),
        ));
        for (i, candidate) in e.detect(&bytes).iter().enumerate() {
            for (vname, view) in [
                ("default", ViewOptions::default()),
                ("compact", compact.clone()),
            ] {
                cases.push(case(
                    format!("open {name} #{i} {vname}"),
                    "engine_open",
                    json!({ "input": b64u(&bytes), "candidate": v(candidate), "view": v(&view) }),
                ));
            }
        }
    }

    // Seeded keys of every family.
    for (n, spec) in [
        json!({ "type": "p256" }),
        json!({ "type": "p384" }),
        json!({ "type": "p521" }),
        json!({ "type": "ed25519" }),
        json!({ "type": "rsa", "bits": 2048 }),
        json!({ "type": "ml_dsa44" }),
    ]
    .into_iter()
    .enumerate()
    {
        let seed = json!({ "type": "seed", "bytes": b64u(&[n as u8 + 10; 32]) });
        cases.push(case(
            format!("keygen {spec}"),
            "engine_key_generate",
            json!({ "req": { "spec": spec, "seed": seed } }),
        ));
    }

    // Issue → present → validate, JOSE and COSE.
    let issue = Fx::issue_request(&fx.issuer, &fx.holder, e);
    cases.push(case(
        "issue sd-cwt",
        "engine_issue",
        json!({ "req": v(&issue) }),
    ));
    let mut jose = issue.clone();
    jose.claims = DocRef::new(
        Kind::JsonClaims,
        br#"{"iss":"https://issuer.example","sub":"alice"}"#.to_vec(),
    );
    jose.sd = serde_json::from_value(json!({ "marks": ["sub"] })).unwrap();
    cases.push(case(
        "issue sd-jwt",
        "engine_issue",
        json!({ "req": v(&jose) }),
    ));
    cases.push(case(
        "redact sd-cwt",
        "engine_redact",
        json!({ "req": v(&issue) }),
    ));
    let present = json!({ "req": {
        "doc": v(&DocRef::from(&fx.sd_cwt_doc)), "keep": [0], "holder": v(&fx.holder.key),
        "aud": "https://verifier.example", "nonce": { "type": "text", "value": "n-1" }, "iat": 1_800_000_000
    } });
    cases.push(case("present sd-cwt", "engine_present", present.clone()));
    if let Ok(kbt) = e.present(&arg(&present, "req")) {
        let mut req = ValidateRequest::new(DocRef::from(&kbt), 1_800_000_010);
        req.keys = vec![e.key_public(&fx.issuer.key).unwrap().key];
        req.expected_aud = Some("https://verifier.example".into());
        cases.push(case(
            "validate sd-kbt",
            "engine_validate",
            json!({ "req": v(&req) }),
        ));
    }
    let mut validate = ValidateRequest::new(DocRef::from(&fx.jwt_doc), 1_300_819_000);
    validate.keys = vec![fx.jwt_key.clone()];
    cases.push(case(
        "validate jwt",
        "engine_validate",
        json!({ "req": v(&validate) }),
    ));
    cases.push(case(
        "validate jwt, no key",
        "engine_validate",
        json!({ "req": { "doc": v(&DocRef::from(&fx.jwt_doc)), "now": 0 } }),
    ));
    cases.push(case(
        "lint cwt",
        "engine_lint",
        json!({ "req": { "doc": v(&DocRef::from(&fx.cwt_doc)) } }),
    ));

    // Manipulation.
    let cwt = v(&DocRef::from(&fx.cwt_doc));
    let sd_jwt = v(&DocRef::from(&fx.sd_jwt_doc));
    cases.push(case(
        "render cwt",
        "engine_render",
        json!({ "req": { "doc": cwt.clone() } }),
    ));
    cases.push(case(
        "disclose",
        "engine_disclose",
        json!({ "req": { "doc": sd_jwt.clone(), "keep": [1] } }),
    ));
    cases.push(case("resign", "engine_resign", json!({ "req": { "doc": cwt.clone(), "key": v(&fx.issuer.key), "randomness": b64u(&[5; 32]) } })));
    cases.push(case(
        "tamper",
        "engine_tamper",
        json!({ "req": { "doc": cwt.clone(), "op": { "type": "remove_alg" } } }),
    ));
    for cbor in ["preserve", "preferred_plus", "deterministic"] {
        cases.push(case(
            format!("reencode {cbor}"),
            "engine_reencode",
            json!({ "req": { "doc": cwt.clone(), "cbor": cbor } }),
        ));
    }
    cases.push(case(
        "reencode jose json",
        "engine_reencode",
        json!({ "req": { "doc": v(&DocRef::from(&fx.jwt_doc)), "jose": "json_general" } }),
    ));
    cases.push(case(
        "edit disclosures",
        "engine_edit_disclosures",
        json!({ "req": { "doc": sd_jwt.clone(), "ops": [{ "type": "duplicate", "index": 0 }], "randomness": b64u(&[4; 32]) } }),
    ));
    cases.push(case(
        "decode embedded",
        "engine_decode_embedded",
        json!({ "req": { "doc": cwt.clone(), "node_id": "signature" } }),
    ));
    for (text, from, to) in [
        (
            r#"{"iss": "https://issuer.example", "exp": 1893456000, "n": 1.5}"#,
            "json",
            "edn",
        ),
        ("{1: \"x\", 4: 1893456000}", "edn", "json"),
        ("{1: h'00'}", "edn", "json"),
    ] {
        cases.push(case(
            format!("convert claims {from} to {to}: {text}"),
            "engine_convert_claims",
            json!({ "req": { "text": text, "from": from, "to": to, "map_claim_labels": true } }),
        ));
    }
    cases.push(case(
        "parse edit",
        "engine_parse_edit",
        json!({ "req": { "kind": v(&fx.cwt_doc.kind), "base": v(&fx.cwt_doc.bytes), "text": fx.cwt_doc.main.text.clone() } }),
    ));

    // Keys.
    for file in [
        "keys/rfc7517-a2-private.jwks.json",
        "keys/sd-cwt-08-c2-issuer-private.cosekey.cbor",
        "keys/rfc8410-s10.3-ed25519-private.pem",
    ] {
        cases.push(case(
            format!("import {file}"),
            "engine_key_import",
            json!({ "req": { "bytes": b64u(&read_testdata(file)) } }),
        ));
    }
    let key = v(&fx.issuer.key);
    cases.push(case(
        "key public",
        "engine_key_public",
        json!({ "key": key.clone() }),
    ));
    for format in [
        json!({ "type": "jwk" }),
        json!({ "type": "cose_key" }),
        json!({ "type": "pem", "encoding": "pkcs8" }),
    ] {
        cases.push(case(
            format!("export {format}"),
            "engine_key_export",
            json!({ "req": { "key": key.clone(), "format": format, "visibility": "private" } }),
        ));
    }
    cases.push(case(
        "thumbprint",
        "engine_key_thumbprint",
        json!({ "req": { "key": key.clone(), "kind": "jwk" } }),
    ));
    cases.push(case(
        "assign kid",
        "engine_key_assign_kid",
        json!({ "req": { "key": key.clone(), "source": { "type": "text", "value": "k1" } } }),
    ));
    cases.push(case(
        "to jwk",
        "engine_key_to_jwk",
        json!({ "req": { "key": key.clone(), "visibility": "public" } }),
    ));
    cases.push(case(
        "to cwk",
        "engine_key_to_cwk",
        json!({ "req": { "key": key.clone(), "visibility": "private" } }),
    ));

    // Date/time and registry.
    for input in [
        json!({ "type": "epoch", "text": "1800000000" }),
        json!({ "type": "rfc3339", "text": "2027-01-15T08:00:00+01:00" }),
        json!({ "type": "edn", "text": "1(1800000000)" }),
    ] {
        cases.push(case(
            format!("datetime {input}"),
            "engine_datetime",
            json!({ "req": { "input": input, "now": 1_800_000_000 } }),
        ));
    }
    cases.push(case(
        "lookup prefix",
        "engine_registry_lookup",
        json!({ "query": { "kind": "jwt_claim", "prefix": "a" } }),
    ));
    cases.push(case(
        "merge jose",
        "engine_registry_merge",
        json!({ "req": { "xml": b64u(&read_testdata("iana/jose.xml")), "which": "jose" } }),
    ));

    // Errors.
    cases.push(case(
        "error: bad key",
        "engine_key_import",
        json!({ "req": { "bytes": b64u(b"nope") } }),
    ));
    cases.push(case("error: tamper missing part", "engine_tamper", json!({ "req": { "doc": cwt, "op": { "type": "flip_bit", "part": { "type": "kb_signature" }, "bit": 0 } } })));
    cases.push(case(
        "error: datetime",
        "engine_datetime",
        json!({ "req": { "input": { "type": "rfc3339", "text": "yesterday" } } }),
    ));
    cases
}

#[test]
fn corpus_is_well_formed() {
    // Guards the corpus itself: every case deserializes for core, and both
    // successes and errors are represented.
    let fx = Fx::new();
    let cases = corpus(&fx);
    let results: Vec<_> = cases
        .iter()
        .map(|c| direct(&fx.engine, c.cmd, &c.args))
        .collect();
    assert!(cases.len() > 100, "{} cases", cases.len());
    assert!(results.iter().filter(|r| r.is_err()).count() >= 3);
    let cmds: std::collections::BTreeSet<_> = cases.iter().map(|c| c.cmd).collect();
    let engine_cmds: std::collections::BTreeSet<_> = tokenator_desktop::COMMANDS
        .iter()
        .copied()
        .filter(|c| c.starts_with("engine_") && *c != "engine_init")
        .collect();
    assert_eq!(cmds, engine_cmds, "the corpus covers every engine command");
}

#[test]
fn command_layer_matches_core_byte_for_byte() {
    let (h, fx) = (Harness::new(), Fx::new());
    let mut failures = Vec::new();
    for c in corpus(&fx) {
        let expected = direct(&fx.engine, c.cmd, &c.args);
        let got = h.invoke(c.cmd, c.args.clone());
        if got != expected {
            failures.push(c.name);
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches: {failures:#?}",
        failures.len()
    );
}

#[test]
fn repeated_requests_are_identical() {
    let (h, fx) = (Harness::new(), Fx::new());
    for c in corpus(&fx).into_iter().step_by(7) {
        assert_eq!(
            h.invoke(c.cmd, c.args.clone()),
            h.invoke(c.cmd, c.args.clone()),
            "{}",
            c.name
        );
    }
}
