//! Every engine command delegates to the same-named `tokenator_core::Engine`
//! method: the IPC response is the exact JSON of the direct call, errors
//! are the core `EngineError` unchanged, and the argument keys are the core
//! parameter names in snake_case.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use common::*;
use serde_json::{Value, json};
use tokenator_core::*;

fn assert_same(h: &Harness, cmd: &str, args: Value, direct: Result<String, Value>) {
    assert_eq!(h.invoke(cmd, args), direct, "{cmd}");
}

/// A command taking `req`: compares the IPC result with the core call.
fn check_req<Req, Res>(
    h: &Harness,
    cmd: &str,
    req: &Req,
    call: impl FnOnce(&Engine, &Req) -> Result<Res, EngineError>,
) where
    Req: serde::Serialize,
    Res: serde::Serialize,
{
    let engine = Engine::new().unwrap();
    assert_same(
        h,
        cmd,
        json!({ "req": v(req) }),
        core_json(call(&engine, req)),
    );
}

#[test]
fn info() {
    let h = Harness::new();
    assert_same(
        &h,
        "engine_info",
        json!({}),
        core_json(Ok(Engine::new().unwrap().info())),
    );
}

#[test]
fn detect_takes_base64url_input() {
    let (h, fx) = (Harness::new(), Fx::new());
    let pasted = [b"Bearer ".as_slice(), &fx.jwt].concat();
    assert_same(
        &h,
        "engine_detect",
        json!({ "input": b64u(&pasted) }),
        core_json(Ok(fx.engine.detect(&pasted))),
    );
}

#[test]
fn detect_of_arbitrary_bytes() {
    let (h, fx) = (Harness::new(), Fx::new());
    let junk = [0xff, 0x00, 0xd8, 0x18, 0x41];
    assert_same(
        &h,
        "engine_detect",
        json!({ "input": b64u(&junk) }),
        core_json(Ok(fx.engine.detect(&junk))),
    );
}

#[test]
fn open_takes_input_candidate_view() {
    let (h, fx) = (Harness::new(), Fx::new());
    for bytes in [&fx.jwt, &fx.cwt] {
        for candidate in fx.engine.detect(bytes) {
            let view = ViewOptions::default();
            assert_same(
                &h,
                "engine_open",
                json!({ "input": b64u(bytes), "candidate": v(&candidate), "view": v(&view) }),
                core_json(fx.engine.open(bytes, &candidate, &view)),
            );
        }
    }
}

#[test]
fn open_error_is_the_core_engine_error() {
    let (h, fx) = (Harness::new(), Fx::new());
    // The JWT's candidate applied to CBOR bytes.
    let candidate = fx.engine.detect(&fx.jwt).remove(0);
    let view = ViewOptions::default();
    let direct = fx.engine.open(&fx.cwt, &candidate, &view);
    assert!(direct.is_err(), "fixture: expected an error");
    let got = h.call(
        "engine_open",
        json!({ "input": b64u(&fx.cwt), "candidate": v(&candidate), "view": v(&view) }),
    );
    let err = got.unwrap_err();
    assert_eq!(err, v(&direct.unwrap_err()));
    // The shape TauriEngine relies on.
    assert!(
        err["code"].is_string() && err["message"].is_string(),
        "{err}"
    );
    assert!(err.get("node_id").is_some(), "{err}");
}

#[test]
fn render() {
    let (h, fx) = (Harness::new(), Fx::new());
    let view = ViewOptions {
        indent: 4,
        ..ViewOptions::default()
    };
    let req = RenderRequest {
        doc: DocRef::from(&fx.cwt_doc),
        layers: Vec::new(),
        view,
    };
    check_req(&h, "engine_render", &req, |e, r| e.render(r));
}

#[test]
fn render_accepts_omitted_defaults() {
    // TS omits #[serde(default)] fields (app/ARCHITECTURE.md).
    let (h, fx) = (Harness::new(), Fx::new());
    let req = RenderRequest {
        doc: DocRef::from(&fx.jwt_doc),
        layers: Vec::new(),
        view: ViewOptions::default(),
    };
    let direct = core_json(fx.engine.render(&req));
    assert_same(
        &h,
        "engine_render",
        json!({ "req": { "doc": v(&DocRef::from(&fx.jwt_doc)) } }),
        direct,
    );
}

#[test]
fn parse_edit() {
    let (h, fx) = (Harness::new(), Fx::new());
    let text = fx.cwt_doc.main.text.replacen("1:", "1 :", 1);
    let req = EditRequest {
        kind: fx.cwt_doc.kind.clone(),
        base: fx.cwt_doc.bytes.clone(),
        text,
        view: ViewOptions::default(),
    };
    check_req(&h, "engine_parse_edit", &req, |e, r| Ok(e.parse_edit(r)));
    // A parse failure is a diagnostic in core, never an IPC error.
    let bad = EditRequest {
        text: "{1: ".into(),
        ..req
    };
    check_req(&h, "engine_parse_edit", &bad, |e, r| Ok(e.parse_edit(r)));
}

#[test]
fn issue_and_redact() {
    let (h, fx) = (Harness::new(), Fx::new());
    let req = Fx::issue_request(&fx.issuer, &fx.holder, &fx.engine);
    check_req(&h, "engine_issue", &req, |e, r| e.issue(r));
    check_req(&h, "engine_redact", &req, |e, r| e.redact(r));
}

#[test]
fn redact_error_nothing_to_redact() {
    let (h, fx) = (Harness::new(), Fx::new());
    let mut req = Fx::issue_request(&fx.issuer, &fx.holder, &fx.engine);
    req.claims = DocRef::new(Kind::EdnClaims, br#"{1: "x"}"#.to_vec());
    let got = h
        .call("engine_redact", json!({ "req": v(&req) }))
        .unwrap_err();
    assert_eq!(got, v(&fx.engine.redact(&req).unwrap_err()));
    assert_eq!(got["code"], "nothing_to_redact");
}

#[test]
fn disclose() {
    let (h, fx) = (Harness::new(), Fx::new());
    let req = DiscloseRequest {
        doc: DocRef::from(&fx.sd_jwt_doc),
        keep: vec![0, 2],
        view: ViewOptions::default(),
    };
    check_req(&h, "engine_disclose", &req, |e, r| e.disclose(r));
}

#[test]
fn present() {
    let (h, fx) = (Harness::new(), Fx::new());
    let req = PresentRequest {
        doc: DocRef::from(&fx.sd_cwt_doc),
        keep: vec![0],
        holder: fx.holder.key.clone(),
        alg: None,
        aud: Some("https://verifier.example".into()),
        nonce: Some(Nonce::Text {
            value: "n-1".into(),
        }),
        iat: 1_800_000_000,
        randomness: None,
        view: ViewOptions::default(),
    };
    check_req(&h, "engine_present", &req, |e, r| e.present(r));
}

#[test]
fn validate_and_lint() {
    let (h, fx) = (Harness::new(), Fx::new());
    let mut req = ValidateRequest::new(DocRef::from(&fx.jwt_doc), 1_300_819_000);
    req.keys = vec![fx.jwt_key.clone()];
    check_req(&h, "engine_validate", &req, |e, r| e.validate(r));
    let lint = LintRequest {
        doc: DocRef::from(&fx.cwt_doc),
        keys: Vec::new(),
    };
    check_req(&h, "engine_lint", &lint, |e, r| e.lint(r));
}

#[test]
fn resign_and_tamper() {
    let (h, fx) = (Harness::new(), Fx::new());
    let req = ResignRequest {
        doc: DocRef::from(&fx.jwt_doc),
        key: fx.issuer.key.clone(),
        alg: None,
        randomness: Some(Bytes(vec![9; 32])),
        view: ViewOptions::default(),
    };
    check_req(&h, "engine_resign", &req, |e, r| e.resign(r));
    let tamper = TamperRequest {
        doc: DocRef::from(&fx.cwt_doc),
        op: TamperOp::FlipBit {
            part: PartRef::Signature,
            bit: 0,
        },
        view: ViewOptions::default(),
    };
    check_req(&h, "engine_tamper", &tamper, |e, r| e.tamper(r));
}

#[test]
fn resign_without_private_key_is_an_engine_error() {
    let (h, fx) = (Harness::new(), Fx::new());
    let req = ResignRequest {
        doc: DocRef::from(&fx.jwt_doc),
        key: fx.jwt_key.clone(),
        alg: None,
        randomness: None,
        view: ViewOptions::default(),
    };
    let err = h
        .call("engine_resign", json!({ "req": v(&req) }))
        .unwrap_err();
    assert_eq!(err, v(&fx.engine.resign(&req).unwrap_err()));
}

#[test]
fn reencode() {
    let (h, fx) = (Harness::new(), Fx::new());
    let args = json!({ "req": { "doc": v(&DocRef::from(&fx.cwt_doc)), "cbor": "deterministic" } });
    let req: ReencodeRequest = serde_json::from_value(args["req"].clone()).unwrap();
    assert_same(
        &h,
        "engine_reencode",
        args,
        core_json(fx.engine.reencode(&req)),
    );
}

#[test]
fn edit_disclosures() {
    let (h, fx) = (Harness::new(), Fx::new());
    let req = EditDisclosuresRequest {
        doc: DocRef::from(&fx.sd_jwt_doc),
        ops: vec![
            DisclosureOp::Move { from: 0, to: 1 },
            DisclosureOp::Remove { index: 2 },
        ],
        randomness: Some(Bytes(vec![3; 32])),
        view: ViewOptions::default(),
    };
    check_req(&h, "engine_edit_disclosures", &req, |e, r| {
        e.edit_disclosures(r)
    });
}

#[test]
fn decode_embedded() {
    let (h, fx) = (Harness::new(), Fx::new());
    for node in ["signature", "protected", "no/such/node"] {
        let req = DecodeEmbeddedRequest {
            doc: DocRef::from(&fx.cwt_doc),
            node_id: serde_json::from_value(json!(node)).unwrap(),
            view: ViewOptions::default(),
        };
        check_req(&h, "engine_decode_embedded", &req, |e, r| {
            e.decode_embedded(r)
        });
    }
}

#[test]
fn key_commands() {
    let (h, fx) = (Harness::new(), Fx::new());
    let jwks = read_testdata("keys/rfc7517-a2-private.jwks.json");
    let import = KeyImportRequest {
        bytes: Bytes(jwks),
        format: None,
        candidate: None,
    };
    check_req(&h, "engine_key_import", &import, |e, r| e.key_import(r));

    let export = KeyExportRequest {
        key: fx.issuer.key.clone(),
        format: KeyFormat::CoseKey,
        visibility: Visibility::Private,
    };
    check_req(&h, "engine_key_export", &export, |e, r| e.key_export(r));

    let keygen = KeyGenRequest {
        spec: KeySpec::Ed25519,
        role: Some(Role::Holder),
        seed: KeySeed::WellKnown,
        kid: None,
    };
    check_req(&h, "engine_key_generate", &keygen, |e, r| e.key_generate(r));

    let thumb = ThumbprintRequest {
        key: fx.jwt_key.clone(),
        kind: ThumbprintKind::Cose,
        hash: HashName::Sha384,
    };
    check_req(&h, "engine_key_thumbprint", &thumb, |e, r| {
        e.key_thumbprint(r)
    });

    let kid = AssignKidRequest {
        key: fx.issuer.key.clone(),
        source: KidSource::JwkThumbprint {
            hash: HashName::Sha256,
        },
    };
    check_req(&h, "engine_key_assign_kid", &kid, |e, r| {
        e.key_assign_kid(r)
    });

    let convert = KeyConvertRequest {
        key: fx.issuer.key.clone(),
        visibility: Visibility::Public,
    };
    check_req(&h, "engine_key_to_jwk", &convert, |e, r| e.key_to_jwk(r));
    check_req(&h, "engine_key_to_cwk", &convert, |e, r| e.key_to_cwk(r));
}

#[test]
fn key_public_takes_key() {
    let (h, fx) = (Harness::new(), Fx::new());
    assert_same(
        &h,
        "engine_key_public",
        json!({ "key": v(&fx.issuer.key) }),
        core_json(fx.engine.key_public(&fx.issuer.key)),
    );
}

#[test]
fn key_import_error() {
    let (h, fx) = (Harness::new(), Fx::new());
    let req = KeyImportRequest {
        bytes: Bytes(b"not a key".to_vec()),
        format: None,
        candidate: None,
    };
    let err = h
        .call("engine_key_import", json!({ "req": v(&req) }))
        .unwrap_err();
    assert_eq!(err, v(&fx.engine.key_import(&req).unwrap_err()));
}

#[test]
fn datetime() {
    let h = Harness::new();
    let args = json!({ "req": { "input": { "type": "epoch", "text": "1800000000" }, "local_offset_minutes": 120 } });
    let req: DateTimeRequest = serde_json::from_value(args["req"].clone()).unwrap();
    assert_same(
        &h,
        "engine_datetime",
        args,
        core_json(Engine::new().unwrap().datetime(&req)),
    );
}

#[test]
fn registry_lookup_takes_query() {
    let h = Harness::new();
    let engine = Engine::new().unwrap();
    for query in [
        json!({ "kind": "cwt_claim", "label": 1 }),
        json!({ "kind": "jose_header", "prefix": "k" }),
        json!({}),
    ] {
        let q: RegistryQuery = serde_json::from_value(query.clone()).unwrap();
        assert_same(
            &h,
            "engine_registry_lookup",
            json!({ "query": query }),
            core_json(Ok(engine.registry_lookup(&q))),
        );
    }
}

#[test]
fn registry_merge() {
    let h = Harness::new();
    let req = RegistryMergeRequest {
        base_snapshot: None,
        xml: Bytes(read_testdata("iana/cose.xml")),
        which: RegistryId::Cose,
    };
    check_req(&h, "engine_registry_merge", &req, |e, r| {
        e.registry_merge(r)
    });
    let bad = RegistryMergeRequest {
        base_snapshot: None,
        xml: Bytes(b"<x/>".to_vec()),
        which: RegistryId::Jwt,
    };
    check_req(&h, "engine_registry_merge", &bad, |e, r| {
        e.registry_merge(r)
    });
}

// --- engine_init: the registry snapshot ---------------------------------

fn merged_snapshot() -> Vec<u8> {
    let engine = Engine::new().unwrap();
    // A registry with a changed record, so lookups tell the engines apart.
    let xml = String::from_utf8(read_testdata("iana/cwt.xml")).unwrap();
    let xml = xml.replacen("<claim>iss</claim>", "<claim>issuer-renamed</claim>", 1);
    assert!(
        xml.contains("issuer-renamed"),
        "fixture: cwt.xml has no <claim>iss</claim>"
    );
    let req = RegistryMergeRequest {
        base_snapshot: None,
        xml: Bytes(xml.into_bytes()),
        which: RegistryId::Cwt,
    };
    engine.registry_merge(&req).unwrap().snapshot.0
}

fn iss_lookup(h: &Harness) -> Value {
    h.call(
        "engine_registry_lookup",
        json!({ "query": { "kind": "cwt_claim", "label": 1 } }),
    )
    .unwrap()
}

#[test]
fn init_with_snapshot_replaces_the_engine() {
    let h = Harness::new();
    let snapshot = merged_snapshot();
    let refreshed = Engine::with_registry_snapshot(&snapshot).unwrap();
    assert_eq!(
        h.invoke("engine_init", json!({ "snapshot": b64u(&snapshot) })),
        Ok("null".into())
    );
    assert_eq!(
        h.invoke("engine_info", json!({})),
        core_json(Ok(refreshed.info()))
    );
    let q: RegistryQuery =
        serde_json::from_value(json!({ "kind": "cwt_claim", "label": 1 })).unwrap();
    assert_eq!(iss_lookup(&h), v(&refreshed.registry_lookup(&q)));
    assert_eq!(iss_lookup(&h)[0]["name"], "issuer-renamed");
}

#[test]
fn init_null_restores_the_bundled_registry() {
    let h = Harness::new();
    let bundled = iss_lookup(&h);
    h.invoke(
        "engine_init",
        json!({ "snapshot": b64u(&merged_snapshot()) }),
    )
    .unwrap();
    assert_ne!(iss_lookup(&h), bundled);
    h.invoke("engine_init", json!({ "snapshot": null }))
        .unwrap();
    assert_eq!(iss_lookup(&h), bundled);
}

#[test]
fn init_can_replace_the_snapshot_again() {
    // "Update registries" twice in one session.
    let h = Harness::new();
    let first = merged_snapshot();
    h.invoke("engine_init", json!({ "snapshot": b64u(&first) }))
        .unwrap();
    let engine = Engine::with_registry_snapshot(&first).unwrap();
    let req = RegistryMergeRequest {
        base_snapshot: Some(Bytes(first)),
        xml: Bytes(read_testdata("iana/cwt.xml")),
        which: RegistryId::Cwt,
    };
    let second = engine.registry_merge(&req).unwrap().snapshot.0;
    h.invoke("engine_init", json!({ "snapshot": b64u(&second) }))
        .unwrap();
    assert_eq!(iss_lookup(&h)[0]["name"], "iss");
}

#[test]
fn init_with_bad_snapshot_keeps_the_previous_engine() {
    let h = Harness::new();
    let good = merged_snapshot();
    h.invoke("engine_init", json!({ "snapshot": b64u(&good) }))
        .unwrap();
    let err = h
        .call("engine_init", json!({ "snapshot": b64u(b"{") }))
        .unwrap_err();
    assert_eq!(err, v(&Engine::with_registry_snapshot(b"{").unwrap_err()));
    assert_eq!(err["code"], "registry");
    assert_eq!(iss_lookup(&h)[0]["name"], "issuer-renamed");
}

// --- argument handling --------------------------------------------------

#[test]
fn camel_case_argument_keys_are_rejected() {
    // rename_all = "snake_case": `suggestedName`-style keys must not work,
    // so TS and Rust agree on one spelling.
    let (h, fx) = (Harness::new(), Fx::new());
    let candidate = fx.engine.detect(&fx.jwt).remove(0);
    // `engine_open` has only one-word keys; use a platform command with two words.
    let err = h
        .invoke("save_file", json!({ "suggestedName": "a.txt", "data": "" }))
        .unwrap_err();
    assert!(err.to_string().contains("suggested_name"), "{err}");
    // And the engine commands keep their single-word core names.
    let ok = h.invoke(
        "engine_open",
        json!({ "input": b64u(&fx.jwt), "candidate": v(&candidate), "view": v(&ViewOptions::default()) }),
    );
    assert!(ok.is_ok(), "{ok:?}");
}

#[test]
fn malformed_arguments_are_rejected_without_panicking() {
    let h = Harness::new();
    for (cmd, args) in [
        ("engine_detect", json!({})),
        ("engine_detect", json!({ "input": "not base64url!" })),
        ("engine_detect", json!({ "input": "0oQ=" })),
        (
            "engine_open",
            json!({ "input": "", "candidate": {}, "view": {} }),
        ),
        ("engine_issue", json!({ "req": { "claims": 1 } })),
        ("engine_key_public", json!({ "key": null })),
        ("engine_init", json!({ "snapshot": 7 })),
    ] {
        let err = h.invoke(cmd, args.clone()).unwrap_err();
        assert!(
            err.is_string(),
            "{cmd} {args}: Tauri reports bad args as a string, got {err}"
        );
    }
    // The app still works afterwards.
    assert!(h.invoke("engine_info", json!({})).is_ok());
}

#[test]
fn every_command_is_registered() {
    let h = Harness::new();
    for cmd in tokenator_desktop::COMMANDS {
        // Empty args: a registered command fails on its arguments (or
        // succeeds), never with "not found".
        if let Err(e) = h.invoke(cmd, json!({})) {
            assert!(!e.to_string().contains("not found"), "{cmd}: {e}");
        }
    }
    let err = h.invoke("engine_nope", json!({})).unwrap_err();
    assert!(err.to_string().contains("not found"), "{err}");
}
