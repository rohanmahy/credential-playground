//! The Engine is a pure function of its inputs: the same seeded flow run
//! twice gives byte-identical serialized DTOs (the WASM/native parity
//! contract, SPEC §11).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_core::{
    CnfChoice, DateTimeInput, DateTimeRequest, DiscloseRequest, DocRef, Engine, IssueRequest,
    KeyGenRequest, KeySeed, KeySpec, Kind, Nonce, PresentRequest, ReencodeRequest, SdOptions,
    TamperOp, TamperRequest, ValidateRequest, ViewOptions,
};

/// One full seeded flow; every DTO it produces, serialized, in order.
fn flow(e: &Engine) -> Vec<String> {
    let mut out = Vec::new();
    let mut gen_with = |spec, seed| {
        let k = e
            .key_generate(&KeyGenRequest {
                spec,
                role: None,
                seed: KeySeed::Entropy { bytes: seed },
                kid: None,
            })
            .unwrap();
        out.push(json(&k));
        k
    };
    let issuer = gen_with(KeySpec::P256, common::seed(1));
    let holder = gen_with(KeySpec::MlDsa44, common::seed(2));
    let cose_holder = gen_with(KeySpec::Ed25519, common::seed(3));

    for (claims, holder) in [
        (
            DocRef::new(Kind::JsonClaims, token("rfc9901-s5.1-input-claims.json")),
            &holder,
        ),
        (
            DocRef::new(
                Kind::EdnClaims,
                br#"{1: "https://issuer.example", 58(500): "x", 501: [58(1), 2]}"#.to_vec(),
            ),
            &cose_holder,
        ),
    ] {
        let jose = claims.kind == Kind::JsonClaims;
        let issued = e
            .issue(&IssueRequest {
                claims,
                issuer: issuer.key.clone(),
                alg: None,
                header: Default::default(),
                sd: SdOptions {
                    marks: if jose {
                        vec![
                            node_id("email"),
                            node_id("address"),
                            node_id("nationalities/0"),
                        ]
                    } else {
                        vec![]
                    },
                    ..SdOptions::default()
                },
                cnf: Some(CnfChoice::Key {
                    key: e.key_public(&holder.key).unwrap().key,
                }),
                jose_serialization: Default::default(),
                cose_tags: None,
                randomness: Some(common::seed(4)),
                view: ViewOptions::default(),
            })
            .unwrap();
        out.push(json(&issued));
        let disclosed = e
            .disclose(&DiscloseRequest {
                doc: DocRef::from(&issued),
                keep: vec![1, 0],
                view: ViewOptions::default(),
            })
            .unwrap();
        out.push(json(&disclosed));
        let nonce = if jose {
            Nonce::Text { value: "n".into() }
        } else {
            Nonce::Bytes {
                value: b"n".to_vec().into(),
            }
        };
        let presented = e
            .present(&PresentRequest {
                doc: DocRef::from(&issued),
                keep: vec![0],
                holder: holder.key.clone(),
                alg: None,
                aud: Some("https://verifier.example".into()),
                nonce: Some(nonce.clone()),
                iat: LATER,
                randomness: Some(common::seed(5)),
                view: ViewOptions::default(),
            })
            .unwrap();
        out.push(json(&presented));
        let mut v = ValidateRequest::new(DocRef::from(&presented), LATER + 1);
        v.keys = vec![issuer.key.clone()];
        v.expected_aud = Some("https://verifier.example".into());
        v.expected_nonce = Some(nonce);
        out.push(json(&e.validate(&v).unwrap()));
        let tampered = e
            .tamper(&TamperRequest {
                doc: DocRef::from(&presented),
                op: TamperOp::StripSignature,
                view: ViewOptions::default(),
            })
            .unwrap();
        out.push(json(&tampered));
        let reencoded = e
            .reencode(&ReencodeRequest {
                doc: DocRef::from(&issued),
                layers: vec![tokenator_core::Layer::Base64Url {
                    padded: false,
                    wrap: None,
                }],
                cose_tags: None,
                cbor: Default::default(),
                deep: false,
                jose: None,
                view: ViewOptions::default(),
            })
            .unwrap();
        out.push(json(&reencoded));
        out.push(json(&e.detect(&reencoded.output)));
    }
    out.push(json(
        &e.datetime(&DateTimeRequest {
            input: DateTimeInput::Epoch {
                text: "1700000000".into(),
            },
            now: Some(LATER),
            local_offset_minutes: 60,
        })
        .unwrap(),
    ));
    out
}

#[test]
fn the_same_seeded_flow_is_byte_identical() {
    let a = flow(&engine());
    let b = flow(&engine());
    assert_eq!(a.len(), b.len());
    for (i, (x, y)) in a.iter().zip(&b).enumerate() {
        assert_eq!(x, y, "step {i} differs");
    }
}

#[test]
fn opening_every_fixture_is_byte_identical() {
    let e1 = engine();
    let e2 = engine();
    for name in JOSE_FIXTURES.iter().chain(COSE_FIXTURES.iter()) {
        let a = json(&open_token(&e1, name));
        let b = json(&open_token(&e2, name));
        assert_eq!(a, b, "{name}");
    }
}

#[test]
fn different_randomness_gives_different_salts() {
    let e = engine();
    let issuer = e
        .key_generate(&KeyGenRequest {
            spec: KeySpec::P256,
            role: None,
            seed: KeySeed::WellKnown,
            kid: None,
        })
        .unwrap();
    let issue = |n| {
        e.issue(&IssueRequest {
            claims: DocRef::new(Kind::JsonClaims, token("rfc9901-s5.1-input-claims.json")),
            issuer: issuer.key.clone(),
            alg: None,
            header: Default::default(),
            sd: SdOptions {
                marks: vec![node_id("email")],
                ..SdOptions::default()
            },
            cnf: None,
            jose_serialization: Default::default(),
            cose_tags: None,
            randomness: Some(common::seed(n)),
            view: ViewOptions::default(),
        })
        .unwrap()
    };
    assert_ne!(issue(1).disclosures[0].salt, issue(2).disclosures[0].salt);
    assert_eq!(issue(1), issue(1));
}
