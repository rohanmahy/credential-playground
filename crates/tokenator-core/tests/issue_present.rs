//! issue / redact → disclose → present → validate round trips, JOSE and
//! COSE, with seeded keys and randomness.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_core::{
    Bytes, CnfChoice, DecoyRequest, DiscloseRequest, DisclosureStatus, DocRef, Document, Engine,
    ErrorCode, HashName, IssueRequest, JoseSerialization, KeyInfo, KeyRef, KeySelection, KeySpec,
    KidChoice, KidValue, Kind, Nonce, PresentRequest, SdOptions, Status, ValidateRequest,
    ViewOptions,
};

const S51_CLAIMS: &str = "rfc9901-s5.1-input-claims.json";
const AUD: &str = "https://verifier.example";
const NONCE: &str = "n-42";

fn json_claims(name: &str) -> DocRef {
    DocRef::new(Kind::JsonClaims, token(name))
}

fn edn_claims(text: &str) -> DocRef {
    DocRef::new(Kind::EdnClaims, text.as_bytes().to_vec())
}

fn request(claims: DocRef, issuer: &KeyInfo) -> IssueRequest {
    IssueRequest {
        claims,
        issuer: issuer.key.clone(),
        alg: None,
        header: Default::default(),
        sd: SdOptions::default(),
        cnf: None,
        jose_serialization: JoseSerialization::Compact,
        cose_tags: None,
        randomness: None,
        view: ViewOptions::default(),
    }
}

fn public(e: &Engine, k: &KeyInfo) -> KeyRef {
    e.key_public(&k.key).unwrap().key
}

fn present_req(doc: &Document, keep: Vec<u32>, holder: &KeyInfo, nonce: Nonce) -> PresentRequest {
    PresentRequest {
        doc: DocRef::from(doc),
        keep,
        holder: holder.key.clone(),
        alg: None,
        aud: Some(AUD.into()),
        nonce: Some(nonce),
        iat: LATER,
        randomness: None,
        view: ViewOptions::default(),
    }
}

fn verify_req(doc: &Document, keys: Vec<KeyRef>, nonce: Nonce) -> ValidateRequest {
    let mut req = ValidateRequest::new(DocRef::from(doc), LATER + 5);
    req.keys = keys;
    req.expected_aud = Some(AUD.into());
    req.expected_nonce = Some(nonce);
    req
}

fn text_nonce() -> Nonce {
    Nonce::Text {
        value: NONCE.into(),
    }
}

fn bytes_nonce() -> Nonce {
    Nonce::Bytes {
        value: Bytes(b"nonce-bytes".to_vec()),
    }
}

// ---------------------------------------------------------------- JOSE

#[test]
fn issue_plain_jwt_and_validate() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let doc = e.issue(&request(json_claims(S51_CLAIMS), &issuer)).unwrap();
    assert_eq!(doc.kind, Kind::Jwt);
    assert!(doc.signed && !doc.signature_stale);
    assert!(doc.layers.is_empty());
    assert!(doc.disclosures.is_empty());
    assert_eq!(main_text(&doc, "protected/~e/alg"), r#""ES256""#);
    let r = validate(&e, &doc, vec![public(&e, &issuer)], LATER);
    assert_status(&r, "signature", Status::Pass);
    assert_no_fail(&r);
}

#[test]
fn issue_every_algorithm_family() {
    let e = engine();
    let rsa = KeyInfo {
        key: key_ref("openssl/rsa2048-pkcs8.pem"),
        ..gen_key(&e, KeySpec::P256, 9)
    };
    let cases: Vec<(KeyInfo, &str)> = vec![
        (gen_key(&e, KeySpec::P256, 1), "ES256"),
        (gen_key(&e, KeySpec::P384, 1), "ES384"),
        (gen_key(&e, KeySpec::P521, 1), "ES512"),
        (gen_key(&e, KeySpec::Ed25519, 1), "Ed25519"),
        (gen_key(&e, KeySpec::Ed25519, 1), "EdDSA"),
        (gen_key(&e, KeySpec::MlDsa44, 1), "ML-DSA-44"),
        (gen_key(&e, KeySpec::MlDsa65, 1), "ML-DSA-65"),
        (gen_key(&e, KeySpec::MlDsa87, 1), "ML-DSA-87"),
        (rsa.clone(), "RS256"),
        (rsa, "PS256"),
    ];
    for (key, alg) in cases {
        for claims in [
            json_claims(S51_CLAIMS),
            edn_claims(r#"{1: "https://issuer.example", 2: "alice"}"#),
        ] {
            let mut req = request(claims, &key);
            req.alg = Some(alg.into());
            req.randomness = Some(seed(4)); // PSS needs it
            let doc = e.issue(&req).unwrap_or_else(|err| panic!("{alg}: {err}"));
            let r = validate(&e, &doc, vec![public(&e, &key)], LATER);
            assert_status(&r, "signature", Status::Pass);
        }
    }
}

#[test]
fn pss_without_randomness_is_refused() {
    let e = engine();
    let rsa = KeyInfo {
        key: key_ref("openssl/rsa2048-pkcs8.pem"),
        ..gen_key(&e, KeySpec::P256, 9)
    };
    let mut req = request(json_claims(S51_CLAIMS), &rsa);
    req.alg = Some("PS256".into());
    assert_eq!(e.issue(&req).unwrap_err().code, ErrorCode::Randomness);
}

#[test]
fn issue_errors() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);

    let mut req = request(json_claims(S51_CLAIMS), &issuer);
    req.issuer = public(&e, &issuer);
    assert_eq!(e.issue(&req).unwrap_err().code, ErrorCode::NoPrivateKey);

    let mut req = request(json_claims(S51_CLAIMS), &issuer);
    req.alg = Some("Ed25519".into());
    assert_eq!(e.issue(&req).unwrap_err().code, ErrorCode::UnsupportedAlg);

    let mut req = request(json_claims(S51_CLAIMS), &issuer);
    req.alg = Some("HS256".into());
    assert_eq!(e.issue(&req).unwrap_err().code, ErrorCode::UnsupportedAlg);

    let req = request(DocRef::new(Kind::JsonClaims, b"{\"a\": ".to_vec()), &issuer);
    assert_eq!(e.issue(&req).unwrap_err().code, ErrorCode::Parse);

    let jwt = token_text("rfc7515-a3-jws-es256.txt");
    let req = request(DocRef::new(Kind::Jwt, jwt.into_bytes()), &issuer);
    assert_eq!(e.issue(&req).unwrap_err().code, ErrorCode::UnsupportedKind);

    let mut req = request(json_claims(S51_CLAIMS), &issuer);
    req.issuer = KeyRef::new(b"garbage".to_vec());
    assert_eq!(e.issue(&req).unwrap_err().code, ErrorCode::Key);
}

#[test]
fn header_kid_choices_drive_key_selection() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let with_kid = e
        .key_assign_kid(&tokenator_core::AssignKidRequest {
            key: issuer.key.clone(),
            source: tokenator_core::KidSource::Text {
                value: "issuer-1".into(),
            },
        })
        .unwrap();

    // kid from the key → panel kid match.
    let mut req = request(json_claims(S51_CLAIMS), &with_kid);
    req.header.kid = KidChoice::FromKey;
    let doc = e.issue(&req).unwrap();
    assert_eq!(main_text(&doc, "protected/~e/kid"), r#""issuer-1""#);
    let r = validate(&e, &doc, vec![public(&e, &with_kid)], LATER);
    assert!(matches!(
        item(&r, "signature").detail,
        Some(tokenator_core::CheckDetail::Signature {
            selection: KeySelection::PanelKid,
            ..
        })
    ));

    // kid = the JWK thumbprint, key without kid → thumbprint match.
    let mut req = request(json_claims(S51_CLAIMS), &issuer);
    req.header.kid = KidChoice::Value {
        kid: KidValue::Text {
            value: issuer.jwk_thumbprint.clone(),
        },
    };
    let doc = e.issue(&req).unwrap();
    let r = validate(&e, &doc, vec![public(&e, &issuer)], LATER);
    assert!(matches!(
        item(&r, "signature").detail,
        Some(tokenator_core::CheckDetail::Signature {
            selection: KeySelection::PanelThumbprint,
            ..
        })
    ));
}

#[test]
fn header_typ_and_extra_members() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let mut req = request(json_claims(S51_CLAIMS), &issuer);
    req.header.typ = tokenator_core::TypChoice::Value {
        value: "example+sd-jwt".into(),
    };
    req.header.extra = Some(r#"{"x-test": [1, 2]}"#.into());
    let doc = e.issue(&req).unwrap();
    assert_eq!(main_text(&doc, "protected/~e/typ"), r#""example+sd-jwt""#);
    assert!(has_node(&doc, "protected/~e/x-test/1"));
}

#[test]
fn issue_sd_jwt_with_marks_decoys_and_cnf() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let holder = gen_key(&e, KeySpec::Ed25519, 2);
    let mut req = request(json_claims(S51_CLAIMS), &issuer);
    req.sd = SdOptions {
        marks: vec![
            node_id("given_name"),
            node_id("email"),
            node_id("address"),
            node_id("address/region"),
            node_id("nationalities/1"),
        ],
        decoys: vec![DecoyRequest {
            at: node_id(""),
            count: 2,
        }],
        sd_alg: Some(HashName::Sha384),
        ..SdOptions::default()
    };
    req.cnf = Some(CnfChoice::Key {
        key: public(&e, &holder),
    });
    req.randomness = Some(seed(3));
    let doc = e.issue(&req).unwrap();
    assert_eq!(doc.kind, Kind::SdJwt { kb: false });
    assert_eq!(doc.disclosures.len(), 5);
    assert_eq!(doc.undisclosed.len(), 2, "the two decoys");
    assert!(
        doc.disclosures
            .iter()
            .all(|d| d.status == DisclosureStatus::Matched)
    );
    assert_eq!(main_text(&doc, "payload/~e/_sd_alg"), r#""sha-384""#);
    assert!(has_node(&doc, "payload/~e/cnf/jwk/x"));
    assert!(!has_node(&doc, "payload/~e/given_name"));
    // Recursive: the region disclosure is inside the address disclosure.
    assert!(
        doc.disclosures
            .iter()
            .any(|d| d.claim.as_deref() == Some("region"))
    );
    assert!(
        doc.disclosures.iter().any(|d| d.claim.is_none()),
        "array element"
    );

    let r = validate(&e, &doc, vec![public(&e, &issuer)], LATER);
    assert_status(&r, "signature", Status::Pass);
    assert_status(&r, "sd.match", Status::Pass);
    assert_status(&r, "sd.sd_alg", Status::Pass);
}

#[test]
fn sd_needs_randomness_or_fixed_salts() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let mut req = request(json_claims(S51_CLAIMS), &issuer);
    req.sd.marks = vec![node_id("email")];
    assert_eq!(e.issue(&req).unwrap_err().code, ErrorCode::Randomness);

    req.sd.fixed_salts = vec!["eluV5Og3gSNII8EYnsxA_A".into()];
    let doc = e.issue(&req).unwrap();
    assert_eq!(doc.disclosures[0].salt, "eluV5Og3gSNII8EYnsxA_A");
    assert_eq!(e.issue(&req).unwrap(), doc, "fixed salts are deterministic");
}

#[test]
fn randomness_must_be_32_bytes() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let mut req = request(json_claims(S51_CLAIMS), &issuer);
    req.sd.marks = vec![node_id("email")];
    req.randomness = Some(Bytes(vec![1; 7]));
    assert_eq!(e.issue(&req).unwrap_err().code, ErrorCode::Randomness);
}

#[test]
fn unknown_mark_is_an_error() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let mut req = request(json_claims(S51_CLAIMS), &issuer);
    req.sd.marks = vec![node_id("no_such_claim")];
    req.randomness = Some(seed(3));
    let err = e.issue(&req).unwrap_err();
    assert_eq!(err.code, ErrorCode::NodeNotFound);
    assert_eq!(err.node_id, Some(node_id("no_such_claim")));
}

#[test]
fn redact_requires_marks() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let mut req = request(json_claims(S51_CLAIMS), &issuer);
    req.randomness = Some(seed(3));
    assert_eq!(e.redact(&req).unwrap_err().code, ErrorCode::NothingToRedact);
    req.sd.marks = vec![node_id("email")];
    let doc = e.redact(&req).unwrap();
    assert_eq!(doc.kind, Kind::SdJwt { kb: false });
    assert_eq!(doc.disclosures.len(), 1);
}

fn issued_sd_jwt(e: &Engine, issuer: &KeyInfo, holder: &KeyInfo) -> Document {
    let mut req = request(json_claims(S51_CLAIMS), issuer);
    req.sd.marks = vec![
        node_id("given_name"),
        node_id("family_name"),
        node_id("email"),
    ];
    req.cnf = Some(CnfChoice::Key {
        key: public(e, holder),
    });
    req.randomness = Some(seed(3));
    e.issue(&req).unwrap()
}

#[test]
fn disclose_keeps_a_subset() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let holder = gen_key(&e, KeySpec::Ed25519, 2);
    let doc = issued_sd_jwt(&e, &issuer, &holder);
    let kept = e
        .disclose(&DiscloseRequest {
            doc: DocRef::from(&doc),
            keep: vec![2, 0],
            view: ViewOptions::default(),
        })
        .unwrap();
    assert_eq!(kept.kind, Kind::SdJwt { kb: false });
    assert_eq!(kept.disclosures.len(), 2);
    assert_eq!(kept.disclosures[0].digest, doc.disclosures[2].digest);
    assert_eq!(kept.disclosures[1].digest, doc.disclosures[0].digest);
    assert_eq!(kept.undisclosed.len(), 1);
    let r = validate(&e, &kept, vec![public(&e, &issuer)], LATER);
    assert_status(&r, "signature", Status::Pass);
    assert_status(&r, "sd.match", Status::Pass);

    let err = e
        .disclose(&DiscloseRequest {
            doc: DocRef::from(&doc),
            keep: vec![7],
            view: ViewOptions::default(),
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::DisclosureIndex);
}

#[test]
fn present_sd_jwt_with_kb_and_validate() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let holder = gen_key(&e, KeySpec::Ed25519, 2);
    let doc = issued_sd_jwt(&e, &issuer, &holder);
    let presented = e
        .present(&present_req(&doc, vec![1], &holder, text_nonce()))
        .unwrap();
    assert_eq!(presented.kind, Kind::SdJwt { kb: true });
    assert_eq!(presented.disclosures.len(), 1);
    assert!(has_node(&presented, "kb/payload/~e/sd_hash"));
    assert_eq!(
        main_text(&presented, "kb/payload/~e/nonce"),
        format!("\"{NONCE}\"")
    );

    let r = e
        .validate(&verify_req(
            &presented,
            vec![public(&e, &issuer)],
            text_nonce(),
        ))
        .unwrap();
    for id in [
        "signature",
        "sd.match",
        "kb.signature",
        "kb.sd_hash",
        "kb.aud",
        "kb.nonce",
        "kb.iat",
    ] {
        assert_status(&r, id, Status::Pass);
    }
    assert_no_fail(&r);
}

#[test]
fn present_without_cnf_cannot_bind() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let holder = gen_key(&e, KeySpec::Ed25519, 2);
    let mut req = request(json_claims(S51_CLAIMS), &issuer);
    req.sd.marks = vec![node_id("email")];
    req.randomness = Some(seed(3));
    let doc = e.issue(&req).unwrap();
    let presented = e
        .present(&present_req(&doc, vec![0], &holder, text_nonce()))
        .unwrap();
    let r = e
        .validate(&verify_req(
            &presented,
            vec![public(&e, &issuer)],
            text_nonce(),
        ))
        .unwrap();
    assert_ne!(status(&r, "kb.signature"), Status::Pass);
}

#[test]
fn present_needs_a_private_holder_key() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let holder = gen_key(&e, KeySpec::Ed25519, 2);
    let doc = issued_sd_jwt(&e, &issuer, &holder);
    let mut req = present_req(&doc, vec![0], &holder, text_nonce());
    req.holder = public(&e, &holder);
    assert_eq!(e.present(&req).unwrap_err().code, ErrorCode::NoPrivateKey);
}

#[test]
fn jose_json_serializations_issue_and_present() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let holder = gen_key(&e, KeySpec::Ed25519, 2);
    for (ser, general) in [
        (JoseSerialization::JsonFlattened, false),
        (JoseSerialization::JsonGeneral, true),
    ] {
        let mut req = request(json_claims(S51_CLAIMS), &issuer);
        req.sd.marks = vec![node_id("email")];
        req.cnf = Some(CnfChoice::Key {
            key: public(&e, &holder),
        });
        req.randomness = Some(seed(3));
        req.jose_serialization = ser;
        let doc = e.issue(&req).unwrap();
        assert_eq!(doc.kind, Kind::SdJwtJson { general, kb: false });
        let presented = e
            .present(&present_req(&doc, vec![0], &holder, text_nonce()))
            .unwrap();
        assert_eq!(presented.kind, Kind::SdJwtJson { general, kb: true });
        let r = e
            .validate(&verify_req(
                &presented,
                vec![public(&e, &issuer)],
                text_nonce(),
            ))
            .unwrap();
        assert_status(&r, "kb.sd_hash", Status::Pass);
        assert_no_fail(&r);
    }
}

// ---------------------------------------------------------------- COSE

const CWT_EDN: &str = r#"{1: "https://issuer.example", 2: "alice", 6: 1700000000}"#;

#[test]
fn issue_cwt_from_edn() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let doc = e.issue(&request(edn_claims(CWT_EDN), &issuer)).unwrap();
    assert_eq!(doc.kind, Kind::Cwt);
    assert_eq!(doc.bytes[0], 0xd2, "tag 18 by default");
    assert!(has_node(&doc, "payload/~e/2"));
    assert!(doc.main.text.contains("/ sub /"));
    let r = validate(&e, &doc, vec![public(&e, &issuer)], LATER);
    assert_status(&r, "signature", Status::Pass);
    assert_status(&r, "time.iat", Status::Pass);
}

#[test]
fn issue_cwt_tags() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    for (tags, prefix) in [
        (vec![], vec![0x84]),
        (vec![61, 18], vec![0xd8, 0x3d, 0xd2, 0x84]),
        (vec![18], vec![0xd2, 0x84]),
    ] {
        let mut req = request(edn_claims(CWT_EDN), &issuer);
        req.cose_tags = Some(tags.clone());
        let doc = e.issue(&req).unwrap();
        assert!(doc.bytes.starts_with(&prefix), "{tags:?}");
        let r = validate(&e, &doc, vec![public(&e, &issuer)], LATER);
        assert_status(&r, "signature", Status::Pass);
    }
}

#[test]
fn issue_cwt_from_cbor_claims() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let claims = DocRef::new(Kind::CborClaims, token("rfc8392-a1-claims.cbor"));
    let doc = e.issue(&request(claims, &issuer)).unwrap();
    assert_eq!(doc.kind, Kind::Cwt);
    // The payload is the claims set byte for byte.
    let payload = raw_bytes(&doc, "payload/~e");
    assert_eq!(payload, &token("rfc8392-a1-claims.cbor")[..]);
    let r = validate(&e, &doc, vec![public(&e, &issuer)], RFC8392_NOW);
    assert_status(&r, "signature", Status::Pass);
    assert_status(&r, "time.exp", Status::Pass);
}

const SD_EDN: &str = r#"{
  1: "https://issuer.example",
  2: "https://holder.example",
  58(500): "secret",
  501: [58("a"), "b"],
  58(502): {58("x"): 1}
}"#;

fn issued_sd_cwt(e: &Engine, issuer: &KeyInfo, holder: &KeyInfo) -> Document {
    let mut req = request(edn_claims(SD_EDN), issuer);
    req.cnf = Some(CnfChoice::Key {
        key: public(e, holder),
    });
    req.randomness = Some(seed(5));
    e.issue(&req).unwrap()
}

#[test]
fn issue_sd_cwt_from_tagged_edn() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let holder = gen_key(&e, KeySpec::P256, 2);
    let doc = issued_sd_cwt(&e, &issuer, &holder);
    assert_eq!(doc.kind, Kind::SdCwt);
    assert!(doc.disclosures.len() >= 3);
    assert!(
        doc.disclosures
            .iter()
            .all(|d| d.status == DisclosureStatus::Matched)
    );
    assert!(has_node(&doc, "payload/~e/simple(59)"));
    assert!(has_node(&doc, "payload/~e/8/1"), "cnf COSE_Key");
    assert!(has_node(&doc, "unprotected/17/0/~e"));
    let r = validate(&e, &doc, vec![public(&e, &issuer)], LATER);
    assert_status(&r, "signature", Status::Pass);
    assert_status(&r, "sd.match", Status::Pass);
}

#[test]
fn redact_edn_requires_tags() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let mut req = request(edn_claims(CWT_EDN), &issuer);
    req.randomness = Some(seed(5));
    assert_eq!(e.redact(&req).unwrap_err().code, ErrorCode::NothingToRedact);
    let mut req = request(edn_claims(SD_EDN), &issuer);
    req.randomness = Some(seed(5));
    assert_eq!(e.redact(&req).unwrap().kind, Kind::SdCwt);
}

#[test]
fn disclose_sd_cwt() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let holder = gen_key(&e, KeySpec::P256, 2);
    let doc = issued_sd_cwt(&e, &issuer, &holder);
    let kept = e
        .disclose(&DiscloseRequest {
            doc: DocRef::from(&doc),
            keep: vec![0],
            view: ViewOptions::default(),
        })
        .unwrap();
    assert_eq!(kept.disclosures.len(), 1);
    assert!(!kept.undisclosed.is_empty());
    let r = validate(&e, &kept, vec![public(&e, &issuer)], LATER);
    assert_status(&r, "signature", Status::Pass);
}

#[test]
fn present_sd_cwt_in_an_sd_kbt() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let holder = gen_key(&e, KeySpec::P256, 2);
    let doc = issued_sd_cwt(&e, &issuer, &holder);
    let kbt = e
        .present(&present_req(&doc, vec![1], &holder, bytes_nonce()))
        .unwrap();
    assert_eq!(kbt.kind, Kind::SdKbt);
    assert_eq!(kbt.disclosures.len(), 1);
    assert!(has_node(&kbt, "protected/~e/13/payload/~e"));
    assert!(has_node(&kbt, "payload/~e/39"), "cnonce");
    let r = e
        .validate(&verify_req(&kbt, vec![public(&e, &issuer)], bytes_nonce()))
        .unwrap();
    for id in [
        "signature",
        "sd.match",
        "kb.signature",
        "kb.aud",
        "kb.nonce",
    ] {
        assert_status(&r, id, Status::Pass);
    }
    assert_no_fail(&r);
}

#[test]
fn present_plain_cwt_wraps_it_in_an_sd_kbt() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let holder = gen_key(&e, KeySpec::Ed25519, 2);
    let mut req = request(edn_claims(CWT_EDN), &issuer);
    req.cnf = Some(CnfChoice::Key {
        key: public(&e, &holder),
    });
    let cwt = e.issue(&req).unwrap();
    assert_eq!(cwt.kind, Kind::Cwt);
    let kbt = e
        .present(&present_req(&cwt, vec![], &holder, bytes_nonce()))
        .unwrap();
    assert_eq!(kbt.kind, Kind::SdKbt);
    assert!(kbt.disclosures.is_empty());
    let r = e
        .validate(&verify_req(&kbt, vec![public(&e, &issuer)], bytes_nonce()))
        .unwrap();
    assert_status(&r, "signature", Status::Pass);
    assert_status(&r, "kb.signature", Status::Pass);
}

#[test]
fn text_nonce_is_refused_for_cose_and_bytes_for_jose() {
    let e = engine();
    let issuer = gen_key(&e, KeySpec::P256, 1);
    let holder = gen_key(&e, KeySpec::P256, 2);
    let jose = issued_sd_jwt(&e, &issuer, &holder);
    let err = e
        .present(&present_req(&jose, vec![0], &holder, bytes_nonce()))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidInput);
    // COSE accepts text as its UTF-8 bytes.
    let cose = issued_sd_cwt(&e, &issuer, &holder);
    let kbt = e
        .present(&present_req(&cose, vec![0], &holder, text_nonce()))
        .unwrap();
    let r = e
        .validate(&verify_req(
            &kbt,
            vec![public(&e, &issuer)],
            Nonce::Bytes {
                value: Bytes(NONCE.as_bytes().to_vec()),
            },
        ))
        .unwrap();
    assert_status(&r, "kb.nonce", Status::Pass);
}

#[test]
fn present_of_a_presentation_is_refused() {
    let e = engine();
    let doc = open_token(&e, "rfc9901-s5.2-sd-jwt-kb.txt");
    let holder = gen_key(&e, KeySpec::P256, 2);
    let err = e
        .present(&present_req(&doc, vec![0], &holder, text_nonce()))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedKind);
}
