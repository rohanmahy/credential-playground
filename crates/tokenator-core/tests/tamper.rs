//! Tamper ops break the expected check (or, for equivalent encodings, keep
//! the signature valid and show up in the lint).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_core::{
    AlgValue, DisclosureStatus, DocRef, Document, Engine, EquivalentEncoding, ErrorCode, KidValue,
    Kind, PartRef, RawView, Severity, Status, TamperOp, TamperRequest, ViewOptions,
};

fn tamper(e: &Engine, doc: &Document, op: TamperOp) -> Document {
    e.tamper(&TamperRequest {
        doc: DocRef::from(doc),
        op,
        view: ViewOptions::default(),
    })
    .unwrap()
}

fn jwt(e: &Engine) -> Document {
    open_token(e, "rfc7515-a3-jws-es256.txt")
}

fn jwt_check(e: &Engine, doc: &Document) -> tokenator_core::ValidationReport {
    validate(e, doc, vec![rfc7515_key("A.3")], RFC7515_NOW)
}

fn cwt(e: &Engine) -> Document {
    open_token(e, CWT_TAGGED)
}

fn cwt_check(e: &Engine, doc: &Document) -> tokenator_core::ValidationReport {
    validate(e, doc, vec![rfc8392_key()], RFC8392_NOW)
}

fn segments(doc: &Document) -> Vec<String> {
    match &doc.raw {
        RawView::Segments { segments } => segments.iter().map(|s| s.text.clone()).collect(),
        other => panic!("{other:?}"),
    }
}

// ---------------------------------------------------------------- JOSE

#[test]
fn baseline_jwt_and_cwt_pass() {
    let e = engine();
    assert_status(&jwt_check(&e, &jwt(&e)), "signature", Status::Pass);
    assert_status(&cwt_check(&e, &cwt(&e)), "signature", Status::Pass);
}

#[test]
fn flip_payload_bit_breaks_the_signature_only_there() {
    let e = engine();
    let doc = jwt(&e);
    let t = tamper(
        &e,
        &doc,
        TamperOp::FlipBit {
            part: PartRef::Payload,
            bit: 10,
        },
    );
    assert!(t.signed && t.signature_stale);
    assert_eq!(t.kind, Kind::Jwt);
    let (before, after) = (segments(&doc), segments(&t));
    assert_eq!(before[0], after[0], "header untouched");
    assert_ne!(before[1], after[1], "payload changed");
    assert_eq!(before[2], after[2], "signature untouched");
    assert_status(&jwt_check(&e, &t), "signature", Status::Fail);
}

#[test]
fn flip_signature_and_header_bits() {
    let e = engine();
    for part in [PartRef::Signature, PartRef::Protected] {
        let t = tamper(&e, &jwt(&e), TamperOp::FlipBit { part, bit: 3 });
        assert_ne!(
            status(&jwt_check(&e, &t), "signature"),
            Status::Pass,
            "{part:?}"
        );
    }
}

#[test]
fn set_alg_none_is_linted_and_fails() {
    let e = engine();
    let t = tamper(
        &e,
        &jwt(&e),
        TamperOp::SetAlg {
            alg: AlgValue::Name("none".into()),
        },
    );
    assert_eq!(main_text(&t, "protected/~e/alg"), r#""none""#);
    let r = jwt_check(&e, &t);
    assert_status(&r, "signature", Status::Fail);
    assert_status(&r, "lint.alg_none", Status::Warn);
}

#[test]
fn set_alg_to_another_alg_breaks_verification() {
    let e = engine();
    let t = tamper(
        &e,
        &jwt(&e),
        TamperOp::SetAlg {
            alg: AlgValue::Name("ES384".into()),
        },
    );
    assert_ne!(status(&jwt_check(&e, &t), "signature"), Status::Pass);
}

#[test]
fn strip_signature() {
    let e = engine();
    let t = tamper(&e, &jwt(&e), TamperOp::StripSignature);
    assert_eq!(segments(&t)[2], "");
    assert_eq!(main_text(&t, "signature"), r#""""#);
    assert_status(&jwt_check(&e, &t), "signature", Status::Fail);
}

#[test]
fn set_and_remove_kid_in_jose() {
    let e = engine();
    let t = tamper(
        &e,
        &jwt(&e),
        TamperOp::SetKid {
            kid: Some(KidValue::Text {
                value: "other".into(),
            }),
        },
    );
    assert_eq!(main_text(&t, "protected/~e/kid"), r#""other""#);
    // The kid is in the protected header, so the signature breaks.
    assert_status(&jwt_check(&e, &t), "signature", Status::Fail);
    let back = tamper(&e, &t, TamperOp::SetKid { kid: None });
    assert!(!has_node(&back, "protected/~e/kid"));
}

#[test]
fn truncate_jose_keeps_a_readable_document() {
    let e = engine();
    let t = tamper(&e, &jwt(&e), TamperOp::Truncate { len: 20 });
    assert_eq!(t.bytes.len(), 20);
    assert!(
        t.diagnostics.iter().any(|d| d.code == "jose.segment_count"),
        "{:?}",
        t.diagnostics
    );
    assert_status(&jwt_check(&e, &t), "signature", Status::Fail);
}

#[test]
fn duplicate_disclosure_is_flagged() {
    let e = engine();
    let doc = open_token(&e, "rfc9901-s5.1-sd-jwt.txt");
    let t = tamper(&e, &doc, TamperOp::DuplicateDisclosure { index: 0 });
    assert_eq!(t.disclosures.len(), doc.disclosures.len() + 1);
    assert_eq!(
        t.disclosures.last().unwrap().status,
        DisclosureStatus::Duplicate
    );
    let r = validate(&e, &t, vec![rfc9901_issuer()], RFC9901_NOW);
    assert_status(&r, "sd.duplicate_disclosure", Status::Fail);
    // The issuer signature does not cover disclosures.
    assert_status(&r, "signature", Status::Pass);
}

#[test]
fn reencoded_jose_header_breaks_the_signature() {
    let e = engine();
    let doc = jwt(&e);
    let t = tamper(
        &e,
        &doc,
        TamperOp::ReencodeProtected {
            how: EquivalentEncoding::Auto,
        },
    );
    assert_ne!(segments(&doc)[0], segments(&t)[0]);
    // Same meaning: still exactly one member, alg ES256.
    assert_eq!(main_text(&t, "protected/~e/alg"), r#""ES256""#);
    assert_eq!(find(&t, "protected/~e").children.len(), 1);
    assert_status(&jwt_check(&e, &t), "signature", Status::Fail);
}

#[test]
fn tamper_works_on_json_serializations() {
    let e = engine();
    let doc = open_token(&e, "rfc7515-a7-jws-json-flattened.json");
    let t = tamper(&e, &doc, TamperOp::StripSignature);
    assert_eq!(t.kind, Kind::JwsJson { general: false });
    let r = validate(&e, &t, vec![rfc7515_key("A.3")], RFC7515_NOW);
    assert_status(&r, "signature", Status::Fail);
}

// ---------------------------------------------------------------- COSE

#[test]
fn cose_flips_break_the_signature() {
    let e = engine();
    let doc = cwt(&e);
    let last = (doc.bytes.len() - 1) as u32;
    for op in [
        TamperOp::FlipBit {
            part: PartRef::Payload,
            bit: 20,
        },
        TamperOp::FlipBit {
            part: PartRef::Signature,
            bit: 0,
        },
        TamperOp::FlipByteBit {
            offset: last,
            bit: 7,
        },
    ] {
        let t = tamper(&e, &doc, op.clone());
        assert!(t.signature_stale);
        assert_eq!(t.bytes.len(), doc.bytes.len());
        assert_status(&cwt_check(&e, &t), "signature", Status::Fail);
    }
}

#[test]
fn cose_strip_signature() {
    let e = engine();
    let t = tamper(&e, &cwt(&e), TamperOp::StripSignature);
    assert_eq!(raw_bytes(&t, "signature"), [0x40]);
    assert_status(&cwt_check(&e, &t), "signature", Status::Fail);
}

#[test]
fn cose_alg_changes() {
    let e = engine();
    for op in [
        TamperOp::SetAlg {
            alg: AlgValue::Label(-35),
        },
        TamperOp::RemoveAlg,
    ] {
        let t = tamper(&e, &cwt(&e), op.clone());
        assert_ne!(
            status(&cwt_check(&e, &t), "signature"),
            Status::Pass,
            "{op:?}"
        );
    }
    let t = tamper(
        &e,
        &cwt(&e),
        TamperOp::SetAlg {
            alg: AlgValue::Label(-35),
        },
    );
    assert_eq!(main_text(&t, "protected/~e/1"), "-35");
}

#[test]
fn cose_unprotected_kid_changes_keep_the_signature() {
    let e = engine();
    let t = tamper(
        &e,
        &cwt(&e),
        TamperOp::SetKid {
            kid: Some(KidValue::Bytes {
                value: b"other".to_vec().into(),
            }),
        },
    );
    let r = cwt_check(&e, &t);
    assert_status(&r, "signature", Status::Pass);
    assert!(matches!(
        item(&r, "signature").detail,
        Some(tokenator_core::CheckDetail::Signature {
            selection: tokenator_core::KeySelection::PanelUnmatched,
            ..
        })
    ));
    let t = tamper(&e, &cwt(&e), TamperOp::SetKid { kid: None });
    assert!(!has_node(&t, "unprotected/4"));
    assert_status(&cwt_check(&e, &t), "signature", Status::Pass);
}

#[test]
fn cose_truncation_gives_an_unreadable_document() {
    let e = engine();
    let t = tamper(&e, &cwt(&e), TamperOp::Truncate { len: 30 });
    assert_eq!(t.bytes.len(), 30);
    assert!(t.signature_stale);
    assert!(
        t.diagnostics.iter().any(|d| d.severity == Severity::Error),
        "{:?}",
        t.diagnostics
    );
    let err = e
        .validate(&tokenator_core::ValidateRequest::new(
            DocRef::from(&t),
            RFC8392_NOW,
        ))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Parse);
}

#[test]
fn equivalent_bstr_head_keeps_the_signature_and_is_linted() {
    let e = engine();
    let doc = cwt(&e);
    let t = tamper(
        &e,
        &doc,
        TamperOp::ReencodeProtected {
            how: EquivalentEncoding::WideBstrHead,
        },
    );
    assert_eq!(t.bytes.len(), doc.bytes.len() + 1);
    let r = cwt_check(&e, &t);
    assert_status(&r, "signature", Status::Pass);
    let enc = items(&r, "lint.encoding");
    assert!(
        enc.iter()
            .any(|i| i.node_ids.contains(&node_id("protected"))),
        "{enc:?}"
    );
}

#[test]
fn equivalent_header_contents_break_the_signature() {
    let e = engine();
    for how in [
        EquivalentEncoding::WideIntegers,
        EquivalentEncoding::IndefiniteMap,
    ] {
        let t = tamper(&e, &cwt(&e), TamperOp::ReencodeProtected { how });
        let r = cwt_check(&e, &t);
        assert_status(&r, "signature", Status::Fail);
        assert!(!items(&r, "lint.encoding").is_empty(), "{how:?}");
        // Still the same header meaning.
        assert_eq!(
            main_text(&t, "protected/~e/1/~k").trim_end_matches("_0"),
            "1"
        );
    }
}

#[test]
fn set_tags_matches_the_derived_fixtures() {
    let e = engine();
    let t = tamper(&e, &cwt(&e), TamperOp::SetTags { tags: vec![] });
    assert_eq!(&t.bytes[..], &token(CWT_UNTAGGED)[..]);
    assert_status(&cwt_check(&e, &t), "signature", Status::Pass);
    let t = tamper(&e, &cwt(&e), TamperOp::SetTags { tags: vec![61, 18] });
    assert_eq!(&t.bytes[..], &token(CWT_TAG61)[..]);
    let t = tamper(&e, &cwt(&e), TamperOp::SetTags { tags: vec![18, 18] });
    assert_eq!(&t.bytes[..2], [0xd2, 0xd2]);
}

#[test]
fn tamper_is_deterministic_and_never_resigns() {
    let e = engine();
    let ops = [
        TamperOp::StripSignature,
        TamperOp::SetTags { tags: vec![] },
        TamperOp::FlipBit {
            part: PartRef::Payload,
            bit: 1,
        },
    ];
    for op in ops {
        let a = tamper(&e, &cwt(&e), op.clone());
        let b = tamper(&e, &cwt(&e), op.clone());
        assert_eq!(json(&a), json(&b));
        assert!(a.signature_stale, "{op:?}");
    }
}

#[test]
fn tamper_on_unsuitable_documents() {
    let e = engine();
    let claims = open_token(&e, "rfc7519-s3.1-claims.json");
    let err = e
        .tamper(&TamperRequest {
            doc: DocRef::from(&claims),
            op: TamperOp::StripSignature,
            view: ViewOptions::default(),
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedKind);

    let err = e
        .tamper(&TamperRequest {
            doc: DocRef::from(&jwt(&e)),
            op: TamperOp::DuplicateDisclosure { index: 0 },
            view: ViewOptions::default(),
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedKind);

    let err = e
        .tamper(&TamperRequest {
            doc: DocRef::from(&open_token(&e, "rfc9901-s5.1-sd-jwt.txt")),
            op: TamperOp::DuplicateDisclosure { index: 99 },
            view: ViewOptions::default(),
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::DisclosureIndex);
}
