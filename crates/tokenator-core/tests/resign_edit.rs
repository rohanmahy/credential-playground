//! Live edit (`parse_edit`) and Edit & re-sign (`resign`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_core::{
    DocRef, Document, Engine, ErrorCode, JsonLayout, KeyRef, KeySpec, Kind, PartRef, ResignRequest,
    Severity, Status, TamperOp, TamperRequest, ViewOptions,
};

fn resign(e: &Engine, doc: &Document, key: KeyRef) -> Document {
    e.resign(&ResignRequest {
        doc: DocRef::from(doc),
        key,
        alg: None,
        randomness: None,
        view: ViewOptions::default(),
    })
    .unwrap()
}

fn jwt(e: &Engine) -> Document {
    open_token(e, "rfc7515-a3-jws-es256.txt")
}

// ---------------------------------------------------------------- parse_edit

#[test]
fn unchanged_text_gives_back_the_same_bytes() {
    let e = engine();
    for name in JOSE_FIXTURES.iter().chain(COSE_FIXTURES.iter()) {
        let doc = open_token(&e, name);
        let r = edit(&e, &doc, doc.main.text.clone());
        assert!(r.ok, "{name}: {:?}", r.diagnostics);
        assert_eq!(r.bytes.as_ref(), Some(&doc.bytes), "{name}");
        assert!(!r.signature_stale, "{name}");
        let redone = r.document.unwrap();
        assert_eq!(redone.tree, doc.tree, "{name}");
        assert_eq!(redone.main, doc.main, "{name}");
    }
}

#[test]
fn editing_a_jwt_claim_marks_the_signature_stale() {
    let e = engine();
    let doc = jwt(&e);
    let r = edit(&e, &doc, replace_node(&doc, "payload/~e/iss", r#""jim""#));
    assert!(r.ok, "{:?}", r.diagnostics);
    assert!(r.signature_stale);
    let new = r.document.unwrap();
    assert!(new.signature_stale);
    assert_eq!(main_text(&new, "payload/~e/iss"), r#""jim""#);
    let (before, after) = (segment_texts(&doc), segment_texts(&new));
    assert_eq!(before[0], after[0], "header bytes kept");
    assert_ne!(before[1], after[1]);
    assert_eq!(before[2], after[2], "original signature kept");
    assert_eq!(ids(&new), ids(&doc), "node ids unchanged");
    let report = validate(&e, &new, vec![rfc7515_key("A.3")], RFC7515_NOW);
    assert_status(&report, "signature", Status::Fail);
}

#[test]
fn jose_whitespace_is_content() {
    // The decoded payload is shown verbatim, so whitespace edits change the
    // payload bytes (RFC 7515 A.3 has CRLFs in its payload).
    let e = engine();
    let doc = jwt(&e);
    let payload = main_text(&doc, "payload/~e");
    assert!(payload.contains("\r\n"), "verbatim decoded payload");
    let r = edit(
        &e,
        &doc,
        replace_node(&doc, "payload/~e", &payload.replace("\r\n", "\n")),
    );
    assert!(r.ok);
    assert!(r.signature_stale);
}

#[test]
fn editing_a_disclosure_does_not_stale_the_issuer_signature() {
    let e = engine();
    let doc = open_token(&e, "rfc9901-s5.1-sd-jwt.txt");
    let i = doc
        .disclosures
        .iter()
        .position(|d| d.claim.as_deref() == Some("given_name"))
        .unwrap();
    let r = edit(
        &e,
        &doc,
        replace_node(&doc, &format!("disclosures/{i}/~e/2"), r#""Jane""#),
    );
    assert!(r.ok, "{:?}", r.diagnostics);
    assert!(!r.signature_stale);
    let new = r.document.unwrap();
    let report = validate(&e, &new, vec![rfc9901_issuer()], RFC9901_NOW);
    assert_status(&report, "signature", Status::Pass);
    assert_status(&report, "sd.unmatched", Status::Fail);
}

#[test]
fn invalid_text_reports_a_located_error() {
    let e = engine();
    for doc in [jwt(&e), open_token(&e, CWT_TAGGED)] {
        let mut text = doc.main.text.clone();
        let cut = text.rfind('}').unwrap();
        text.truncate(cut);
        let r = edit(&e, &doc, text);
        assert!(!r.ok);
        assert!(r.bytes.is_none() && r.document.is_none());
        let err = r
            .diagnostics
            .iter()
            .find(|d| d.severity == Severity::Error)
            .expect("an error");
        assert!(err.main.is_some(), "{err:?}");
    }
}

#[test]
fn editing_a_cwt_claim_keeps_other_bytes() {
    let e = engine();
    let doc = open_token(&e, CWT_TAGGED);
    let r = edit(&e, &doc, replace_node(&doc, "payload/~e/2", r#""alice""#));
    assert!(r.ok, "{:?}", r.diagnostics);
    assert!(r.signature_stale);
    let new = r.document.unwrap();
    assert_eq!(raw_bytes(&new, "protected"), raw_bytes(&doc, "protected"));
    assert_eq!(
        raw_bytes(&new, "unprotected"),
        raw_bytes(&doc, "unprotected")
    );
    assert_eq!(raw_bytes(&new, "signature"), raw_bytes(&doc, "signature"));
    assert_eq!(new.bytes[0], 0xd2, "tag kept");
    assert_eq!(ids(&new), ids(&doc));
    assert_status(
        &validate(&e, &new, vec![rfc8392_key()], RFC8392_NOW),
        "signature",
        Status::Fail,
    );
    // Edit & re-sign.
    let signed = resign(&e, &new, rfc8392_key());
    assert!(!signed.signature_stale);
    assert_eq!(raw_bytes(&signed, "payload"), raw_bytes(&new, "payload"));
    assert_status(
        &validate(&e, &signed, vec![rfc8392_key()], RFC8392_NOW),
        "signature",
        Status::Pass,
    );
}

#[test]
fn edits_to_unprotected_cose_headers_are_not_stale() {
    let e = engine();
    let doc = open_token(&e, CWT_TAGGED);
    let r = edit(&e, &doc, replace_node(&doc, "unprotected/4", "h'01'"));
    assert!(r.ok, "{:?}", r.diagnostics);
    assert!(!r.signature_stale);
}

#[test]
fn edn_encoding_indicators_produce_non_preferred_bytes() {
    let e = engine();
    let doc = render(&e, Kind::CborClaims, &hexd("a2 01 18 01 02 02"));
    assert_eq!(main_text(&doc, "1"), "1_0");
    let r = edit(&e, &doc, replace_node(&doc, "2", "3"));
    assert!(r.ok);
    // `1_0` was kept, only the edited value changed.
    assert_eq!(r.bytes.unwrap().0, hexd("a2 01 18 01 02 03"));
    let r = edit(&e, &doc, replace_node(&doc, "2", "2_1"));
    assert_eq!(r.bytes.unwrap().0, hexd("a2 01 18 01 02 19 00 02"));
    assert!(!r.signature_stale, "claim sets are unsigned");
}

#[test]
fn non_canonical_nan_is_written_with_a_warning() {
    let e = engine();
    let doc = render(&e, Kind::CborClaims, &hexd("a1 01 f9 3e 00"));
    let r = edit(&e, &doc, replace_node(&doc, "1", "NaN_2"));
    assert!(r.ok);
    assert_eq!(r.bytes.unwrap().0, hexd("a1 01 fa 7f c0 00 00"));
    assert!(
        r.diagnostics
            .iter()
            .any(|d| d.code == "edn.warning.non_canonical_nan" && d.severity == Severity::Warning),
        "{:?}",
        r.diagnostics
    );
}

#[test]
fn json_claim_edits_are_the_new_text() {
    let e = engine();
    let doc = open_token(&e, "rfc7519-s3.1-claims.json");
    let text = replace_node(&doc, "iss", r#""jim""#);
    let r = edit(&e, &doc, text.clone());
    assert!(r.ok);
    assert_eq!(r.bytes.unwrap().0, text.into_bytes());
    assert!(!r.signature_stale);
}

#[test]
fn edn_claim_edits_keep_comments() {
    let e = engine();
    let doc = open_token(&e, "sd-cwt-08-fig4-claims.edn");
    let text = replace_node(&doc, "500", "false");
    let r = edit(&e, &doc, text.clone());
    assert!(r.ok, "{:?}", r.diagnostics);
    assert_eq!(r.bytes.unwrap().0, text.into_bytes());
    assert!(
        r.document
            .unwrap()
            .main
            .text
            .contains("/most_recent_inspection_passed/")
    );
}

#[test]
fn pretty_json_layout_still_keeps_unedited_bytes() {
    let e = engine();
    let doc = jwt(&e);
    let pretty_view = ViewOptions {
        json_layout: JsonLayout::Pretty,
        ..ViewOptions::default()
    };
    let pretty = e
        .render(&tokenator_core::RenderRequest {
            doc: DocRef::from(&doc),
            layers: vec![],
            view: pretty_view.clone(),
        })
        .unwrap();
    assert_eq!(ids(&pretty), ids(&doc));
    let r = e.parse_edit(&tokenator_core::EditRequest {
        kind: doc.kind.clone(),
        base: doc.bytes.clone(),
        text: replace_node(&pretty, "payload/~e/iss", r#""jim""#),
        view: pretty_view,
    });
    assert!(r.ok, "{:?}", r.diagnostics);
    let new = r.document.unwrap();
    assert_eq!(segment_texts(&new)[0], segment_texts(&doc)[0]);
    assert_eq!(segment_texts(&new)[2], segment_texts(&doc)[2]);
}

// ---------------------------------------------------------------- resign

#[test]
fn resign_repairs_a_tampered_jwt() {
    let e = engine();
    let t = e
        .tamper(&TamperRequest {
            doc: DocRef::from(&jwt(&e)),
            op: TamperOp::FlipBit {
                part: PartRef::Payload,
                bit: 12,
            },
            view: ViewOptions::default(),
        })
        .unwrap();
    let fixed = resign(&e, &t, rfc7515_key("A.3"));
    assert!(!fixed.signature_stale);
    assert_eq!(
        segment_texts(&fixed)[1],
        segment_texts(&t)[1],
        "payload kept"
    );
    assert_status(
        &validate(&e, &fixed, vec![rfc7515_key("A.3")], RFC7515_NOW),
        "signature",
        Status::Pass,
    );
}

#[test]
fn resign_with_another_key() {
    let e = engine();
    let other = gen_key(&e, KeySpec::P256, 7);
    let doc = resign(&e, &jwt(&e), other.key.clone());
    assert_status(
        &validate(&e, &doc, vec![rfc7515_key("A.3")], RFC7515_NOW),
        "signature",
        Status::Fail,
    );
    assert_status(
        &validate(&e, &doc, vec![other.key], RFC7515_NOW),
        "signature",
        Status::Pass,
    );
}

#[test]
fn resign_is_deterministic_without_randomness() {
    let e = engine();
    let a = resign(&e, &jwt(&e), rfc7515_key("A.3"));
    let b = resign(&e, &jwt(&e), rfc7515_key("A.3"));
    assert_eq!(a.bytes, b.bytes);
    // With randomness, ML-DSA signing is hedged: reproducible per seed.
    let key = gen_key(&e, KeySpec::MlDsa44, 1);
    let mut req = ResignRequest {
        doc: DocRef::from(&open_token(&e, CWT_TAGGED)),
        key: key.key.clone(),
        alg: Some("ML-DSA-44".into()),
        randomness: Some(seed(1)),
        view: ViewOptions::default(),
    };
    let x = e.resign(&req).unwrap();
    assert_eq!(e.resign(&req).unwrap().bytes, x.bytes, "same seed");
    req.randomness = Some(seed(2));
    assert_ne!(e.resign(&req).unwrap().bytes, x.bytes, "different seed");
}

#[test]
fn resign_alg_override() {
    let e = engine();
    let key = gen_key(&e, KeySpec::Ed25519, 3);
    let doc = e
        .resign(&ResignRequest {
            doc: DocRef::from(&open_token(&e, CWT_TAGGED)),
            key: key.key.clone(),
            alg: Some("Ed25519".into()),
            randomness: None,
            view: ViewOptions::default(),
        })
        .unwrap();
    // The header still says ES256: the mismatch is the point, and the lint
    // reports it once a verifier key is supplied.
    assert_eq!(main_text(&doc, "protected/~e/1"), "-7");
    let r = validate(&e, &doc, vec![key.key], RFC8392_NOW);
    assert_ne!(status(&r, "signature"), Status::Pass);
}

#[test]
fn resign_needs_a_private_key() {
    let e = engine();
    let public = e.key_public(&rfc8392_key()).unwrap().key;
    let err = e
        .resign(&ResignRequest {
            doc: DocRef::from(&open_token(&e, CWT_TAGGED)),
            key: public,
            alg: None,
            randomness: None,
            view: ViewOptions::default(),
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::NoPrivateKey);
}

#[test]
fn resign_sd_cwt_keeps_disclosures() {
    let e = engine();
    let doc = open_token(&e, SD_ISSUER);
    let signed = resign(&e, &doc, sd_issuer_key());
    assert_eq!(signed.disclosures, doc.disclosures);
    let r = validate(&e, &signed, vec![sd_issuer_key()], SD_NOW);
    assert_status(&r, "signature", Status::Pass);
    assert_status(&r, "sd.match", Status::Pass);
}
