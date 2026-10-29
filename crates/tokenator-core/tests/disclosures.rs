//! SD views (`Document.disclosures`, `undisclosed`, `SdMark`s) and
//! `edit_disclosures` for both families.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use base64ct::{Base64UrlUnpadded, Encoding};
use common::*;
use tokenator_core::{
    DisclosureOp, DisclosureStatus, DocRef, Document, EditDisclosuresRequest, Engine, ErrorCode,
    Kind, SdMark, Status, ViewOptions,
};
use tokenator_crypto::{HashAlg, digest};

fn edit_d(e: &Engine, doc: &Document, ops: Vec<DisclosureOp>) -> Document {
    try_edit(e, doc, ops).unwrap()
}

fn try_edit(
    e: &Engine,
    doc: &Document,
    ops: Vec<DisclosureOp>,
) -> Result<Document, tokenator_core::EngineError> {
    e.edit_disclosures(&EditDisclosuresRequest {
        doc: DocRef::from(doc),
        ops,
        randomness: Some(seed(8)),
        view: ViewOptions::default(),
    })
}

fn sd_jwt(e: &Engine) -> Document {
    open_token(e, "rfc9901-s5.1-sd-jwt.txt")
}

fn sd_jwt_check(e: &Engine, doc: &Document) -> tokenator_core::ValidationReport {
    validate(e, doc, vec![rfc9901_issuer()], RFC9901_NOW)
}

fn sd_cwt(e: &Engine) -> Document {
    open_token(e, SD_ISSUER)
}

fn sd_cwt_check(e: &Engine, doc: &Document) -> tokenator_core::ValidationReport {
    validate(e, doc, vec![sd_issuer_key()], SD_NOW)
}

/// `(digest, disclosure)` for RFC 9901 §5.1.
fn rfc9901_s51() -> Vec<(String, String)> {
    let text = std::fs::read_to_string(testdata("tokens/rfc9901-disclosures.json")).unwrap();
    let all: serde_json::Value = serde_json::from_str(&text).unwrap();
    all.as_array()
        .unwrap()
        .iter()
        .filter(|v| v["section"] == "5.1")
        .map(|v| {
            (
                v["digest"].as_str().unwrap().to_owned(),
                v["disclosure"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

// ---------------------------------------------------------------- SD views

#[test]
fn jose_disclosures_list_digest_salt_name_value() {
    let e = engine();
    let doc = sd_jwt(&e);
    let expected = rfc9901_s51();
    assert_eq!(doc.disclosures.len(), 10);
    for (i, d) in doc.disclosures.iter().enumerate() {
        assert_eq!(d.index as usize, i);
        assert_eq!(d.node_id, node_id(&format!("disclosures/{i}")));
        let (_, text) = expected
            .iter()
            .find(|(digest, _)| *digest == d.digest)
            .unwrap_or_else(|| panic!("unknown digest {}", d.digest));
        let arr: serde_json::Value =
            serde_json::from_slice(&Base64UrlUnpadded::decode_vec(text).unwrap()).unwrap();
        assert_eq!(d.salt, arr[0].as_str().unwrap());
        let value = if arr.as_array().unwrap().len() == 3 {
            assert_eq!(d.claim.as_deref(), arr[1].as_str());
            &arr[2]
        } else {
            assert_eq!(d.claim, None, "array element");
            &arr[1]
        };
        let shown: serde_json::Value = serde_json::from_str(&d.value).unwrap();
        assert_eq!(&shown, value);
        assert_eq!(d.status, DisclosureStatus::Matched);
        assert!(!d.decoy);
    }
    assert!(doc.undisclosed.is_empty());
}

#[test]
fn matched_disclosures_link_to_their_slots() {
    let e = engine();
    for name in [
        "rfc9901-s5.1-sd-jwt.txt",
        "rfc9901-a2-presentation.txt",
        "rfc9901-a3-sd-jwt.txt",
        SD_ISSUER,
        SD_NESTED_ISSUER,
    ] {
        let doc = open_token(&e, name);
        for d in &doc.disclosures {
            let slot = d.slot.as_ref().unwrap_or_else(|| panic!("{name}: {d:?}"));
            assert_eq!(
                find(&doc, slot.as_str()).sd,
                Some(SdMark::Slot {
                    digest: d.digest.clone(),
                    disclosure: Some(d.index)
                }),
                "{name}"
            );
            assert_eq!(
                find(&doc, d.node_id.as_str()).sd,
                Some(SdMark::Disclosure { index: d.index }),
                "{name}"
            );
        }
    }
}

#[test]
fn undisclosed_slots_are_marked() {
    let e = engine();
    for name in ["rfc9901-a1-presentation.txt", SD_DECOY] {
        let doc = open_token(&e, name);
        assert!(!doc.undisclosed.is_empty(), "{name}");
        for s in &doc.undisclosed {
            assert_eq!(
                find(&doc, s.node_id.as_str()).sd,
                Some(SdMark::Slot {
                    digest: s.digest.clone(),
                    disclosure: None
                }),
                "{name}"
            );
        }
    }
}

#[test]
fn cose_disclosures_hash_the_encoded_bstr() {
    let e = engine();
    let doc = sd_cwt(&e);
    for d in &doc.disclosures {
        assert_eq!(d.node_id, node_id(&format!("unprotected/17/{}", d.index)));
        let bstr = raw_bytes(&doc, d.node_id.as_str());
        assert_eq!(d.digest, hex::encode(digest(HashAlg::Sha256, bstr)));
        assert_eq!(d.salt.len(), 32, "16-byte salt as hex");
        assert!(hex::decode(&d.salt).is_ok());
    }
    assert!(
        doc.disclosures
            .iter()
            .any(|d| d.claim.as_deref() == Some("501")),
        "{:?}",
        doc.disclosures
    );
}

#[test]
fn sd_kbt_disclosures_live_inside_kcwt() {
    let e = engine();
    let doc = open_token(&e, SD_KBT);
    assert!(!doc.disclosures.is_empty());
    for d in &doc.disclosures {
        assert!(
            d.node_id
                .as_str()
                .starts_with("protected/~e/13/unprotected/17/"),
            "{}",
            d.node_id
        );
    }
}

// ---------------------------------------------------------------- JOSE edits

#[test]
fn jose_remove_withholds_a_claim() {
    let e = engine();
    let doc = sd_jwt(&e);
    let t = edit_d(&e, &doc, vec![DisclosureOp::Remove { index: 0 }]);
    assert_eq!(t.disclosures.len(), 9);
    assert_eq!(t.undisclosed.len(), 1);
    assert!(!t.signature_stale);
    let r = sd_jwt_check(&e, &t);
    assert_status(&r, "signature", Status::Pass);
    assert_status(&r, "sd.match", Status::Pass);
}

#[test]
fn jose_duplicate_move_select() {
    let e = engine();
    let doc = sd_jwt(&e);
    let t = edit_d(&e, &doc, vec![DisclosureOp::Duplicate { index: 0 }]);
    assert_eq!(t.disclosures.len(), 11);
    assert_status(
        &sd_jwt_check(&e, &t),
        "sd.duplicate_disclosure",
        Status::Fail,
    );

    let t = edit_d(&e, &doc, vec![DisclosureOp::Move { from: 0, to: 9 }]);
    assert_eq!(t.disclosures[9].digest, doc.disclosures[0].digest);
    assert_status(&sd_jwt_check(&e, &t), "sd.match", Status::Pass);

    let t = edit_d(
        &e,
        &doc,
        vec![DisclosureOp::Select {
            indices: vec![3, 1],
        }],
    );
    let digests: Vec<_> = t.disclosures.iter().map(|d| d.digest.clone()).collect();
    assert_eq!(
        digests,
        [
            doc.disclosures[3].digest.clone(),
            doc.disclosures[1].digest.clone()
        ]
    );
}

#[test]
fn jose_append_forge_and_replace_do_not_match() {
    let e = engine();
    let doc = sd_jwt(&e);
    let foreign = rfc9901_s51()[0].1.clone();
    let other = open_token(&e, "rfc9901-a1-presentation.txt");
    let foreign_other = segment_texts(&other)[3].clone();
    assert_ne!(foreign, foreign_other);

    let t = edit_d(
        &e,
        &doc,
        vec![DisclosureOp::Append {
            encoded: foreign_other,
        }],
    );
    assert_eq!(t.disclosures[10].status, DisclosureStatus::Unmatched);
    assert_status(&sd_jwt_check(&e, &t), "sd.unmatched", Status::Fail);

    let t = edit_d(
        &e,
        &doc,
        vec![DisclosureOp::Forge {
            salt: Some("c2FsdA".into()),
            claim: Some("given_name".into()),
            value: Some(r#""Mallory""#.into()),
        }],
    );
    let forged = &t.disclosures[10];
    assert_eq!(forged.salt, "c2FsdA");
    assert_eq!(forged.value, r#""Mallory""#);
    assert_eq!(forged.status, DisclosureStatus::Unmatched);

    let i = doc
        .disclosures
        .iter()
        .position(|d| d.claim.as_deref() == Some("given_name"))
        .unwrap() as u32;
    let t = edit_d(
        &e,
        &doc,
        vec![DisclosureOp::ReplaceValue {
            index: i,
            value: r#""Jane""#.into(),
        }],
    );
    let replaced = &t.disclosures[i as usize];
    assert_eq!(replaced.salt, doc.disclosures[i as usize].salt);
    assert_eq!(replaced.status, DisclosureStatus::Unmatched);
    assert!(!t.signature_stale, "disclosures are not signed");
}

#[test]
fn jose_digest_edits_stale_the_signature() {
    let e = engine();
    let doc = sd_jwt(&e);
    let t = edit_d(
        &e,
        &doc,
        vec![DisclosureOp::AddDecoy {
            at: node_id("payload/~e"),
            digest: None,
        }],
    );
    assert!(t.signature_stale);
    assert_eq!(t.undisclosed.len(), 1);
    assert_status(&sd_jwt_check(&e, &t), "signature", Status::Fail);

    let t = edit_d(
        &e,
        &doc,
        vec![DisclosureOp::RemoveDigest {
            digest: doc.disclosures[0].digest.clone(),
        }],
    );
    assert!(t.signature_stale);
    assert_eq!(t.disclosures[0].status, DisclosureStatus::Unmatched);
}

#[test]
fn jose_edit_errors() {
    let e = engine();
    let doc = sd_jwt(&e);
    let err = try_edit(&e, &doc, vec![DisclosureOp::Remove { index: 10 }]).unwrap_err();
    assert_eq!(err.code, ErrorCode::DisclosureIndex);

    let err = e
        .edit_disclosures(&EditDisclosuresRequest {
            doc: DocRef::from(&doc),
            ops: vec![DisclosureOp::Forge {
                salt: None,
                claim: Some("x".into()),
                value: Some("1".into()),
            }],
            randomness: None,
            view: ViewOptions::default(),
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Randomness);

    let err = try_edit(
        &e,
        &doc,
        vec![DisclosureOp::Forge {
            salt: Some("s".into()),
            claim: Some("x".into()),
            value: Some("{not json".into()),
        }],
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::Parse);

    let jwt = open_token(&e, "rfc7515-a3-jws-es256.txt");
    let err = try_edit(&e, &jwt, vec![DisclosureOp::Remove { index: 0 }]).unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedKind);
}

#[test]
fn edits_keep_the_kb_jwt_but_break_its_sd_hash() {
    let e = engine();
    let doc = open_token(&e, "rfc9901-s5.2-sd-jwt-kb.txt");
    let t = edit_d(&e, &doc, vec![DisclosureOp::Remove { index: 0 }]);
    assert_eq!(t.kind, Kind::SdJwt { kb: true });
    assert_eq!(segment_texts(&t).last(), segment_texts(&doc).last());
    let mut req = tokenator_core::ValidateRequest::new(DocRef::from(&t), RFC9901_NOW);
    req.keys = vec![rfc9901_issuer()];
    let r = e.validate(&req).unwrap();
    assert_status(&r, "kb.sd_hash", Status::Fail);
}

// ---------------------------------------------------------------- COSE edits

#[test]
fn cose_remove_duplicate_move_select() {
    let e = engine();
    let doc = sd_cwt(&e);
    let n = doc.disclosures.len();
    assert!(n >= 2);

    let t = edit_d(&e, &doc, vec![DisclosureOp::Remove { index: 0 }]);
    assert_eq!(t.disclosures.len(), n - 1);
    assert!(!t.signature_stale, "sd_claims is unprotected");
    let r = sd_cwt_check(&e, &t);
    assert_status(&r, "signature", Status::Pass);
    assert_status(&r, "sd.match", Status::Pass);

    let t = edit_d(&e, &doc, vec![DisclosureOp::Duplicate { index: 1 }]);
    assert_eq!(t.disclosures.len(), n + 1);
    assert_status(
        &sd_cwt_check(&e, &t),
        "sd.duplicate_disclosure",
        Status::Fail,
    );

    let t = edit_d(
        &e,
        &doc,
        vec![DisclosureOp::Move {
            from: 0,
            to: (n - 1) as u32,
        }],
    );
    assert_eq!(t.disclosures[n - 1].digest, doc.disclosures[0].digest);

    let t = edit_d(&e, &doc, vec![DisclosureOp::Select { indices: vec![] }]);
    assert!(t.disclosures.is_empty());
    assert!(
        !has_node(&t, "unprotected/17"),
        "empty sd_claims is removed"
    );
}

#[test]
fn cose_forge_append_replace() {
    let e = engine();
    let doc = sd_cwt(&e);
    let n = doc.disclosures.len();

    let t = edit_d(
        &e,
        &doc,
        vec![DisclosureOp::Forge {
            salt: Some("00112233445566778899aabbccddeeff".into()),
            claim: Some("500".into()),
            value: Some("false".into()),
        }],
    );
    let forged = &t.disclosures[n];
    assert_eq!(forged.claim.as_deref(), Some("500"));
    assert_eq!(forged.value, "false");
    assert_eq!(forged.status, DisclosureStatus::Unmatched);

    let t = edit_d(
        &e,
        &doc,
        vec![DisclosureOp::Forge {
            salt: None,
            claim: None,
            value: None,
        }],
    );
    assert!(t.disclosures[n].decoy);

    // [h'00', 1] as bstr contents
    let t = edit_d(
        &e,
        &doc,
        vec![DisclosureOp::Append {
            encoded: "824100 01".replace(' ', ""),
        }],
    );
    assert_eq!(t.disclosures.len(), n + 1);
    assert_eq!(t.disclosures[n].status, DisclosureStatus::Unmatched);

    let t = edit_d(
        &e,
        &doc,
        vec![DisclosureOp::ReplaceValue {
            index: 0,
            value: r#""changed""#.into(),
        }],
    );
    assert_eq!(t.disclosures[0].salt, doc.disclosures[0].salt);
    assert_eq!(t.disclosures[0].value, r#""changed""#);
    assert_status(&sd_cwt_check(&e, &t), "sd.unmatched", Status::Fail);
}

#[test]
fn cose_digest_edits_are_not_supported_yet() {
    let e = engine();
    let doc = sd_cwt(&e);
    for op in [
        DisclosureOp::AddDecoy {
            at: node_id("payload/~e"),
            digest: None,
        },
        DisclosureOp::RemoveDigest {
            digest: doc.disclosures[0].digest.clone(),
        },
    ] {
        assert_eq!(
            try_edit(&e, &doc, vec![op]).unwrap_err().code,
            ErrorCode::Unsupported
        );
    }
}

#[test]
fn editing_an_sd_kbt_stales_the_kbt_signature() {
    let e = engine();
    let doc = open_token(&e, SD_KBT);
    let t = edit_d(&e, &doc, vec![DisclosureOp::Remove { index: 0 }]);
    assert_eq!(t.kind, Kind::SdKbt);
    assert!(t.signature_stale, "kcwt is in the KBT protected header");
    let mut req = tokenator_core::ValidateRequest::new(DocRef::from(&t), SD_NOW);
    req.keys = vec![sd_issuer_key()];
    let r = e.validate(&req).unwrap();
    assert_status(&r, "signature", Status::Pass);
    assert_status(&r, "kb.signature", Status::Fail);
}
