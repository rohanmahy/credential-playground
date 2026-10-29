//! The `x5c` / `x5chain` leaf as an untrusted embedded key (SPEC §6 step 2).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use base64ct::{Base64, Encoding};
use common::*;
use tokenator_core::{
    CheckDetail, DocRef, HeaderOptions, IssueRequest, KeySelection, Kind, SdOptions, Status,
    ViewOptions,
};

fn cert_b64() -> String {
    Base64::encode_string(&key_file("x509/p256-selfsigned.der"))
}

fn issue(claims: DocRef, x5c: Vec<String>) -> tokenator_core::Document {
    engine()
        .issue(&IssueRequest {
            claims,
            issuer: key_ref("openssl/p256-pkcs8.pem"),
            alg: None,
            header: HeaderOptions {
                x5c,
                ..HeaderOptions::default()
            },
            sd: SdOptions::default(),
            cnf: None,
            jose_serialization: Default::default(),
            cose_tags: None,
            randomness: None,
            view: ViewOptions::default(),
        })
        .unwrap()
}

fn selection(r: &tokenator_core::ValidationReport) -> (KeySelection, bool) {
    match &item(r, "signature").detail {
        Some(CheckDetail::Signature {
            selection,
            untrusted,
            ..
        }) => (*selection, *untrusted),
        other => panic!("{other:?}"),
    }
}

#[test]
fn jose_x5c_leaf_verifies_untrusted() {
    let e = engine();
    let doc = issue(
        DocRef::new(Kind::JsonClaims, br#"{"sub": "x"}"#.to_vec()),
        vec![cert_b64()],
    );
    assert!(has_node(&doc, "protected/~e/x5c/0"));
    let r = validate(&e, &doc, vec![], LATER);
    assert_status(&r, "signature", Status::Pass);
    assert_eq!(selection(&r), (KeySelection::EmbeddedX5c, true));
    // A fitting panel key comes first (and here does not verify).
    let r = validate(&e, &doc, vec![rfc9901_issuer()], LATER);
    assert_status(&r, "signature", Status::Fail);
    assert_eq!(selection(&r).0, KeySelection::PanelUnmatched);
}

#[test]
fn cose_x5chain_leaf_verifies_untrusted() {
    let e = engine();
    let doc = issue(
        DocRef::new(Kind::EdnClaims, br#"{1: "x"}"#.to_vec()),
        vec![cert_b64()],
    );
    assert!(has_node(&doc, "protected/~e/33"));
    let r = validate(&e, &doc, vec![], LATER);
    assert_status(&r, "signature", Status::Pass);
    assert_eq!(selection(&r), (KeySelection::EmbeddedX5c, true));
}

#[test]
fn a_certificate_for_another_key_fails() {
    let e = engine();
    let other = Base64::encode_string(&{
        let pem = String::from_utf8(key_file("x509/ed25519-selfsigned.pem")).unwrap();
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        Base64::decode_vec(&body).unwrap()
    });
    // An Ed25519 certificate does not fit ES256: nothing to try.
    let doc = issue(
        DocRef::new(Kind::JsonClaims, br#"{"sub": "x"}"#.to_vec()),
        vec![other],
    );
    let r = validate(&e, &doc, vec![], LATER);
    assert_status(&r, "signature", Status::Skip);
}
