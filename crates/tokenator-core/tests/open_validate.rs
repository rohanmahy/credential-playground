//! paste → detect → open → validate for every token family (SPEC §6).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_core::{
    Category, CheckDetail, DocRef, ErrorCode, FetchKind, KeyRef, KeySelection, Kind, Nonce,
    RawView, Status, ValidateRequest, ValidationReport,
};

fn selection(report: &ValidationReport, id: &str) -> (KeySelection, bool, Option<u32>) {
    match &item(report, id).detail {
        Some(CheckDetail::Signature {
            selection,
            untrusted,
            key_index,
            ..
        }) => (*selection, *untrusted, *key_index),
        other => panic!("{id}: no signature detail: {other:?}"),
    }
}

fn kb_request(doc: &tokenator_core::Document, keys: Vec<KeyRef>) -> ValidateRequest {
    let mut req = ValidateRequest::new(DocRef::from(doc), RFC9901_NOW);
    req.keys = keys;
    req.expected_aud = Some(RFC9901_AUD.into());
    req.expected_nonce = Some(Nonce::Text {
        value: RFC9901_NONCE.into(),
    });
    req
}

fn sd_kbt_request(doc: &tokenator_core::Document) -> ValidateRequest {
    let mut req = ValidateRequest::new(DocRef::from(doc), SD_NOW);
    req.keys = vec![sd_issuer_key()];
    req.expected_aud = Some(SD_AUD.into());
    req.expected_nonce = Some(Nonce::Bytes {
        value: hexd(SD_CNONCE_HEX).into(),
    });
    req
}

// ---------------------------------------------------------------- JWT

#[test]
fn jwt_es256_verifies_with_its_key() {
    let e = engine();
    let doc = open_token(&e, "rfc7515-a3-jws-es256.txt");
    let r = validate(&e, &doc, vec![rfc7515_key("A.3")], RFC7515_NOW);
    assert_status(&r, "signature", Status::Pass);
    // No kid in the header: the panel key is tried because its alg fits.
    assert_eq!(
        selection(&r, "signature"),
        (KeySelection::PanelUnmatched, false, Some(0))
    );
    assert_status(&r, "time.exp", Status::Pass);
    assert!(!has(&r, "time.nbf") && !has(&r, "time.iat"));
    assert_no_fail(&r);
    assert_ne!(r.overall, Status::Fail);
}

#[test]
fn jwt_rs256_verifies_with_its_key() {
    let e = engine();
    let doc = open_token(&e, "rfc7515-a2-jws-rs256.txt");
    let r = validate(&e, &doc, vec![rfc7515_key("A.2")], RFC7515_NOW);
    assert_status(&r, "signature", Status::Pass);
    match &item(&r, "signature").detail {
        Some(CheckDetail::Signature { alg, key_label, .. }) => {
            assert_eq!(alg.as_deref(), Some("RS256"));
            assert_eq!(key_label.as_deref(), Some("RFC 7515 A.2"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn jwt_time_claims_honor_the_skew() {
    let e = engine();
    let doc = open_token(&e, "rfc7515-a3-jws-es256.txt");
    let exp = 1_300_819_380;
    let key = || vec![rfc7515_key("A.3")];
    assert_status(
        &validate(&e, &doc, key(), exp + 59),
        "time.exp",
        Status::Pass,
    );
    let r = validate(&e, &doc, key(), exp + 60);
    assert_status(&r, "time.exp", Status::Fail);
    assert_eq!(r.overall, Status::Fail);
    match &item(&r, "time.exp").detail {
        Some(CheckDetail::Time {
            claim,
            value,
            now,
            skew,
        }) => {
            assert_eq!(
                (claim.as_str(), *value, *now, *skew),
                ("exp", exp, exp + 60, 60)
            );
        }
        other => panic!("{other:?}"),
    }
    // A custom skew.
    let mut req = ValidateRequest::new(DocRef::from(&doc), exp + 60);
    req.keys = key();
    req.skew = 120;
    assert_status(&e.validate(&req).unwrap(), "time.exp", Status::Pass);
    req.skew = 0;
    req.now = exp;
    assert_status(&e.validate(&req).unwrap(), "time.exp", Status::Fail);
}

#[test]
fn jwt_time_items_link_to_their_claim_nodes() {
    let e = engine();
    let doc = open_token(&e, "rfc7515-a3-jws-es256.txt");
    let r = validate(&e, &doc, vec![rfc7515_key("A.3")], RFC7515_NOW);
    assert_eq!(item(&r, "time.exp").node_ids, [node_id("payload/~e/exp")]);
    assert!(
        item(&r, "signature")
            .node_ids
            .contains(&node_id("signature"))
    );
}

#[test]
fn hs256_is_skipped_as_unsupported() {
    let e = engine();
    for name in ["rfc7515-a1-jws-hs256.txt", "rfc7519-s3.1-jwt-hs256.txt"] {
        let doc = open_token(&e, name);
        let r = validate(&e, &doc, vec![], RFC7515_NOW);
        assert_status(&r, "signature", Status::Skip);
        assert!(item(&r, "signature").message.contains("HS256"), "{name}");
    }
}

#[test]
fn unsecured_jwts_fail_and_are_linted() {
    let e = engine();
    for name in [
        "rfc7515-a5-unsecured-jws.txt",
        "rfc7519-s6.1-unsecured-jwt.txt",
    ] {
        let doc = open_token(&e, name);
        let r = validate(&e, &doc, vec![], RFC7515_NOW);
        assert_status(&r, "signature", Status::Fail);
        assert_status(&r, "lint.alg_none", Status::Warn);
        assert_eq!(r.overall, Status::Fail, "{name}");
    }
}

#[test]
fn no_key_means_skip_not_fail() {
    let e = engine();
    let doc = open_token(&e, "rfc7515-a3-jws-es256.txt");
    let r = validate(&e, &doc, vec![], RFC7515_NOW);
    assert_status(&r, "signature", Status::Skip);
    assert_eq!(selection(&r, "signature").0, KeySelection::None);
    assert!(matches!(r.overall, Status::Skip | Status::Warn));
}

#[test]
fn a_wrong_panel_key_fails() {
    let e = engine();
    let doc = open_token(&e, "rfc7515-a3-jws-es256.txt");
    let r = validate(&e, &doc, vec![rfc9901_issuer()], RFC7515_NOW);
    assert_status(&r, "signature", Status::Fail);
}

#[test]
fn keys_that_do_not_fit_the_alg_are_not_tried() {
    let e = engine();
    let doc = open_token(&e, "rfc7515-a3-jws-es256.txt");
    // An RSA key cannot verify ES256: nothing to try, so skip.
    let r = validate(&e, &doc, vec![rfc7515_key("A.2")], RFC7515_NOW);
    assert_status(&r, "signature", Status::Skip);
}

#[test]
fn the_verifying_key_is_found_among_several() {
    let e = engine();
    let doc = open_token(&e, "rfc7515-a3-jws-es256.txt");
    let keys = vec![rfc9901_issuer(), rfc7515_key("A.2"), rfc7515_key("A.3")];
    let r = validate(&e, &doc, keys, RFC7515_NOW);
    assert_status(&r, "signature", Status::Pass);
    assert_eq!(selection(&r, "signature").2, Some(2));
}

#[test]
fn non_json_jws_payload_opens_with_a_diagnostic() {
    let e = engine();
    let doc = open_token(&e, "rfc7515-a4-jws-es512-nonjson-payload.txt");
    assert_eq!(doc.kind, Kind::JwsCompact);
    assert!(
        doc.diagnostics
            .iter()
            .any(|d| d.node_id == Some(node_id("payload"))),
        "{:?}",
        doc.diagnostics
    );
    let r = validate(&e, &doc, vec![rfc7515_key("A.4")], RFC7515_NOW);
    assert_status(&r, "signature", Status::Pass);
}

#[test]
fn jws_json_serializations_verify() {
    let e = engine();
    let doc = open_token(&e, "rfc7515-a7-jws-json-flattened.json");
    let r = validate(&e, &doc, vec![rfc7515_key("A.3")], RFC7515_NOW);
    assert_status(&r, "signature", Status::Pass);

    // General: one signature item per signature, in order.
    let doc = open_token(&e, "rfc7515-a6-jws-json-general.json");
    let r = validate(
        &e,
        &doc,
        vec![rfc7515_key("A.2"), rfc7515_key("A.3")],
        RFC7515_NOW,
    );
    let sigs = items(&r, "signature");
    assert_eq!(sigs.len(), 2);
    assert!(sigs.iter().all(|s| s.status == Status::Pass), "{sigs:?}");
    assert!(
        sigs[1]
            .node_ids
            .contains(&node_id("signatures/1/signature"))
    );
}

// ---------------------------------------------------------------- SD-JWT

#[test]
fn sd_jwt_without_kb_validates() {
    let e = engine();
    let doc = open_token(&e, "rfc9901-s5.1-sd-jwt.txt");
    let r = validate(&e, &doc, vec![rfc9901_issuer()], RFC9901_NOW);
    assert_status(&r, "signature", Status::Pass);
    assert_status(&r, "time.iat", Status::Pass);
    assert_status(&r, "time.exp", Status::Pass);
    assert_status(&r, "sd.sd_alg", Status::Pass);
    assert_status(&r, "sd.match", Status::Pass);
    assert_status(&r, "kb", Status::Skip);
    assert!(!has(&r, "sd.unmatched"));
    assert_eq!(doc.disclosures.len(), 10);
}

#[test]
fn sd_jwt_kb_validates_against_expectations() {
    let e = engine();
    let doc = open_token(&e, "rfc9901-s5.2-sd-jwt-kb.txt");
    let r = e
        .validate(&kb_request(&doc, vec![rfc9901_issuer()]))
        .unwrap();
    assert_status(&r, "signature", Status::Pass);
    assert_status(&r, "sd.match", Status::Pass);
    for id in ["kb.signature", "kb.sd_hash", "kb.aud", "kb.nonce", "kb.iat"] {
        assert_status(&r, id, Status::Pass);
    }
    // The cnf key is embedded, so it is labeled untrusted.
    assert_eq!(
        selection(&r, "kb.signature"),
        (KeySelection::EmbeddedCnf, true, None)
    );
    assert_no_fail(&r);
}

#[test]
fn sd_jwt_kb_wrong_nonce_and_aud_fail() {
    let e = engine();
    let doc = open_token(&e, "rfc9901-s5.2-sd-jwt-kb.txt");
    let mut req = kb_request(&doc, vec![rfc9901_issuer()]);
    req.expected_nonce = Some(Nonce::Text {
        value: "other".into(),
    });
    req.expected_aud = Some("https://someone.else".into());
    let r = e.validate(&req).unwrap();
    assert_status(&r, "kb.nonce", Status::Fail);
    assert_status(&r, "kb.aud", Status::Fail);
    assert_status(&r, "kb.signature", Status::Pass);
    assert_eq!(r.overall, Status::Fail);
}

#[test]
fn sd_jwt_kb_freshness() {
    let e = engine();
    let doc = open_token(&e, "rfc9901-s5.2-sd-jwt-kb.txt");
    let mut req = kb_request(&doc, vec![rfc9901_issuer()]);
    req.max_kb_age = Some(300);
    assert_status(&e.validate(&req).unwrap(), "kb.iat", Status::Pass);
    req.max_kb_age = Some(1);
    assert_status(&e.validate(&req).unwrap(), "kb.iat", Status::Fail);
}

#[test]
fn missing_kb_fails_when_expected() {
    let e = engine();
    let doc = open_token(&e, "rfc9901-s5.1-sd-jwt.txt");
    let r = e
        .validate(&kb_request(&doc, vec![rfc9901_issuer()]))
        .unwrap();
    assert_status(&r, "kb", Status::Fail);
}

#[test]
fn sd_jwt_kb_fixtures_all_validate() {
    let e = engine();
    for name in [
        "rfc9901-s5.2-sd-jwt-kb.txt",
        "rfc9901-a3-sd-jwt-kb.txt",
        "rfc9901-a4-sd-jwt-kb.txt",
        "rfc9901-s8.2-sd-jwt-kb-json-flattened.json",
    ] {
        let doc = open_token(&e, name);
        let r = e
            .validate(&kb_request(&doc, vec![rfc9901_issuer()]))
            .unwrap();
        assert_status(&r, "signature", Status::Pass);
        assert_status(&r, "kb.signature", Status::Pass);
        assert_status(&r, "kb.sd_hash", Status::Pass);
        assert_status(&r, "sd.match", Status::Pass);
    }
}

#[test]
fn general_sd_jwt_reports_each_signature() {
    let e = engine();
    let doc = open_token(&e, "rfc9901-s8.3-sd-jwt-kb-json-general.json");
    let r = e
        .validate(&kb_request(&doc, vec![rfc9901_issuer()]))
        .unwrap();
    let sigs = items(&r, "signature");
    assert_eq!(sigs.len(), 2);
    // Only the first signature's key (issuer-key-1) is published.
    assert_eq!(sigs[0].status, Status::Pass);
    assert_ne!(sigs[1].status, Status::Pass);
    assert_status(&r, "kb.sd_hash", Status::Pass);
}

#[test]
fn decoys_are_reported_as_undisclosed_info() {
    let e = engine();
    let doc = open_token(&e, "rfc9901-a1-presentation.txt");
    assert_eq!(doc.disclosures.len(), 2);
    assert!(!doc.undisclosed.is_empty());
    let r = validate(&e, &doc, vec![rfc9901_issuer()], RFC9901_NOW);
    assert_status(&r, "sd.match", Status::Pass);
    let undisclosed = items(&r, "sd.undisclosed");
    assert_eq!(undisclosed.len(), doc.undisclosed.len());
    assert!(undisclosed.iter().all(|i| i.status == Status::Info));
}

#[test]
fn issuer_metadata_is_offered_never_fetched() {
    let e = engine();
    let doc = open_token(&e, "rfc9901-a3-sd-jwt.txt");
    let r = validate(&e, &doc, vec![], RFC9901_NOW);
    assert_status(&r, "signature", Status::Skip);
    assert!(
        r.fetchable
            .iter()
            .any(|h| h.kind == FetchKind::IssuerMetadata
                && h.url == "https://pid-issuer.bund.de.example/.well-known/jwt-vc-issuer"),
        "{:?}",
        r.fetchable
    );
}

// ---------------------------------------------------------------- CWT

#[test]
fn cwt_verifies_tagged_untagged_and_tag61() {
    let e = engine();
    for name in [CWT_TAGGED, CWT_UNTAGGED, CWT_TAG61] {
        let doc = open_token(&e, name);
        assert_eq!(doc.kind, Kind::Cwt);
        let r = validate(&e, &doc, vec![rfc8392_key()], RFC8392_NOW);
        assert_status(&r, "signature", Status::Pass);
        // kid "AsymmetricECDSA256" matches the key's kid.
        assert_eq!(
            selection(&r, "signature"),
            (KeySelection::PanelKid, false, Some(0))
        );
        for id in ["time.exp", "time.nbf", "time.iat"] {
            assert_status(&r, id, Status::Pass);
        }
        assert_no_fail(&r);
    }
}

#[test]
fn cwt_expiry() {
    let e = engine();
    let doc = open_token(&e, CWT_TAGGED);
    let r = validate(&e, &doc, vec![rfc8392_key()], 1_444_064_944 + 60);
    assert_status(&r, "time.exp", Status::Fail);
    assert_eq!(item(&r, "time.exp").node_ids, [node_id("payload/~e/4")]);
    let r = validate(&e, &doc, vec![rfc8392_key()], 1_443_944_944 - 61);
    assert_status(&r, "time.nbf", Status::Fail);
    assert_status(&r, "time.iat", Status::Warn);
}

#[test]
fn cose_sign1_with_text_payload_verifies() {
    let e = engine();
    let doc = open_token(&e, "rfc9052-c2.1-sign1.cbor");
    assert_eq!(doc.kind, Kind::CoseSign1);
    let set = key_file("rfc8152-c7.1-public.cosekeyset.cbor");
    let keys = (0..4)
        .map(|i| {
            let mut k = KeyRef::new(set.clone());
            k.index = i;
            k
        })
        .collect();
    let r = validate(&e, &doc, keys, RFC8392_NOW);
    assert_status(&r, "signature", Status::Pass);
    assert_eq!(selection(&r, "signature").0, KeySelection::PanelKid);
}

// ---------------------------------------------------------------- SD-CWT

#[test]
fn sd_cwt_issuer_token_validates() {
    let e = engine();
    let doc = open_token(&e, SD_ISSUER);
    let r = validate(&e, &doc, vec![sd_issuer_key()], SD_NOW);
    assert_status(&r, "signature", Status::Pass);
    // The header kid (https://issuer.example/cose-key3) is not the key's
    // kid (…/cwk3.cbor), so the key is tried as a fitting panel key.
    assert_eq!(selection(&r, "signature").0, KeySelection::PanelUnmatched);
    assert_status(&r, "sd.match", Status::Pass);
    assert_status(&r, "sd.sd_alg", Status::Pass);
    for id in ["time.exp", "time.nbf", "time.iat"] {
        assert_status(&r, id, Status::Pass);
    }
    assert!(!doc.disclosures.is_empty());
    assert!(
        doc.disclosures
            .iter()
            .all(|d| d.status == tokenator_core::DisclosureStatus::Matched)
    );
}

#[test]
fn sd_cwt_kid_url_is_a_fetch_hint() {
    let e = engine();
    let doc = open_token(&e, SD_ISSUER);
    let r = validate(&e, &doc, vec![], SD_NOW);
    assert_status(&r, "signature", Status::Skip);
    assert!(
        r.fetchable
            .iter()
            .any(|h| h.kind == FetchKind::KidUrl && h.url == "https://issuer.example/cose-key3"),
        "{:?}",
        r.fetchable
    );
}

#[test]
fn sd_cwt_declared_alg_mismatch_is_linted() {
    // The C.2 key declares alg -51 (ESP384), the header says ES384 (-35).
    let e = engine();
    let doc = open_token(&e, SD_ISSUER);
    let r = validate(&e, &doc, vec![sd_issuer_key()], SD_NOW);
    let alg_key = items(&r, "lint.alg_key");
    assert!(!alg_key.is_empty(), "{:?}", ids_of(&r));
    assert!(alg_key.iter().all(|i| i.status == Status::Warn));
}

#[test]
fn sd_kbt_validates_with_expectations() {
    let e = engine();
    for name in [SD_KBT, SD_NESTED_KBT] {
        let doc = open_token(&e, name);
        assert_eq!(doc.kind, Kind::SdKbt);
        let r = e.validate(&sd_kbt_request(&doc)).unwrap();
        assert_status(&r, "signature", Status::Pass);
        assert_status(&r, "sd.match", Status::Pass);
        for id in ["kb.signature", "kb.aud", "kb.nonce", "kb.iat"] {
            assert_status(&r, id, Status::Pass);
        }
        assert_eq!(selection(&r, "kb.signature").0, KeySelection::EmbeddedCnf);
        assert!(!has(&r, "kb.sd_hash"), "{name}: sd_hash is JOSE only");
    }
}

#[test]
fn sd_kbt_wrong_cnonce_fails() {
    let e = engine();
    let doc = open_token(&e, SD_KBT);
    let mut req = sd_kbt_request(&doc);
    req.expected_nonce = Some(Nonce::Bytes {
        value: vec![0; 16].into(),
    });
    assert_status(&e.validate(&req).unwrap(), "kb.nonce", Status::Fail);
}

#[test]
fn sd_cwt_decoys_are_undisclosed() {
    let e = engine();
    let doc = open_token(&e, SD_DECOY);
    let r = validate(&e, &doc, vec![sd_issuer_key()], SD_NOW);
    assert_status(&r, "signature", Status::Pass);
    assert!(items(&r, "sd.undisclosed").len() >= 2, "{:?}", ids_of(&r));
    assert!(doc.undisclosed.len() >= 2);
}

#[test]
fn nested_sd_cwt_validates() {
    let e = engine();
    let doc = open_token(&e, SD_NESTED_ISSUER);
    let r = validate(&e, &doc, vec![sd_issuer_key()], SD_NOW);
    assert_status(&r, "signature", Status::Pass);
    assert_status(&r, "sd.match", Status::Pass);
}

// ---------------------------------------------------------------- shape

#[test]
fn report_items_are_ordered_by_category() {
    let e = engine();
    let doc = open_token(&e, "rfc9901-s5.2-sd-jwt-kb.txt");
    let r = e
        .validate(&kb_request(&doc, vec![rfc9901_issuer()]))
        .unwrap();
    let cats: Vec<Category> = r.items.iter().map(|i| i.category).collect();
    assert!(cats.windows(2).all(|w| w[0] <= w[1]), "{cats:?}");
    assert_eq!(cats.first(), Some(&Category::Signature));
}

#[test]
fn lint_items_only_warn_or_inform() {
    let e = engine();
    let names = JOSE_FIXTURES.iter().chain(COSE_FIXTURES.iter());
    for name in names {
        let doc = open_token(&e, name);
        let r = validate(&e, &doc, vec![], LATER);
        for i in r.items.iter().filter(|i| i.category == Category::Lint) {
            assert!(
                matches!(i.status, Status::Warn | Status::Info),
                "{name}: {} {:?}",
                i.id,
                i.status
            );
            assert!(i.id.starts_with("lint."), "{name}: {}", i.id);
        }
    }
}

#[test]
fn report_node_ids_exist_in_the_document() {
    let e = engine();
    let names = JOSE_FIXTURES.iter().chain(COSE_FIXTURES.iter());
    for name in names {
        let doc = open_token(&e, name);
        let r = validate(&e, &doc, vec![], LATER);
        for i in &r.items {
            for id in &i.node_ids {
                assert!(has_node(&doc, id.as_str()), "{name}: {} → {id}", i.id);
            }
        }
    }
}

#[test]
fn overall_follows_the_worst_item() {
    let e = engine();
    let names = JOSE_FIXTURES.iter().chain(COSE_FIXTURES.iter());
    for name in names {
        let doc = open_token(&e, name);
        let r = validate(&e, &doc, vec![], LATER);
        let any = |s| r.items.iter().any(|i| i.status == s);
        let expected =
            if any(Status::Fail) {
                Status::Fail
            } else if any(Status::Warn) {
                Status::Warn
            } else if r.items.iter().any(|i| {
                i.status == Status::Skip && (i.id == "signature" || i.id.starts_with("kb"))
            }) {
                Status::Skip
            } else {
                Status::Pass
            };
        assert_eq!(r.overall, expected, "{name}");
    }
}

#[test]
fn claim_sets_cannot_be_validated() {
    let e = engine();
    let doc = open_token(&e, "rfc7519-s3.1-claims.json");
    let err = e
        .validate(&ValidateRequest::new(DocRef::from(&doc), LATER))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedKind);
}

#[test]
fn claim_sets_open_as_unsigned_drafts() {
    let e = engine();
    let json = open_token(&e, "rfc7519-s3.1-claims.json");
    assert_eq!(json.kind, Kind::JsonClaims);
    assert!(!json.signed);
    assert_eq!(json.main.language, tokenator_core::Language::Json);
    assert_eq!(
        json.main.text,
        String::from_utf8(json.bytes.0.clone()).unwrap()
    );
    assert_eq!(json.raw, RawView::None);
    assert!(has_node(&json, "iss"));

    let cbor = open_token(&e, "rfc8392-a1-claims.cbor");
    assert_eq!(cbor.kind, Kind::CborClaims);
    assert!(!cbor.signed);
    assert_eq!(cbor.main.language, tokenator_core::Language::Edn);
    assert_eq!(hex_bytes(&cbor), &token("rfc8392-a1-claims.cbor")[..]);
    assert!(has_node(&cbor, "1") && has_node(&cbor, "7"));

    let edn = open_token(&e, "sd-cwt-08-fig4-claims.edn");
    assert_eq!(edn.kind, Kind::EdnClaims);
    // The hex view shows the CBOR encoding of the EDN.
    let encoded = common::edn(&String::from_utf8(token("sd-cwt-08-fig4-claims.edn")).unwrap());
    assert_eq!(hex_bytes(&edn), &encoded[..]);
}

#[test]
fn validate_is_repeatable() {
    let e = engine();
    let doc = open_token(&e, SD_KBT);
    let a = e.validate(&sd_kbt_request(&doc)).unwrap();
    let b = e.validate(&sd_kbt_request(&doc)).unwrap();
    assert_eq!(json(&a), json(&b));
}
