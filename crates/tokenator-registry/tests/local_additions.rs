//! Local additions: the bundled file, the pinned SD-CWT revision, and
//! precedence against IANA at build time.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{COSE_XML, CWT_XML, registry, registry_with, remove_record};
use tokenator_registry::{EntryKind, Label, LocalAdditions, RegistryError, RegistryId, Source};

const REVISION: &str = "draft-ietf-spice-sd-cwt-08";

#[test]
fn bundled_file_parses_with_pinned_revision() {
    let local = LocalAdditions::bundled().unwrap();
    assert_eq!(local.sd_cwt_revision, REVISION);
    assert!(!local.entries.is_empty());
    assert!(local.entries.iter().all(|e| e.source == Source::Local));
}

#[test]
fn revision_exposed_by_registry() {
    let r = registry();
    assert_eq!(r.sd_cwt_revision(), REVISION);
    assert_eq!(r.info().sd_cwt_revision, REVISION);
}

#[test]
fn sd_cwt_tags_and_simple_value_are_local() {
    let r = registry();
    for (t, name) in [
        (58, "to-be-redacted"),
        (60, "redacted-claim-element"),
        (62, "to-be-decoy"),
    ] {
        let e = r.cbor_tag(t).unwrap();
        assert_eq!(e.source, Source::Local, "tag {t}");
        assert_eq!(e.name, name);
        assert!(
            e.reference.iter().any(|x| x.text.contains(REVISION)),
            "{e:?}"
        );
        assert!(
            e.reference
                .iter()
                .any(|x| x.url.as_deref().is_some_and(|u| u.contains(REVISION)))
        );
    }
    let s = r.cbor_simple(59).unwrap();
    assert_eq!(s.source, Source::Local);
    assert_eq!(s.name, "redacted_claim_keys");
    assert!(s.reference.iter().any(|x| x.text.contains(REVISION)));
}

#[test]
fn local_file_lists_sd_cwt_header_params_and_vct() {
    let local = LocalAdditions::bundled().unwrap();
    let has = |kind, label: i64, name: &str| {
        local
            .entries
            .iter()
            .any(|e| e.kind == kind && e.label == Label::Int(label) && e.name == name)
    };
    assert!(has(EntryKind::CoseHeader, 17, "sd_claims"));
    assert!(has(EntryKind::CoseHeader, 170, "sd_alg"));
    assert!(has(EntryKind::CoseHeader, 171, "sd_aead_encrypted_claims"));
    assert!(has(EntryKind::CoseHeader, 172, "sd_aead"));
    assert!(has(EntryKind::CwtClaim, 11, "vct"));
    assert!(has(EntryKind::CborTag, 18, "COSE_Sign1"));
    assert!(has(EntryKind::CborTag, 61, "CWT"));
    let vct = local
        .entries
        .iter()
        .find(|e| e.kind == EntryKind::CwtClaim)
        .unwrap();
    assert_eq!(vct.jwt_name.as_deref(), Some("vct"));
}

#[test]
fn iana_wins_over_local_at_build_time() {
    let r = registry();
    // TEMPORARY IANA registrations exist in the fixtures for these.
    let sd = r.cose_header(17).unwrap();
    assert_eq!(sd.source, Source::Iana);
    assert!(sd.temporary);
    assert_eq!(r.cose_header(170).unwrap().source, Source::Iana);
    assert_eq!(r.cwt_claim(11).unwrap().source, Source::Iana);
    // and there is exactly one entry for the codepoint
    let n = r
        .entries(EntryKind::CoseHeader)
        .iter()
        .filter(|e| e.label == Label::Int(17))
        .count();
    assert_eq!(n, 1);
}

#[test]
fn local_fills_in_when_iana_lacks_the_codepoint() {
    let cose = remove_record(
        std::str::from_utf8(COSE_XML).unwrap(),
        "<name>sd_claims (TEMPORARY",
    );
    let cwt = remove_record(
        std::str::from_utf8(CWT_XML).unwrap(),
        "<claim>vct (TEMPORARY",
    );
    let r = registry_with(
        &[
            (RegistryId::Cose, cose.as_bytes()),
            (RegistryId::Cwt, cwt.as_bytes()),
        ],
        LocalAdditions::bundled().unwrap(),
    );
    let sd = r.cose_header(17).unwrap();
    assert_eq!(sd.source, Source::Local);
    assert_eq!(sd.name, "sd_claims");
    assert!(!sd.temporary);
    assert!(sd.reference.iter().any(|x| x.text.contains(REVISION)));
    let vct = r.cwt_claim(11).unwrap();
    assert_eq!(vct.source, Source::Local);
    assert_eq!(
        r.jwt_to_cwt("vct"),
        Some(&Label::Int(11)),
        "local entries feed the claim mapping"
    );
    // other SD-CWT headers still come from IANA
    assert_eq!(r.cose_header(170).unwrap().source, Source::Iana);
}

#[test]
fn custom_local_additions() {
    let text = r#"{
        "sd_cwt_revision": "draft-ietf-spice-sd-cwt-99",
        "entries": [
            {"kind": "cose_header", "label": "my-text-label", "name": "mine",
             "description": "A text-labelled local header", "reference": []},
            {"kind": "cbor_tag", "label": 1234567, "name": "test-tag",
             "description": "Test", "value_type": "any",
             "reference": [{"text": "Nowhere", "url": null}]}
        ]
    }"#;
    let local = LocalAdditions::parse(text).unwrap();
    assert_eq!(local.sd_cwt_revision, "draft-ietf-spice-sd-cwt-99");
    assert_eq!(local.entries.len(), 2);
    assert_eq!(local.entries[0].label, Label::Text("my-text-label".into()));
    assert_eq!(local.entries[0].value_type, None);
    assert_eq!(local.entries[1].value_type.as_deref(), Some("any"));
    assert_eq!(local.entries[1].reference[0].url, None);
    let r = registry_with(&[], local);
    assert_eq!(r.sd_cwt_revision(), "draft-ietf-spice-sd-cwt-99");
    assert_eq!(r.cose_header("my-text-label").unwrap().name, "mine");
    assert_eq!(r.cbor_tag(1_234_567).unwrap().source, Source::Local);
    assert!(r.cbor_tag(58).is_none(), "bundled additions not mixed in");
}

#[test]
fn malformed_local_additions_are_errors() {
    for bad in [
        "",
        "not json",
        "{}",
        r#"{"sd_cwt_revision": "x"}"#,
        r#"{"entries": []}"#,
        r#"{"sd_cwt_revision": "x", "entries": [{"kind": "no_such_kind", "label": 1, "name": "a", "description": ""}]}"#,
        r#"{"sd_cwt_revision": "x", "entries": [{"kind": "cbor_tag", "label": 1.5, "name": "a", "description": ""}]}"#,
        r#"{"sd_cwt_revision": "x", "entries": [{"kind": "cbor_tag", "name": "a", "description": ""}]}"#,
    ] {
        assert!(
            matches!(
                LocalAdditions::parse(bad),
                Err(RegistryError::LocalAdditions(_))
            ),
            "{bad:?} should be rejected"
        );
    }
}
