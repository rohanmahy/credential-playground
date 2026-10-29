//! Registry lookups, annotations in rendered documents, and the stateless
//! refresh (merge returns a snapshot; a new engine is built from it).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_core::{
    Engine, ErrorCode, RegistryEntry, RegistryId, RegistryKind, RegistryLabel,
    RegistryMergeRequest, RegistryQuery, RenderRequest, ViewOptions,
};

fn lookup(e: &Engine, q: RegistryQuery) -> Vec<RegistryEntry> {
    e.registry_lookup(&q)
}

fn by_label(kind: RegistryKind, label: RegistryLabel) -> RegistryQuery {
    RegistryQuery {
        kind: Some(kind),
        label: Some(label),
        ..RegistryQuery::default()
    }
}

/// `draft-…-NN` with a two-digit revision.
fn has_draft_revision(text: &str) -> bool {
    let mut rest = text;
    while let Some(i) = rest.find("draft-") {
        let name: String = rest[i..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        if let Some((_, rev)) = name.rsplit_once('-')
            && rev.len() == 2
            && rev.bytes().all(|b| b.is_ascii_digit())
        {
            return true;
        }
        rest = &rest[i + 6..];
    }
    false
}

#[test]
fn lookups_by_label_name_and_prefix() {
    let e = engine();
    let kid = lookup(
        &e,
        by_label(RegistryKind::CoseHeader, RegistryLabel::Int(4)),
    );
    assert_eq!(kid.len(), 1);
    assert_eq!(kid[0].name, "kid");

    let alg = lookup(
        &e,
        RegistryQuery {
            kind: Some(RegistryKind::CoseAlg),
            name: Some("ML-DSA-65".into()),
            ..RegistryQuery::default()
        },
    );
    assert_eq!(alg[0].label, RegistryLabel::Int(-49));

    let cn = lookup(
        &e,
        RegistryQuery {
            kind: Some(RegistryKind::JwtClaim),
            prefix: Some("cn".into()),
            ..RegistryQuery::default()
        },
    );
    assert!(cn.iter().any(|x| x.name == "cnf"), "{cn:?}");
    assert!(cn.iter().all(|x| x.name.starts_with("cn")));

    let iss = lookup(&e, by_label(RegistryKind::CwtClaim, RegistryLabel::Int(1)));
    assert_eq!(iss[0].name, "iss");
    assert_eq!(iss[0].jwt_name.as_deref(), Some("iss"));

    assert!(lookup(&e, RegistryQuery::default()).is_empty());
}

#[test]
fn sd_cwt_codepoints_come_from_local_additions() {
    let e = engine();
    let sd_claims = lookup(
        &e,
        by_label(RegistryKind::CoseHeader, RegistryLabel::Int(17)),
    );
    assert_eq!(sd_claims[0].name, "sd_claims");
    let refs: Vec<_> = sd_claims[0].spec.iter().map(|s| s.text.as_str()).collect();
    assert!(
        refs.iter().any(|t| t.contains("draft-ietf-spice-sd-cwt")),
        "{refs:?}"
    );
}

#[test]
fn spec_links_never_show_draft_revisions() {
    let e = engine();
    for kind in [
        RegistryKind::CoseHeader,
        RegistryKind::CwtClaim,
        RegistryKind::JwtClaim,
        RegistryKind::CborTag,
        RegistryKind::CborSimple,
    ] {
        let all = lookup(
            &e,
            RegistryQuery {
                kind: Some(kind),
                prefix: Some(String::new()),
                ..RegistryQuery::default()
            },
        );
        assert!(!all.is_empty(), "{kind:?}");
        for entry in all {
            for s in &entry.spec {
                assert!(
                    !has_draft_revision(&s.text),
                    "{kind:?} {}: {}",
                    entry.name,
                    s.text
                );
            }
        }
    }
}

#[test]
fn cose_documents_are_annotated() {
    let e = engine();
    let doc = open_token(&e, CWT_TAGGED);
    for comment in ["/ alg /", "/ kid /", "/ iss /", "/ exp /", "/ cti /"] {
        assert!(
            doc.main.text.contains(comment),
            "{comment}\n{}",
            doc.main.text
        );
    }
    let alg = find(&doc, "protected/~e/1").annotation.clone().unwrap();
    assert_eq!(alg.name, "alg");
    assert_eq!(alg.value_name.as_deref(), Some("ES256"));
    assert!(!alg.spec.is_empty());
    assert_eq!(
        find(&doc, "payload/~e/1").annotation.as_ref().unwrap().name,
        "iss"
    );
    // Hex rows carry the same comments.
    let tokenator_core::RawView::Hex { rows, .. } = &doc.raw else {
        panic!()
    };
    assert!(rows.iter().any(|r| r.comment.as_deref() == Some("alg")));
}

#[test]
fn sd_cwt_and_kbt_codepoints_are_annotated() {
    let e = engine();
    let doc = open_token(&e, SD_KBT);
    assert_eq!(
        find(&doc, "protected/~e/13")
            .annotation
            .as_ref()
            .unwrap()
            .name,
        "kcwt"
    );
    assert_eq!(
        find(&doc, "protected/~e/13/protected/~e/170")
            .annotation
            .as_ref()
            .unwrap()
            .name,
        "sd_alg"
    );
    assert_eq!(
        find(&doc, "protected/~e/13/unprotected/17")
            .annotation
            .as_ref()
            .unwrap()
            .name,
        "sd_claims"
    );
    // cnf contents are annotated in key context.
    let crv = find(&doc, "protected/~e/13/payload/~e/8/1/-1");
    assert_eq!(crv.annotation.as_ref().unwrap().name, "crv");
    assert_eq!(
        crv.annotation.as_ref().unwrap().value_name.as_deref(),
        Some("P-256")
    );
}

#[test]
fn jose_annotations_use_descriptions() {
    let e = engine();
    let doc = open_token(&e, "rfc7515-a3-jws-es256.txt");
    let iss = find(&doc, "payload/~e/iss").annotation.clone().unwrap();
    assert_eq!(iss.name, "iss");
    assert_eq!(iss.description, "Issuer");
    // JSON has no comments: the main text is unchanged by annotations.
    assert!(!doc.main.text.contains("/ "));
}

#[test]
fn annotations_can_be_turned_off() {
    let e = engine();
    let doc = open_token(&e, CWT_TAGGED);
    let plain = e
        .render(&RenderRequest {
            doc: tokenator_core::DocRef::from(&doc),
            layers: vec![],
            view: ViewOptions {
                annotations: false,
                ..ViewOptions::default()
            },
        })
        .unwrap();
    assert!(!plain.main.text.contains("/ alg /"));
    assert!(walk(&plain.tree).iter().all(|n| n.annotation.is_none()));
}

#[test]
fn info_reports_versions() {
    let e = engine();
    let info = e.info();
    assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(info.sd_cwt_revision, "draft-ietf-spice-sd-cwt-08");
    assert!(
        info.registry_updated
            .keys()
            .all(|k| ["cwt", "cose", "jwt", "jose"].contains(&k.as_str()))
    );
}

#[test]
fn merge_returns_a_snapshot_for_a_new_engine() {
    let e = engine();
    let before = lookup(
        &e,
        by_label(RegistryKind::CoseHeader, RegistryLabel::Int(4)),
    );
    let xml = std::fs::read(testdata("iana/cose.xml")).unwrap();
    let merged = e
        .registry_merge(&RegistryMergeRequest {
            base_snapshot: None,
            xml: xml.into(),
            which: RegistryId::Cose,
        })
        .unwrap();
    let s = &merged.stats;
    assert!(s.added + s.updated + s.unchanged > 0, "{s:?}");
    // The engine itself did not change.
    assert_eq!(
        lookup(
            &e,
            by_label(RegistryKind::CoseHeader, RegistryLabel::Int(4))
        ),
        before
    );
    let refreshed = Engine::with_registry_snapshot(&merged.snapshot).unwrap();
    let kid = lookup(
        &refreshed,
        by_label(RegistryKind::CoseHeader, RegistryLabel::Int(4)),
    );
    assert_eq!(kid[0].name, "kid");
    // Merging into an explicit base gives the same snapshot.
    let again = e
        .registry_merge(&RegistryMergeRequest {
            base_snapshot: Some(merged.snapshot.clone()),
            xml: std::fs::read(testdata("iana/cose.xml")).unwrap().into(),
            which: RegistryId::Cose,
        })
        .unwrap();
    assert_eq!(again.stats.added, 0);
}

#[test]
fn bad_registry_data_is_an_error() {
    let e = engine();
    let err = e
        .registry_merge(&RegistryMergeRequest {
            base_snapshot: None,
            xml: b"<not-a-registry/>".to_vec().into(),
            which: RegistryId::Jwt,
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Registry);
    let err = Engine::with_registry_snapshot(b"{").unwrap_err();
    assert_eq!(err.code, ErrorCode::Registry);
}
