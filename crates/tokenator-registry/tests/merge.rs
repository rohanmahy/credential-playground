//! `Registry::merge_iana` semantics: precedence, stats, atomicity.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{
    COSE_XML, JOSE_XML, insert_record, parsed, registry, registry_with, remove_record, xml_str,
};
use tokenator_registry::{
    EntryKind, Label, LocalAdditions, Registry, RegistryError, RegistryId, RegistryStats, Source,
};

fn cose_str() -> &'static str {
    xml_str(RegistryId::Cose)
}

/// The kinds a merge of `which` owns, all entries of them.
fn owned(r: &Registry, which: RegistryId) -> Vec<tokenator_registry::Entry> {
    which
        .kinds()
        .iter()
        .flat_map(|k| r.entries(*k).into_iter().cloned().collect::<Vec<_>>())
        .collect()
}

const TEST_ALG: &str = r#"<record date="2026-10-01">
      <name>TEST-ALG</name>
      <value>-65000</value>
      <description>A test algorithm</description>
      <capabilities>[kty]</capabilities>
      <controller>IETF</controller>
      <xref type="rfc" data="rfc9999"/>
      <recommended>No</recommended>
    </record>"#;

const HEADER_18: &str = r#"<record date="2026-10-01">
      <name>iana-18</name>
      <label>18</label>
      <value>bstr</value>
      <reg/>
      <description>Newly registered header</description>
      <xref type="rfc" data="rfc9999"/>
    </record>"#;

fn local_with_header_18() -> LocalAdditions {
    LocalAdditions::parse(
        r#"{
        "sd_cwt_revision": "draft-ietf-spice-sd-cwt-08",
        "entries": [
            {"kind": "cose_header", "label": 18, "name": "local-18",
             "description": "Local guess at header 18", "reference": []},
            {"kind": "cose_header", "label": 19, "name": "local-19",
             "description": "Another local header", "reference": []},
            {"kind": "cbor_tag", "label": 58, "name": "to-be-redacted",
             "description": "x", "reference": []}
        ]
    }"#,
    )
    .unwrap()
}

#[test]
fn merging_identical_data_changes_nothing_but_source() {
    let mut r = registry();
    let before_len = r.len();
    let n = parsed(RegistryId::Cose).entries.len();
    let stats = r.merge_iana(COSE_XML, RegistryId::Cose).unwrap();
    assert_eq!(
        stats,
        RegistryStats {
            added: 0,
            updated: 0,
            unchanged: n,
            removed: 0,
            superseded_local: 0,
            iana_updated: Some("2026-08-25".into()),
        }
    );
    assert_eq!(r.len(), before_len);
    assert!(
        owned(&r, RegistryId::Cose)
            .iter()
            .all(|e| e.source == Source::Refreshed)
    );
    // other registries untouched
    assert!(
        owned(&r, RegistryId::Cwt)
            .iter()
            .all(|e| e.source == Source::Iana)
    );
    assert!(
        owned(&r, RegistryId::Jose)
            .iter()
            .all(|e| e.source == Source::Iana)
    );
    assert_eq!(r.cbor_tag(58).unwrap().source, Source::Local);
}

#[test]
fn updated_entry_counts_and_wins() {
    let mut r = registry();
    let xml = cose_str().replace(
        "<description>ECDSA w/ SHA-256</description>",
        "<description>ECDSA w/ SHA-256 (refreshed)</description>",
    );
    let stats = r.merge_iana(xml.as_bytes(), RegistryId::Cose).unwrap();
    assert_eq!(stats.updated, 1);
    assert_eq!(stats.added, 0);
    assert_eq!(stats.removed, 0);
    let es256 = r.cose_alg(-7).unwrap();
    assert_eq!(es256.description, "ECDSA w/ SHA-256 (refreshed)");
    assert_eq!(es256.source, Source::Refreshed);
}

#[test]
fn added_entry_counts_and_is_findable() {
    let mut r = registry();
    assert!(r.cose_alg(-65000).is_none());
    let xml = insert_record(cose_str(), "algorithms", TEST_ALG);
    let stats = r.merge_iana(xml.as_bytes(), RegistryId::Cose).unwrap();
    assert_eq!(stats.added, 1);
    assert_eq!(stats.updated, 0);
    let e = r.cose_alg(-65000).unwrap();
    assert_eq!(e.name, "TEST-ALG");
    assert_eq!(e.source, Source::Refreshed);
    assert_eq!(
        r.by_name(EntryKind::CoseAlg, "TEST-ALG").unwrap().label,
        Label::Int(-65000)
    );
}

#[test]
fn removed_entry_counts_and_disappears() {
    let mut r = registry();
    let before = r.len();
    let xml = remove_record(cose_str(), "<name>ESP256</name>");
    let stats = r.merge_iana(xml.as_bytes(), RegistryId::Cose).unwrap();
    assert_eq!(stats.removed, 1);
    assert_eq!(stats.added, 0);
    assert!(r.cose_alg(-9).is_none());
    assert!(r.by_name(EntryKind::CoseAlg, "ESP256").is_none());
    assert_eq!(r.len(), before - 1);
}

#[test]
fn iana_registration_supersedes_local_entry() {
    let mut r = registry_with(&[], local_with_header_18());
    let local = r.cose_header(18).unwrap();
    assert_eq!(local.source, Source::Local);
    assert_eq!(local.name, "local-18");
    let before = r.len();

    let xml = insert_record(cose_str(), "header-parameters", HEADER_18);
    let stats = r.merge_iana(xml.as_bytes(), RegistryId::Cose).unwrap();
    assert_eq!(stats.superseded_local, 1);
    assert_eq!(stats.added, 0, "superseded locals are not counted as added");
    let e = r.cose_header(18).unwrap();
    assert_eq!(e.name, "iana-18");
    assert_eq!(e.source, Source::Refreshed);
    assert_eq!(r.len(), before, "one visible entry per codepoint");
    // unrelated local entries remain
    assert_eq!(r.cose_header(19).unwrap().source, Source::Local);
    assert_eq!(r.cbor_tag(58).unwrap().source, Source::Local);
}

#[test]
fn local_entry_resurfaces_when_iana_drops_the_codepoint() {
    // Build: IANA registers sd_claims (TEMPORARY), shadowing the local entry.
    let mut r = registry();
    assert_eq!(r.cose_header(17).unwrap().source, Source::Iana);
    // Refresh: the temporary registration has expired.
    let xml = remove_record(cose_str(), "<name>sd_claims (TEMPORARY");
    let stats = r.merge_iana(xml.as_bytes(), RegistryId::Cose).unwrap();
    assert_eq!(stats.removed, 1);
    let e = r.cose_header(17).unwrap();
    assert_eq!(e.source, Source::Local);
    assert_eq!(e.name, "sd_claims");
    assert!(!e.temporary);
}

#[test]
fn shadowed_local_entries_survive_snapshot_round_trip() {
    let r = registry();
    let mut back = Registry::from_snapshot(&r.to_snapshot().unwrap()).unwrap();
    let xml = remove_record(cose_str(), "<name>sd_claims (TEMPORARY");
    back.merge_iana(xml.as_bytes(), RegistryId::Cose).unwrap();
    assert_eq!(back.cose_header(17).unwrap().source, Source::Local);
}

#[test]
fn merge_is_idempotent() {
    let mut r = registry();
    let xml = insert_record(cose_str(), "algorithms", TEST_ALG);
    r.merge_iana(xml.as_bytes(), RegistryId::Cose).unwrap();
    let snap1 = r.to_snapshot().unwrap();
    let stats = r.merge_iana(xml.as_bytes(), RegistryId::Cose).unwrap();
    assert_eq!(stats.added, 0);
    assert_eq!(stats.updated, 0);
    assert_eq!(stats.removed, 0);
    assert_eq!(stats.unchanged, parsed(RegistryId::Cose).entries.len() + 1);
    assert_eq!(r.to_snapshot().unwrap(), snap1);
}

#[test]
fn merge_records_new_iana_date() {
    let mut r = registry();
    let xml = cose_str().replacen(
        "<updated>2026-08-25</updated>",
        "<updated>2026-11-01</updated>",
        1,
    );
    let stats = r.merge_iana(xml.as_bytes(), RegistryId::Cose).unwrap();
    assert_eq!(stats.iana_updated.as_deref(), Some("2026-11-01"));
    assert_eq!(
        r.info()
            .iana_updated
            .get(&RegistryId::Cose)
            .map(String::as_str),
        Some("2026-11-01")
    );
    assert_eq!(
        r.info()
            .iana_updated
            .get(&RegistryId::Jose)
            .map(String::as_str),
        Some("2026-09-29")
    );
}

#[test]
fn merged_registry_round_trips_with_sources() {
    let mut r = registry();
    r.merge_iana(JOSE_XML, RegistryId::Jose).unwrap();
    let back = Registry::from_snapshot(&r.to_snapshot().unwrap()).unwrap();
    assert_eq!(back.jose_header("typ").unwrap().source, Source::Refreshed);
    assert_eq!(back.cose_header(4).unwrap().source, Source::Iana);
    assert_eq!(back.cbor_tag(61).unwrap().source, Source::Local);
}

#[test]
fn malformed_xml_is_an_error_and_leaves_registry_unchanged() {
    let mut r = registry();
    let before = r.to_snapshot().unwrap();
    let truncated = &COSE_XML[..COSE_XML.len() / 2];
    for bad in [&b""[..], b"<registry", b"not xml at all", truncated] {
        let err = r.merge_iana(bad, RegistryId::Cose).unwrap_err();
        assert!(
            matches!(
                err,
                RegistryError::Xml {
                    registry: RegistryId::Cose,
                    ..
                }
            ),
            "{err:?}"
        );
        assert_eq!(r.to_snapshot().unwrap(), before);
    }
}

#[test]
fn wrong_registry_is_an_error_and_leaves_registry_unchanged() {
    let mut r = registry();
    let before = r.to_snapshot().unwrap();
    let err = r.merge_iana(COSE_XML, RegistryId::Jwt).unwrap_err();
    assert!(
        matches!(
            err,
            RegistryError::WrongRegistry {
                expected: RegistryId::Jwt,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(r.to_snapshot().unwrap(), before);
}

#[test]
fn merging_each_registry_touches_only_its_kinds() {
    for which in RegistryId::ALL {
        let mut r = registry();
        r.merge_iana(common::xml(which), which).unwrap();
        for other in RegistryId::ALL {
            let expect = if other == which {
                Source::Refreshed
            } else {
                Source::Iana
            };
            for e in owned(&r, other) {
                // local entries can only appear in kinds IANA doesn't cover here
                assert_eq!(e.source, expect, "after merging {which:?}: {e:?}");
            }
        }
    }
}
