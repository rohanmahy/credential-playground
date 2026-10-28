//! Snapshot round-trip and the bundled snapshot.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::registry;
use tokenator_registry::{EntryKind, Registry, RegistryError, RegistryId, Source};

fn all_entries(r: &Registry) -> Vec<tokenator_registry::Entry> {
    use EntryKind::*;
    [
        JoseHeader,
        JoseAlg,
        JwkKty,
        JwkCrv,
        JwkParam,
        JwtClaim,
        JwtCnfMethod,
        CoseHeader,
        CoseHeaderAlgParam,
        CoseAlg,
        CoseKeyParam,
        CoseKeyTypeParam,
        CoseKty,
        CoseCrv,
        CwtClaim,
        CwtCnfMethod,
        CborTag,
        CborSimple,
    ]
    .into_iter()
    .flat_map(|k| r.entries(k).into_iter().cloned().collect::<Vec<_>>())
    .collect()
}

#[test]
fn round_trip_preserves_everything() {
    let r = registry();
    let bytes = r.to_snapshot().unwrap();
    let back = Registry::from_snapshot(&bytes).unwrap();
    assert_eq!(back.len(), r.len());
    assert_eq!(back.info(), r.info());
    assert_eq!(back.sd_cwt_revision(), "draft-ietf-spice-sd-cwt-08");
    assert_eq!(all_entries(&back), all_entries(&r));
    // spot-check rich fields survive
    let sd = back.cose_header(17).unwrap();
    assert!(sd.temporary);
    assert!(sd.reference[0].url.is_some());
    assert_eq!(
        back.cose_key_param(Some(7), -1).unwrap().key_type,
        Some(7.into())
    );
    assert_eq!(back.cwt_claim(7).unwrap().jwt_name.as_deref(), Some("jti"));
    assert_eq!(back.cbor_tag(58).unwrap().source, Source::Local);
}

#[test]
fn to_snapshot_is_deterministic() {
    let a = registry().to_snapshot().unwrap();
    let b = registry().to_snapshot().unwrap();
    assert_eq!(a, b);
    let again = Registry::from_snapshot(&a).unwrap().to_snapshot().unwrap();
    assert_eq!(
        a, again,
        "re-serializing a loaded snapshot must be byte-identical"
    );
}

#[test]
fn bundled_snapshot_loads_and_matches_fixtures() {
    let bundled = Registry::bundled().unwrap();
    let built = registry();
    assert_eq!(bundled.info(), built.info());
    assert_eq!(all_entries(&bundled), all_entries(&built));
    assert_eq!(
        Registry::BUNDLED_SNAPSHOT,
        built.to_snapshot().unwrap().as_slice()
    );
}

#[test]
fn bundled_snapshot_has_well_known_entries() {
    let r = Registry::bundled().unwrap();
    assert_eq!(r.cose_alg(-7).unwrap().name, "ES256");
    assert_eq!(r.cose_header(4).unwrap().name, "kid");
    assert_eq!(r.cwt_claim(8).unwrap().name, "cnf");
    assert_eq!(r.jose_header("typ").unwrap().description, "Type");
    assert_eq!(r.cbor_tag(61).unwrap().name, "CWT");
    assert_eq!(r.sd_cwt_revision(), "draft-ietf-spice-sd-cwt-08");
    for id in RegistryId::ALL {
        assert!(r.info().iana_updated.contains_key(&id), "{id:?}");
    }
}

#[test]
fn empty_and_garbage_snapshots_are_errors() {
    let good = registry().to_snapshot().unwrap();
    let truncated = &good[..good.len() / 2];
    for bad in [
        &b""[..],
        b"garbage",
        b"{}",
        b"[]",
        b"\xff\xfe\x00",
        truncated,
    ] {
        assert!(
            matches!(
                Registry::from_snapshot(bad),
                Err(RegistryError::Snapshot(_))
            ),
            "{:?} should be rejected",
            String::from_utf8_lossy(&bad[..bad.len().min(40)])
        );
    }
}

#[test]
fn unsupported_format_version_is_an_error() {
    let good = String::from_utf8(registry().to_snapshot().unwrap()).unwrap();
    // The proposed snapshot is JSON with a top-level `"format": 1`. If the
    // implementation picks another encoding this test should be adapted.
    let bumped = good.replacen("\"format\":1", "\"format\":999", 1).replacen(
        "\"format\": 1",
        "\"format\": 999",
        1,
    );
    assert_ne!(bumped, good, "snapshot should carry a format version");
    assert!(matches!(
        Registry::from_snapshot(bumped.as_bytes()),
        Err(RegistryError::Snapshot(_))
    ));
}
