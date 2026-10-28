//! JWT claim name <-> CWT claim key mapping.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::registry;
use tokenator_registry::{EntryKind, Label};

const PAIRS: &[(&str, i64)] = &[
    ("iss", 1),
    ("sub", 2),
    ("aud", 3),
    ("exp", 4),
    ("nbf", 5),
    ("iat", 6),
    ("jti", 7),
    ("cnf", 8),
    ("scope", 9),
    ("eat_nonce", 10),
    ("vct", 11),
    ("hcert", -260),
];

#[test]
fn jwt_to_cwt_well_known() {
    let r = registry();
    for &(name, key) in PAIRS {
        assert_eq!(r.jwt_to_cwt(name), Some(&Label::Int(key)), "{name}");
    }
}

#[test]
fn cwt_to_jwt_well_known() {
    let r = registry();
    for &(name, key) in PAIRS {
        assert_eq!(r.cwt_to_jwt(key), Some(name), "{key}");
    }
}

#[test]
fn cti_maps_to_jti_not_cti() {
    let r = registry();
    assert_eq!(r.cwt_to_jwt(7), Some("jti"));
    assert_eq!(r.jwt_to_cwt("jti"), Some(&Label::Int(7)));
    assert_eq!(
        r.jwt_to_cwt("cti"),
        None,
        "cti is the CWT name, not a JWT claim name"
    );
}

#[test]
fn round_trip_for_every_mapped_cwt_claim() {
    let r = registry();
    let mut mapped = 0;
    for e in r.entries(EntryKind::CwtClaim) {
        if let Some(jwt) = r.cwt_to_jwt(e.label.clone()) {
            assert_eq!(r.jwt_to_cwt(jwt), Some(&e.label), "{jwt}");
            assert_eq!(e.jwt_name.as_deref(), Some(jwt));
            mapped += 1;
        }
    }
    assert!(mapped >= 40, "only {mapped} mapped claims");
}

#[test]
fn unmapped_claims() {
    let r = registry();
    assert_eq!(r.jwt_to_cwt("_sd"), None, "SD-JWT _sd has no CWT claim key");
    assert_eq!(r.jwt_to_cwt("sd_hash"), None);
    assert_eq!(r.jwt_to_cwt("no-such-claim"), None);
    assert_eq!(r.jwt_to_cwt(""), None);
    assert_eq!(r.cwt_to_jwt(-261), None, "JWT column N/A");
    assert_eq!(r.cwt_to_jwt(0), None);
    assert_eq!(r.cwt_to_jwt(123_456_789), None);
    assert_eq!(r.cwt_to_jwt("iss"), None, "text CWT keys are not JWT names");
}

#[test]
fn mapping_does_not_require_jwt_registry_entry() {
    // vct is only in the CWT registry's JWT column, not in the JWT claims registry.
    let r = registry();
    assert!(r.jwt_claim("vct").is_none());
    assert_eq!(r.jwt_to_cwt("vct"), Some(&Label::Int(11)));
}
