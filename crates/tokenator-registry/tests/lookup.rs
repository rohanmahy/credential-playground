//! Lookups by every key kind on a registry built from the fixtures.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::registry;
use tokenator_registry::{EntryKind, Label, Source};

#[test]
fn jose_lookups() {
    let r = registry();
    assert_eq!(r.jose_header("alg").unwrap().description, "Algorithm");
    assert_eq!(
        r.jose_header("x5c").unwrap().description,
        "X.509 Certificate Chain"
    );
    assert_eq!(r.jose_header("typ").unwrap().name, "typ");
    assert_eq!(r.jose_header("kid").unwrap().kind, EntryKind::JoseHeader);
    assert_eq!(
        r.jose_alg("ES256").unwrap().description,
        "ECDSA using P-256 and SHA-256"
    );
    assert!(r.jose_alg("ML-DSA-65").is_some());
    assert_eq!(r.jwk_kty("EC").unwrap().description, "Elliptic Curve");
    assert!(r.jwk_kty("AKP").is_some());
    assert_eq!(r.jwk_crv("P-256").unwrap().description, "P-256 Curve");
    assert_eq!(r.jwk_param("kty").unwrap().description, "Key Type");
    assert!(r.jwk_param("priv").is_some());
}

#[test]
fn jwt_lookups() {
    let r = registry();
    assert_eq!(r.jwt_claim("iss").unwrap().description, "Issuer");
    assert_eq!(r.jwt_claim("cnf").unwrap().description, "Confirmation");
    assert!(r.jwt_claim("_sd").is_some());
    assert!(r.jwt_claim("_sd_alg").is_some());
    assert!(r.jwt_claim("vct").is_none());
    assert_eq!(
        r.jwt_cnf_method("jkt").unwrap().description,
        "JWK SHA-256 Thumbprint"
    );
    assert_eq!(
        r.jwt_cnf_method("jwk").unwrap().kind,
        EntryKind::JwtCnfMethod
    );
}

#[test]
fn cose_header_lookup_int_and_text() {
    let r = registry();
    assert_eq!(r.cose_header(1).unwrap().name, "alg");
    assert_eq!(r.cose_header(4).unwrap().name, "kid");
    assert_eq!(r.cose_header(13).unwrap().name, "kcwt");
    assert_eq!(r.cose_header(33).unwrap().name, "x5chain");
    assert_eq!(r.cose_header(Label::Int(16)).unwrap().name, "typ");
    // text labels are looked up as text, not confused with JOSE names
    assert!(r.cose_header("alg").is_none());
    assert!(r.cose_header("no-such-header").is_none());
    assert!(r.cose_header(18).is_none());
    assert!(r.cose_header(i64::MIN).is_none());
}

#[test]
fn cose_value_lookups() {
    let r = registry();
    assert_eq!(r.cose_alg(-7).unwrap().name, "ES256");
    assert_eq!(r.cose_alg(-8).unwrap().name, "EdDSA");
    assert_eq!(r.cose_alg(-19).unwrap().name, "Ed25519");
    assert_eq!(r.cose_alg(-48).unwrap().name, "ML-DSA-44");
    assert_eq!(r.cose_alg(-257).unwrap().name, "RS256");
    assert!(r.cose_alg(0).is_none());
    assert!(r.cose_alg(-100_000).is_none());
    assert_eq!(r.cose_kty(2).unwrap().name, "EC2");
    assert_eq!(r.cose_kty(7).unwrap().name, "AKP");
    assert!(r.cose_kty(0).is_none());
    assert_eq!(r.cose_crv(1).unwrap().name, "P-256");
    assert_eq!(r.cose_crv(6).unwrap().name, "Ed25519");
}

#[test]
fn cose_key_params_common_and_type_specific() {
    let r = registry();
    assert_eq!(r.cose_key_param(None, 1).unwrap().name, "kty");
    assert_eq!(r.cose_key_param(None, 2).unwrap().name, "kid");
    assert_eq!(r.cose_key_param(None, 3).unwrap().name, "alg");
    // with a kty, common params are still found
    assert_eq!(r.cose_key_param(Some(2), 1).unwrap().name, "kty");
    assert_eq!(r.cose_key_param(Some(2), -1).unwrap().name, "crv");
    assert_eq!(r.cose_key_param(Some(2), -2).unwrap().name, "x");
    assert_eq!(r.cose_key_param(Some(1), -2).unwrap().name, "x");
    assert_eq!(r.cose_key_param(Some(3), -1).unwrap().name, "n");
    assert_eq!(r.cose_key_param(Some(7), -1).unwrap().name, "pub");
    assert_eq!(r.cose_key_param(Some(7), -2).unwrap().name, "priv");
    assert_eq!(
        r.cose_key_param(Some(2), -1).unwrap().kind,
        EntryKind::CoseKeyTypeParam
    );
    // negative labels are ambiguous without a kty
    assert!(r.cose_key_param(None, -1).is_none());
    assert!(r.cose_key_param(Some(999), -1).is_none());
}

#[test]
fn cwt_lookups() {
    let r = registry();
    for (k, name) in [
        (1, "iss"),
        (2, "sub"),
        (3, "aud"),
        (4, "exp"),
        (5, "nbf"),
        (6, "iat"),
        (7, "cti"),
        (8, "cnf"),
    ] {
        assert_eq!(r.cwt_claim(k).unwrap().name, name, "claim {k}");
    }
    assert_eq!(r.cwt_claim(11).unwrap().name, "vct");
    assert!(r.cwt_claim(0).is_none());
    assert!(r.cwt_claim("iss").is_none(), "CWT claims are keyed by int");
    assert_eq!(r.cwt_cnf_method(1).unwrap().name, "COSE_Key");
    assert_eq!(r.cwt_cnf_method(3).unwrap().name, "kid");
    assert!(r.cwt_cnf_method(0).is_none());
}

#[test]
fn cbor_tag_and_simple_lookups() {
    let r = registry();
    for (t, name) in [
        (18, "COSE_Sign1"),
        (61, "CWT"),
        (98, "COSE_Sign"),
        (58, "to-be-redacted"),
        (60, "redacted-claim-element"),
        (62, "to-be-decoy"),
    ] {
        let e = r.cbor_tag(t).unwrap_or_else(|| panic!("tag {t}"));
        assert_eq!(e.name, name);
        assert_eq!(e.kind, EntryKind::CborTag);
    }
    for t in [0, 1, 16, 17, 24, 96, 97, 100, 1004, 55799] {
        assert!(r.cbor_tag(t).is_some(), "tag {t}");
    }
    assert!(r.cbor_tag(u64::MAX).is_none());
    assert!(r.cbor_tag(12345).is_none());
    assert_eq!(r.cbor_simple(59).unwrap().name, "redacted_claim_keys");
    assert!(r.cbor_simple(20).is_none());
    assert!(r.cbor_simple(255).is_none());
}

#[test]
fn generic_get_matches_convenience_lookups() {
    let r = registry();
    assert_eq!(r.get(EntryKind::CoseAlg, -7), r.cose_alg(-7));
    assert_eq!(r.get(EntryKind::CoseHeader, 4), r.cose_header(4));
    assert_eq!(r.get(EntryKind::JoseHeader, "x5c"), r.jose_header("x5c"));
    assert_eq!(r.get(EntryKind::JwtClaim, "iss"), r.jwt_claim("iss"));
    assert_eq!(r.get(EntryKind::CwtClaim, 8), r.cwt_claim(8));
    assert_eq!(r.get(EntryKind::CborTag, 61), r.cbor_tag(61));
    assert_eq!(r.get(EntryKind::CborSimple, 59), r.cbor_simple(59));
    assert!(
        r.get(EntryKind::CoseAlg, "ES256").is_none(),
        "label, not name"
    );
}

#[test]
fn by_name() {
    let r = registry();
    assert_eq!(
        r.by_name(EntryKind::CoseAlg, "ES256").unwrap().label,
        Label::Int(-7)
    );
    assert_eq!(
        r.by_name(EntryKind::CoseAlg, "ML-DSA-87").unwrap().label,
        Label::Int(-50)
    );
    assert_eq!(
        r.by_name(EntryKind::CoseHeader, "x5chain").unwrap().label,
        Label::Int(33)
    );
    assert_eq!(
        r.by_name(EntryKind::CoseHeader, "typ").unwrap().label,
        Label::Int(16)
    );
    assert_eq!(
        r.by_name(EntryKind::CoseHeader, "sd_claims").unwrap().label,
        Label::Int(17)
    );
    assert_eq!(
        r.by_name(EntryKind::CwtClaim, "cti").unwrap().label,
        Label::Int(7)
    );
    assert_eq!(
        r.by_name(EntryKind::CoseKty, "EC2").unwrap().label,
        Label::Int(2)
    );
    assert_eq!(
        r.by_name(EntryKind::CborTag, "CWT").unwrap().label,
        Label::Int(61)
    );
    assert!(
        r.by_name(EntryKind::CoseAlg, "es256").is_none(),
        "exact match"
    );
    assert!(r.by_name(EntryKind::CoseAlg, "").is_none());
}

#[test]
fn entries_by_kind_sorted_and_homogeneous() {
    let r = registry();
    let algs = r.entries(EntryKind::CoseAlg);
    assert!(algs.len() > 50, "{}", algs.len());
    assert!(algs.iter().all(|e| e.kind == EntryKind::CoseAlg));
    let labels: Vec<_> = algs.iter().map(|e| e.label.clone()).collect();
    let mut sorted = labels.clone();
    sorted.sort();
    assert_eq!(labels, sorted, "entries() must be ordered by label");
    let tags = r.entries(EntryKind::CborTag);
    assert!(tags.iter().all(|e| e.source == Source::Local));
    assert!(tags.len() >= 16);
}

#[test]
fn every_kind_has_entries_and_len_is_sum() {
    use EntryKind::*;
    let r = registry();
    let kinds = [
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
    ];
    let mut total = 0;
    for k in kinds {
        let n = r.entries(k).len();
        assert!(n > 0, "{k:?} empty");
        total += n;
    }
    assert_eq!(r.len(), total);
    assert!(!r.is_empty());
}

#[test]
fn search_prefix() {
    let r = registry();
    let hits = r.search(Some(EntryKind::CoseAlg), "ml-dsa");
    let mut names: Vec<_> = hits.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]);
    let x5 = r.search(Some(EntryKind::JoseHeader), "x5");
    assert!(x5.iter().any(|e| e.name == "x5c"));
    assert!(x5.iter().all(|e| e.kind == EntryKind::JoseHeader));
    let any = r.search(None, "kid");
    assert!(any.iter().any(|e| e.kind == EntryKind::CoseHeader));
    assert!(any.iter().any(|e| e.kind == EntryKind::JoseHeader));
    assert!(r.search(None, "zzzz-nothing").is_empty());
    assert_eq!(
        r.search(Some(EntryKind::CborSimple), "").len(),
        r.entries(EntryKind::CborSimple).len()
    );
}

#[test]
fn iana_snapshot_dates_recorded() {
    let r = registry();
    let info = r.info();
    assert_eq!(
        info.iana_updated
            .get(&tokenator_registry::RegistryId::Cose)
            .map(String::as_str),
        Some("2026-08-25")
    );
    assert_eq!(
        info.iana_updated
            .get(&tokenator_registry::RegistryId::Jose)
            .map(String::as_str),
        Some("2026-09-29")
    );
    assert_eq!(info.iana_updated.len(), 4);
}
