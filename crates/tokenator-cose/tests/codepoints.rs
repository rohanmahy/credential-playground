//! The crate's codepoints agree with the tokenator-registry snapshot.

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use tokenator_cose::codepoints::*;
use tokenator_registry::{EntryKind, Registry};

#[test]
fn sd_cwt_revision_matches_registry() {
    let reg = Registry::shared().unwrap();
    assert_eq!(reg.sd_cwt_revision(), SD_CWT_REVISION);
}

#[test]
fn tags_and_simple_values() {
    let reg = Registry::shared().unwrap();
    for (tag, name) in [
        (TAG_TO_BE_REDACTED, "to-be-redacted"),
        (TAG_REDACTED_ELEMENT, "redacted-claim-element"),
        (TAG_TO_BE_DECOY, "to-be-decoy"),
    ] {
        assert_eq!(
            reg.cbor_tag(tag).map(|e| e.name.as_str()),
            Some(name),
            "tag {tag}"
        );
    }
    assert_eq!(
        reg.cbor_simple(SIMPLE_REDACTED_KEYS)
            .map(|e| e.name.as_str()),
        Some("redacted_claim_keys")
    );
}

#[test]
fn header_labels() {
    let reg = Registry::shared().unwrap();
    for (label, name) in [
        (HDR_ALG, "alg"),
        (HDR_CRIT, "crit"),
        (HDR_CONTENT_TYPE, "content type"),
        (HDR_KID, "kid"),
        (HDR_KCWT, "kcwt"),
        (HDR_CWT_CLAIMS, "CWT Claims"),
        (HDR_TYP, "typ"),
        (HDR_SD_CLAIMS, "sd_claims"),
        (HDR_SD_ALG, "sd_alg"),
    ] {
        assert_eq!(
            reg.cose_header(label).map(|e| e.name.as_str()),
            Some(name),
            "header {label}"
        );
    }
}

#[test]
fn claim_keys_and_cnf_methods() {
    let reg = Registry::shared().unwrap();
    for (key, name) in [
        (CLAIM_ISS, "iss"),
        (CLAIM_SUB, "sub"),
        (CLAIM_AUD, "aud"),
        (CLAIM_EXP, "exp"),
        (CLAIM_NBF, "nbf"),
        (CLAIM_IAT, "iat"),
        (CLAIM_CTI, "cti"),
        (CLAIM_CNF, "cnf"),
        (CLAIM_VCT, "vct"),
        (CLAIM_CNONCE, "cnonce"),
    ] {
        assert_eq!(
            reg.cwt_claim(key).map(|e| e.name.as_str()),
            Some(name),
            "claim {key}"
        );
    }
    for (key, name) in [
        (CNF_COSE_KEY, "COSE_Key"),
        (CNF_ENCRYPTED_COSE_KEY, "Encrypted_COSE_Key"),
        (CNF_KID, "kid"),
        (CNF_CKT, "ckt"),
    ] {
        assert_eq!(
            reg.cwt_cnf_method(key).map(|e| e.name.as_str()),
            Some(name),
            "cnf {key}"
        );
    }
}

#[test]
fn sha2_algs_are_registered() {
    let reg = Registry::shared().unwrap();
    for (label, name) in [(-16, "SHA-256"), (-43, "SHA-384"), (-44, "SHA-512")] {
        assert_eq!(reg.cose_alg(label).map(|e| e.name.as_str()), Some(name));
    }
    assert!(reg.by_name(EntryKind::CoseAlg, "ES384").is_some());
}

#[test]
fn never_redacted_is_table_2() {
    assert_eq!(NEVER_REDACTED, [1, 3, 4, 5, 6, 7, 8, 39]);
    assert!(!NEVER_REDACTED.contains(&CLAIM_SUB));
}

#[test]
fn media_types() {
    assert_eq!((TYP_SD_CWT, MEDIA_SD_CWT), (293, "application/sd-cwt"));
    assert_eq!((TYP_KB_CWT, MEDIA_KB_CWT), (294, "application/kb+cwt"));
    assert_eq!((TAG_COSE_SIGN1, TAG_CWT), (18, 61));
}
