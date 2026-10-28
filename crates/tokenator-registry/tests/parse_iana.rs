//! `parse_iana` over the IANA fixtures: spot-checks and normalisation rules.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::parsed;
use tokenator_registry::{
    Entry, EntryKind, Label, ParsedRegistry, RegistryError, RegistryId, Source, parse_iana,
};

fn get(p: &ParsedRegistry, kind: EntryKind, label: impl Into<Label>) -> &Entry {
    let label = label.into();
    let hits: Vec<_> = p
        .entries
        .iter()
        .filter(|e| e.kind == kind && e.label == label)
        .collect();
    assert!(!hits.is_empty(), "{kind:?} {label:?} missing");
    hits[0]
}

fn try_get(p: &ParsedRegistry, kind: EntryKind, label: impl Into<Label>) -> Option<&Entry> {
    let label = label.into();
    p.entries
        .iter()
        .find(|e| e.kind == kind && e.label == label)
}

fn key_param(p: &ParsedRegistry, kty: i64, label: i64) -> &Entry {
    p.entries
        .iter()
        .find(|e| {
            e.kind == EntryKind::CoseKeyTypeParam
                && e.key_type == Some(Label::Int(kty))
                && e.label == Label::Int(label)
        })
        .unwrap_or_else(|| panic!("key type param ({kty}, {label}) missing"))
}

// ---------------------------------------------------------------- COSE

#[test]
fn cose_metadata() {
    let p = parsed(RegistryId::Cose);
    assert_eq!(p.which, RegistryId::Cose);
    assert_eq!(p.updated.as_deref(), Some("2026-08-25"));
    assert!(
        p.entries.len() > 150,
        "only {} COSE entries",
        p.entries.len()
    );
}

#[test]
fn cose_algorithms() {
    let p = parsed(RegistryId::Cose);
    for (v, name) in [
        (-7, "ES256"),
        (-35, "ES384"),
        (-36, "ES512"),
        (-8, "EdDSA"),
        (-19, "Ed25519"),
        (-9, "ESP256"),
        (-37, "PS256"),
        (-38, "PS384"),
        (-39, "PS512"),
        (-257, "RS256"),
        (-258, "RS384"),
        (-259, "RS512"),
        (-48, "ML-DSA-44"),
        (-49, "ML-DSA-65"),
        (-50, "ML-DSA-87"),
    ] {
        let e = get(&p, EntryKind::CoseAlg, v);
        assert_eq!(e.name, name, "alg {v}");
        assert_eq!(e.source, Source::Iana);
    }
    assert_eq!(
        get(&p, EntryKind::CoseAlg, -7).description,
        "ECDSA w/ SHA-256"
    );
}

#[test]
fn cose_header_parameters() {
    let p = parsed(RegistryId::Cose);
    for (l, name) in [
        (1, "alg"),
        (2, "crit"),
        (3, "content type"),
        (4, "kid"),
        (5, "IV"),
        (13, "kcwt"),
        (15, "CWT Claims"),
        (16, "typ"),
        (17, "sd_claims"),
        (33, "x5chain"),
        (34, "x5t"),
        (170, "sd_alg"),
    ] {
        assert_eq!(get(&p, EntryKind::CoseHeader, l).name, name, "header {l}");
    }
    let kid = get(&p, EntryKind::CoseHeader, 4);
    assert_eq!(kid.value_type.as_deref(), Some("bstr"));
    assert_eq!(kid.description, "Key identifier");
    assert_eq!(
        get(&p, EntryKind::CoseHeader, 33).value_type.as_deref(),
        Some("COSE_X509")
    );
}

#[test]
fn cose_header_algorithm_parameters_are_separate_kind() {
    let p = parsed(RegistryId::Cose);
    let e = p
        .entries
        .iter()
        .find(|e| e.name == "x5chain-sender")
        .expect("x5chain-sender");
    assert_eq!(e.kind, EntryKind::CoseHeaderAlgParam);
    assert!(matches!(e.label, Label::Int(n) if n < 0));
}

#[test]
fn cose_key_types_curves_and_params() {
    let p = parsed(RegistryId::Cose);
    for (v, name) in [
        (1, "OKP"),
        (2, "EC2"),
        (3, "RSA"),
        (4, "Symmetric"),
        (7, "AKP"),
    ] {
        assert_eq!(get(&p, EntryKind::CoseKty, v).name, name, "kty {v}");
    }
    for (v, name) in [
        (1, "P-256"),
        (2, "P-384"),
        (3, "P-521"),
        (6, "Ed25519"),
        (7, "Ed448"),
    ] {
        assert_eq!(get(&p, EntryKind::CoseCrv, v).name, name, "crv {v}");
    }
    for (l, name) in [(1, "kty"), (2, "kid"), (3, "alg"), (4, "key_ops")] {
        assert_eq!(
            get(&p, EntryKind::CoseKeyParam, l).name,
            name,
            "key param {l}"
        );
    }
    assert_eq!(
        get(&p, EntryKind::CoseKeyParam, 1).value_type.as_deref(),
        Some("tstr / int")
    );
    assert_eq!(key_param(&p, 2, -1).name, "crv");
    assert_eq!(key_param(&p, 2, -2).name, "x");
    assert_eq!(key_param(&p, 2, -3).name, "y");
    assert_eq!(key_param(&p, 1, -1).name, "crv");
    assert_eq!(key_param(&p, 3, -1).name, "n");
    assert_eq!(key_param(&p, 7, -1).name, "pub");
    assert_eq!(key_param(&p, 7, -2).name, "priv");
    assert_eq!(key_param(&p, 2, -2).value_type.as_deref(), Some("bstr"));
}

#[test]
fn cose_ranges_and_placeholders_are_skipped() {
    let p = parsed(RegistryId::Cose);
    for e in &p.entries {
        assert!(!e.name.starts_with("Unassigned"), "{e:?}");
        assert!(!e.name.starts_with("Reserved"), "{e:?}");
        assert!(!e.name.starts_with("delegated"), "{e:?}");
    }
    // 18-21 is an Unassigned range; 0 is a Reserved kty.
    assert!(try_get(&p, EntryKind::CoseHeader, 18).is_none());
    assert!(try_get(&p, EntryKind::CoseKty, 0).is_none());
}

#[test]
fn trailing_parentheticals_are_stripped_and_temporary_flagged() {
    let p = parsed(RegistryId::Cose);
    let typ = get(&p, EntryKind::CoseHeader, 16);
    assert_eq!(typ.name, "typ");
    assert!(!typ.temporary);
    for l in [17, 170, 171, 172] {
        let e = get(&p, EntryKind::CoseHeader, l);
        assert!(e.temporary, "header {l} should be temporary");
        assert!(!e.name.contains('('), "{}", e.name);
        assert!(e.name.starts_with("sd_"), "{}", e.name);
    }
    assert!(!get(&p, EntryKind::CoseHeader, 4).temporary);
}

#[test]
fn descriptions_are_flattened_plain_text() {
    let p = parsed(RegistryId::Cose);
    let kcwt = get(&p, EntryKind::CoseHeader, 13);
    assert!(kcwt.description.contains("8392"), "{}", kcwt.description);
    assert!(kcwt.description.starts_with("A CBOR Web Token (CWT)"));
    for e in &p.entries {
        assert!(!e.description.contains('<'), "markup left in {e:?}");
        assert!(!e.description.contains('\n'), "newline left in {e:?}");
        assert!(
            !e.description.contains("  "),
            "whitespace not collapsed in {e:?}"
        );
    }
    let ed = get(&p, EntryKind::CoseAlg, -19);
    assert!(ed.description.contains("8032"), "{}", ed.description);
}

#[test]
fn rfc_and_draft_references() {
    let p = parsed(RegistryId::Cose);
    let kid = get(&p, EntryKind::CoseHeader, 4);
    assert_eq!(kid.reference.len(), 1);
    assert_eq!(kid.reference[0].text, "RFC 9052");
    assert_eq!(
        kid.reference[0].url.as_deref(),
        Some("https://www.rfc-editor.org/rfc/rfc9052")
    );
    let es256 = get(&p, EntryKind::CoseAlg, -7);
    assert_eq!(es256.reference.len(), 2, "{:?}", es256.reference);
    let typ = get(&p, EntryKind::CoseHeader, 16);
    assert_eq!(typ.reference[0].text, "RFC 9596, Section 2");
    assert_eq!(
        typ.reference[0].url.as_deref(),
        Some("https://www.rfc-editor.org/rfc/rfc9596#section-2")
    );
    let sd = get(&p, EntryKind::CoseHeader, 17);
    let url = sd.reference[0].url.as_deref().unwrap();
    assert!(
        url.starts_with("https://datatracker.ietf.org/doc/"),
        "{url}"
    );
    assert!(url.contains("draft-ietf-spice-sd-cwt"), "{url}");
    assert!(sd.reference[0].text.contains("spice-sd-cwt"));
    // xrefs inside <description> are not references
    let kcwt = get(&p, EntryKind::CoseHeader, 13);
    assert!(kcwt.reference.iter().all(|r| !r.text.contains("8392")));
}

// ---------------------------------------------------------------- CWT

#[test]
fn cwt_claims_with_jwt_names() {
    let p = parsed(RegistryId::Cwt);
    assert_eq!(p.updated.as_deref(), Some("2026-07-20"));
    for (k, name, jwt) in [
        (1, "iss", "iss"),
        (2, "sub", "sub"),
        (3, "aud", "aud"),
        (4, "exp", "exp"),
        (5, "nbf", "nbf"),
        (6, "iat", "iat"),
        (7, "cti", "jti"),
        (8, "cnf", "cnf"),
        (9, "scope", "scope"),
        (10, "Nonce", "eat_nonce"),
        (-260, "hcert", "hcert"),
    ] {
        let e = get(&p, EntryKind::CwtClaim, k);
        assert_eq!(e.name, name, "claim {k}");
        assert_eq!(e.jwt_name.as_deref(), Some(jwt), "claim {k}");
    }
    assert_eq!(
        get(&p, EntryKind::CwtClaim, 1).value_type.as_deref(),
        Some("text string")
    );
    assert_eq!(get(&p, EntryKind::CwtClaim, 8).description, "Confirmation");
}

#[test]
fn cwt_temporary_vct_and_na_jwt_name() {
    let p = parsed(RegistryId::Cwt);
    let vct = get(&p, EntryKind::CwtClaim, 11);
    assert_eq!(vct.name, "vct");
    assert!(vct.temporary);
    assert_eq!(vct.jwt_name.as_deref(), Some("vct"));
    // JWT column "N/A" means no JWT counterpart.
    let gp = get(&p, EntryKind::CwtClaim, -261);
    assert_eq!(gp.name, "globalplatform_component");
    assert_eq!(gp.jwt_name, None);
}

#[test]
fn cwt_ranges_skipped() {
    let p = parsed(RegistryId::Cwt);
    assert!(
        try_get(&p, EntryKind::CwtClaim, 0).is_none(),
        "0 is Reserved"
    );
    assert!(
        try_get(&p, EntryKind::CwtClaim, 12).is_none(),
        "12 to 37 Unassigned"
    );
    assert!(p.entries.iter().all(|e| matches!(e.label, Label::Int(_))));
}

#[test]
fn cwt_uri_reference() {
    let p = parsed(RegistryId::Cwt);
    let hcert = get(&p, EntryKind::CwtClaim, -260);
    let r = &hcert.reference[0];
    assert_eq!(r.text, "Electronic Health Certificate Specification");
    assert!(
        r.url
            .as_deref()
            .unwrap()
            .starts_with("https://github.com/ehn-digital-green-development/")
    );
}

#[test]
fn cwt_confirmation_methods() {
    let p = parsed(RegistryId::Cwt);
    for (k, name, jwt) in [
        (1, "COSE_Key", "jwk"),
        (2, "Encrypted_COSE_Key", "jwe"),
        (3, "kid", "kid"),
    ] {
        let e = get(&p, EntryKind::CwtCnfMethod, k);
        assert_eq!(e.name, name);
        assert_eq!(e.jwt_name.as_deref(), Some(jwt));
    }
    let e = get(&p, EntryKind::CwtCnfMethod, 2);
    assert!(!e.value_type.as_deref().unwrap().contains('\n'));
}

// ---------------------------------------------------------------- JWT

#[test]
fn jwt_claims() {
    let p = parsed(RegistryId::Jwt);
    assert_eq!(p.updated.as_deref(), Some("2026-07-20"));
    for (name, desc) in [
        ("iss", "Issuer"),
        ("sub", "Subject"),
        ("aud", "Audience"),
        ("exp", "Expiration Time"),
        ("jti", "JWT ID"),
        ("cnf", "Confirmation"),
        ("_sd", "Digests of Disclosures for object properties"),
        ("...", "Digest of the Disclosure for an array element"),
        (
            "_sd_alg",
            "Hash algorithm used to generate Disclosure digests and digest over presentation",
        ),
        (
            "sd_hash",
            "Digest of the SD-JWT to which the KB-JWT is tied",
        ),
    ] {
        let e = get(&p, EntryKind::JwtClaim, name);
        assert_eq!(e.name, name);
        assert_eq!(e.description, desc, "{name}");
    }
    let iss = get(&p, EntryKind::JwtClaim, "iss");
    assert_eq!(iss.reference[0].text, "RFC 7519, Section 4.1.1");
    assert_eq!(
        iss.reference[0].url.as_deref(),
        Some("https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1")
    );
    assert!(
        try_get(&p, EntryKind::JwtClaim, "vct").is_none(),
        "vct is not a registered JWT claim"
    );
    assert!(p.entries.iter().all(|e| matches!(e.label, Label::Text(_))));
}

#[test]
fn jwt_confirmation_methods() {
    let p = parsed(RegistryId::Jwt);
    for name in ["jwk", "jwe", "kid", "jku", "jkt"] {
        assert_eq!(get(&p, EntryKind::JwtCnfMethod, name).name, name);
    }
    assert_eq!(
        get(&p, EntryKind::JwtCnfMethod, "jkt").description,
        "JWK SHA-256 Thumbprint"
    );
}

// ---------------------------------------------------------------- JOSE

#[test]
fn jose_headers_deduplicated_jws_first() {
    let p = parsed(RegistryId::Jose);
    assert_eq!(p.updated.as_deref(), Some("2026-09-29"));
    for (name, desc) in [
        ("alg", "Algorithm"),
        ("jwk", "JSON Web Key"),
        ("kid", "Key ID"),
        ("x5c", "X.509 Certificate Chain"),
        ("x5t#S256", "X.509 Certificate SHA-256 Thumbprint"),
        ("typ", "Type"),
        ("cty", "Content Type"),
        ("crit", "Critical"),
    ] {
        let hits: Vec<_> = p
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::JoseHeader && e.label == Label::from(name))
            .collect();
        assert_eq!(hits.len(), 1, "{name} should appear once");
        assert_eq!(hits[0].description, desc, "{name}");
    }
    assert_eq!(
        get(&p, EntryKind::JoseHeader, "typ").reference[0].text,
        "RFC 7515, Section 4.1.9"
    );
    // JWE-only parameter is still present
    assert!(try_get(&p, EntryKind::JoseHeader, "enc").is_some());
}

#[test]
fn jose_algorithms() {
    let p = parsed(RegistryId::Jose);
    for name in [
        "HS256",
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
        "Ed25519",
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        "none",
    ] {
        assert_eq!(get(&p, EntryKind::JoseAlg, name).name, name);
    }
    assert_eq!(
        get(&p, EntryKind::JoseAlg, "ES256").description,
        "ECDSA using P-256 and SHA-256"
    );
}

#[test]
fn jwk_types_curves_params() {
    let p = parsed(RegistryId::Jose);
    for (name, desc) in [
        ("EC", "Elliptic Curve"),
        ("RSA", "RSA"),
        ("oct", "Octet sequence"),
        ("OKP", "Octet string key pairs"),
        ("AKP", "Algorithm Key Pair"),
    ] {
        assert_eq!(get(&p, EntryKind::JwkKty, name).description, desc, "{name}");
    }
    assert_eq!(
        get(&p, EntryKind::JwkCrv, "P-256").description,
        "P-256 Curve"
    );
    assert!(try_get(&p, EntryKind::JwkCrv, "Ed25519").is_some());
    for name in [
        "kty", "use", "kid", "x5c", "crv", "x", "y", "d", "n", "e", "pub", "priv",
    ] {
        let hits = p
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::JwkParam && e.label == Label::from(name))
            .count();
        assert_eq!(hits, 1, "JWK param {name} should appear once");
    }
    let x = get(&p, EntryKind::JwkParam, "x");
    assert_eq!(
        x.key_type,
        Some(Label::from("EC")),
        "first (EC) record wins"
    );
    assert_eq!(
        get(&p, EntryKind::JwkParam, "kty").key_type,
        Some(Label::from("*"))
    );
}

// ---------------------------------------------------------------- general

#[test]
fn every_entry_is_iana_and_kind_belongs_to_registry() {
    for id in RegistryId::ALL {
        let p = parsed(id);
        assert!(!p.entries.is_empty(), "{id:?}");
        for e in &p.entries {
            assert_eq!(e.source, Source::Iana, "{e:?}");
            assert!(id.kinds().contains(&e.kind), "{id:?} produced {e:?}");
            assert!(!e.name.is_empty(), "{e:?}");
            assert_eq!(e.name, e.name.trim(), "{e:?}");
        }
    }
}

#[test]
fn every_kind_of_each_registry_is_populated() {
    for id in RegistryId::ALL {
        let p = parsed(id);
        for kind in id.kinds() {
            assert!(
                p.entries.iter().any(|e| e.kind == *kind),
                "{id:?} has no {kind:?}"
            );
        }
    }
}

#[test]
fn no_duplicate_identities() {
    for id in RegistryId::ALL {
        let p = parsed(id);
        let mut seen = std::collections::HashSet::new();
        for e in &p.entries {
            assert!(
                seen.insert((
                    e.kind,
                    e.key_type
                        .clone()
                        .filter(|_| e.kind == EntryKind::CoseKeyTypeParam),
                    e.label.clone()
                )),
                "duplicate {e:?}"
            );
        }
    }
}

#[test]
fn wrong_registry_is_an_error() {
    let err = parse_iana(common::COSE_XML, RegistryId::Jwt).unwrap_err();
    assert_eq!(
        err,
        RegistryError::WrongRegistry {
            expected: RegistryId::Jwt,
            found: "cose".into()
        }
    );
    assert!(matches!(
        parse_iana(common::CWT_XML, RegistryId::Jose),
        Err(RegistryError::WrongRegistry { .. })
    ));
}

#[test]
fn parse_is_deterministic() {
    for id in RegistryId::ALL {
        assert_eq!(parsed(id), parsed(id));
    }
}
