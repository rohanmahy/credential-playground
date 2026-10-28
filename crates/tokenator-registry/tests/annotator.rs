//! `Annotator` output for JOSE and COSE contexts.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::registry;
use tokenator_registry::{Annotator, Context, EntryKind, Family, Label};

fn int(v: i64) -> Label {
    Label::Int(v)
}

fn text(v: &str) -> Label {
    Label::from(v)
}

#[test]
fn cose_header_names() {
    let r = registry();
    for ctx in [Context::ProtectedHeader, Context::UnprotectedHeader] {
        assert_eq!(r.display_name(Family::Cose, &ctx, &int(1)), Some("alg"));
        assert_eq!(r.display_name(Family::Cose, &ctx, &int(4)), Some("kid"));
        assert_eq!(r.display_name(Family::Cose, &ctx, &int(16)), Some("typ"));
        assert_eq!(
            r.display_name(Family::Cose, &ctx, &int(17)),
            Some("sd_claims")
        );
        assert_eq!(
            r.display_name(Family::Cose, &ctx, &int(33)),
            Some("x5chain")
        );
        assert_eq!(r.display_name(Family::Cose, &ctx, &int(18)), None);
    }
}

#[test]
fn cose_claim_names() {
    let r = registry();
    let c = Context::Claims;
    assert_eq!(r.display_name(Family::Cose, &c, &int(1)), Some("iss"));
    assert_eq!(r.display_name(Family::Cose, &c, &int(7)), Some("cti"));
    assert_eq!(r.display_name(Family::Cose, &c, &int(8)), Some("cnf"));
    assert_eq!(r.display_name(Family::Cose, &c, &int(11)), Some("vct"));
    assert_eq!(r.display_name(Family::Cose, &c, &int(0)), None);
    assert_eq!(r.display_name(Family::Cose, &c, &text("iss")), None);
}

#[test]
fn context_selects_the_registry() {
    // label 1 means alg in a header, iss in claims, kty in a key, COSE_Key in cnf
    let r = registry();
    assert_eq!(
        r.display_name(Family::Cose, &Context::ProtectedHeader, &int(1)),
        Some("alg")
    );
    assert_eq!(
        r.display_name(Family::Cose, &Context::Claims, &int(1)),
        Some("iss")
    );
    assert_eq!(
        r.display_name(Family::Cose, &Context::Key { kty: None }, &int(1)),
        Some("kty")
    );
    assert_eq!(
        r.display_name(Family::Cose, &Context::Cnf, &int(1)),
        Some("COSE_Key")
    );
    let e = r.entry(Family::Cose, &Context::Claims, &int(1)).unwrap();
    assert_eq!(e.kind, EntryKind::CwtClaim);
    let e = r
        .entry(Family::Cose, &Context::ProtectedHeader, &int(1))
        .unwrap();
    assert_eq!(e.kind, EntryKind::CoseHeader);
}

#[test]
fn cose_key_names_depend_on_kty() {
    let r = registry();
    let ec2 = Context::Key { kty: Some(int(2)) };
    let akp = Context::Key { kty: Some(int(7)) };
    let rsa = Context::Key { kty: Some(int(3)) };
    assert_eq!(r.display_name(Family::Cose, &ec2, &int(-1)), Some("crv"));
    assert_eq!(r.display_name(Family::Cose, &ec2, &int(-2)), Some("x"));
    assert_eq!(r.display_name(Family::Cose, &ec2, &int(-4)), Some("d"));
    assert_eq!(r.display_name(Family::Cose, &akp, &int(-1)), Some("pub"));
    assert_eq!(r.display_name(Family::Cose, &rsa, &int(-1)), Some("n"));
    assert_eq!(r.display_name(Family::Cose, &ec2, &int(3)), Some("alg"));
    assert_eq!(
        r.display_name(Family::Cose, &Context::Key { kty: None }, &int(-1)),
        None
    );
}

#[test]
fn jose_uses_descriptions() {
    let r = registry();
    assert_eq!(
        r.display_name(Family::Jose, &Context::ProtectedHeader, &text("alg")),
        Some("Algorithm")
    );
    assert_eq!(
        r.display_name(Family::Jose, &Context::ProtectedHeader, &text("typ")),
        Some("Type")
    );
    assert_eq!(
        r.display_name(Family::Jose, &Context::ProtectedHeader, &text("x5c")),
        Some("X.509 Certificate Chain")
    );
    assert_eq!(
        r.display_name(Family::Jose, &Context::Claims, &text("iss")),
        Some("Issuer")
    );
    assert_eq!(
        r.display_name(Family::Jose, &Context::Claims, &text("jti")),
        Some("JWT ID")
    );
    assert_eq!(
        r.display_name(Family::Jose, &Context::Claims, &text("_sd")),
        Some("Digests of Disclosures for object properties")
    );
    assert_eq!(
        r.display_name(
            Family::Jose,
            &Context::Key {
                kty: Some(text("EC"))
            },
            &text("kty")
        ),
        Some("Key Type")
    );
    assert_eq!(
        r.display_name(Family::Jose, &Context::Cnf, &text("jkt")),
        Some("JWK SHA-256 Thumbprint")
    );
    assert_eq!(
        r.display_name(Family::Jose, &Context::Claims, &text("nope")),
        None
    );
    assert_eq!(
        r.display_name(Family::Jose, &Context::Claims, &int(1)),
        None
    );
    let e = r
        .entry(Family::Jose, &Context::Claims, &text("iss"))
        .unwrap();
    assert_eq!(e.kind, EntryKind::JwtClaim);
}

#[test]
fn cose_value_names() {
    let r = registry();
    let h = Context::ProtectedHeader;
    assert_eq!(
        r.value_name(Family::Cose, &h, &int(1), &int(-7)),
        Some("ES256")
    );
    assert_eq!(
        r.value_name(Family::Cose, &h, &int(1), &int(-48)),
        Some("ML-DSA-44")
    );
    assert_eq!(r.value_name(Family::Cose, &h, &int(1), &int(-12345)), None);
    // kid values are not registered
    assert_eq!(r.value_name(Family::Cose, &h, &int(4), &int(1)), None);
    // sd_alg values come from the COSE algorithms registry too
    assert_eq!(
        r.value_name(Family::Cose, &h, &int(170), &int(-16)),
        Some("SHA-256")
    );
    let k = Context::Key { kty: Some(int(2)) };
    assert_eq!(
        r.value_name(Family::Cose, &k, &int(1), &int(2)),
        Some("EC2")
    );
    assert_eq!(
        r.value_name(Family::Cose, &k, &int(3), &int(-7)),
        Some("ES256")
    );
    assert_eq!(
        r.value_name(Family::Cose, &k, &int(-1), &int(1)),
        Some("P-256")
    );
    let okp = Context::Key { kty: Some(int(1)) };
    assert_eq!(
        r.value_name(Family::Cose, &okp, &int(-1), &int(6)),
        Some("Ed25519")
    );
    // RSA -1 is n, not crv: no value annotation
    let rsa = Context::Key { kty: Some(int(3)) };
    assert_eq!(r.value_name(Family::Cose, &rsa, &int(-1), &int(1)), None);
    // claims values are not annotated
    assert_eq!(
        r.value_name(Family::Cose, &Context::Claims, &int(1), &int(-7)),
        None
    );
}

#[test]
fn jose_value_names() {
    let r = registry();
    let h = Context::ProtectedHeader;
    assert_eq!(
        r.value_name(Family::Jose, &h, &text("alg"), &text("ES256")),
        Some("ECDSA using P-256 and SHA-256")
    );
    assert_eq!(
        r.value_name(Family::Jose, &h, &text("alg"), &text("XX999")),
        None
    );
    let k = Context::Key {
        kty: Some(text("EC")),
    };
    assert_eq!(
        r.value_name(Family::Jose, &k, &text("kty"), &text("EC")),
        Some("Elliptic Curve")
    );
    assert_eq!(
        r.value_name(Family::Jose, &k, &text("crv"), &text("P-256")),
        Some("P-256 Curve")
    );
    let e = r
        .value_entry(Family::Jose, &h, &text("alg"), &text("EdDSA"))
        .unwrap();
    assert_eq!(e.kind, EntryKind::JoseAlg);
}

#[test]
fn works_through_dyn_annotator() {
    let r = registry();
    let a: &dyn Annotator = &r;
    assert_eq!(
        a.display_name(Family::Cose, &Context::Claims, &int(4)),
        Some("exp")
    );
    assert_eq!(
        a.value_name(Family::Cose, &Context::ProtectedHeader, &int(1), &int(-8)),
        Some("EdDSA")
    );
    assert_eq!(
        a.display_name(Family::Jose, &Context::Claims, &text("exp")),
        Some("Expiration Time")
    );
}
