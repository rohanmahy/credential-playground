//! The `Key` model: constructors, accessors, equality, and `to_public`.

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_crypto::{Alg, KeySpec, KeyType, generate_from_seed};
use tokenator_keys::{
    DeclaredAlg, Extra, Key, KeyError, KeyOp, Kid, Role, Visibility, to_cwk, to_jwk, to_public,
};

fn decorated(kind: Kind) -> Key {
    let mut key = sample_key(kind);
    key.role = Some(Role::Issuer);
    key.kid = Some(Kid::Text("k1".into()));
    key.alg = Some(DeclaredAlg::UnknownJose("whatever".into()));
    key.key_use = Some("sig".into());
    key.key_ops = Some(vec![KeyOp::Sign]);
    key.extras = vec![Extra::Jose {
        name: "x-note".into(),
        json: "\"hi\"".into(),
    }];
    key
}

#[test]
fn constructors_and_accessors() {
    for kind in ALL_KINDS {
        let key = sample_key(kind);
        assert!(key.is_private(), "{kind:?}");
        assert!(key.private_key().is_some());
        assert_eq!(key.role, None);
        assert_eq!(key.kid, None);
        assert_eq!(key.alg, None);
        assert_eq!(key.key_use, None);
        assert_eq!(key.key_ops, None);
        assert!(key.extras.is_empty());
        assert!(!key.derived);
        let expected_type = match kind {
            k if k.is_ec() => KeyType::Ec,
            Kind::Ed25519 => KeyType::Okp,
            Kind::Rsa2048 => KeyType::Rsa,
            _ => KeyType::Akp,
        };
        assert_eq!(key.key_type(), expected_type);
        assert_eq!(
            key.public_key(),
            key.private_key().unwrap().public_key(),
            "{kind:?}"
        );

        let public = Key::from_public(key.public_key());
        assert!(!public.is_private());
        assert!(public.private_key().is_none());
        assert_eq!(public.key_type(), expected_type);
        assert_eq!(public.public_key(), key.public_key());
    }
}

#[test]
fn to_public_keeps_metadata_and_marks_derived() {
    for kind in ALL_KINDS {
        let key = decorated(kind);
        let public = to_public(&key);
        assert!(!public.is_private(), "{kind:?}");
        assert!(public.derived);
        assert_eq!(public.public_key(), key.public_key());
        assert_eq!(public.role, key.role);
        assert_eq!(public.kid, key.kid);
        assert_eq!(public.alg, key.alg);
        assert_eq!(public.key_use, key.key_use);
        assert_eq!(public.key_ops, key.key_ops);
        assert_eq!(public.extras, key.extras);
        // Original untouched.
        assert!(key.is_private());
        assert!(!key.derived);
    }
}

#[test]
fn to_public_of_public_key_is_unchanged() {
    for kind in ALL_KINDS {
        let mut key = Key::from_public(sample_key(kind).public_key());
        key.kid = Some(Kid::Bytes(vec![7]));
        let again = to_public(&key);
        assert_eq!(again, key, "{kind:?}");
        assert!(!again.derived);
        // Idempotent from a private key as well.
        let derived = to_public(&decorated(kind));
        assert_eq!(to_public(&derived), derived);
    }
}

#[test]
fn derived_public_key_cannot_export_privately() {
    for kind in ALL_KINDS {
        let public = to_public(&sample_key(kind));
        assert_eq!(
            to_jwk(&public, Visibility::Private).unwrap_err(),
            KeyError::NoPrivateKey
        );
        assert_eq!(
            to_cwk(&public, Visibility::Private).unwrap_err(),
            KeyError::NoPrivateKey
        );
        assert!(to_jwk(&public, Visibility::Public).is_ok());
    }
}

#[test]
fn public_export_of_private_key_equals_export_of_its_public_half() {
    for kind in ALL_KINDS {
        let key = decorated(kind);
        assert_eq!(
            to_jwk(&key, Visibility::Public).unwrap().to_json(),
            to_jwk(&to_public(&key), Visibility::Public)
                .unwrap()
                .to_json(),
            "{kind:?}"
        );
        assert_eq!(
            to_cwk(&key, Visibility::Public).unwrap(),
            to_cwk(&to_public(&key), Visibility::Public).unwrap()
        );
    }
}

#[test]
fn same_material_ignores_metadata_but_not_visibility() {
    let a = sample_key(Kind::P256);
    let b = decorated(Kind::P256);
    assert!(a.same_material(&b));
    assert!(b.same_material(&a));
    assert!(!a.same_material(&to_public(&a)), "private vs public");
    assert!(to_public(&a).same_material(&to_public(&b)));

    let other = Key::from_private(generate_from_seed(KeySpec::P256, &[1; 32]).unwrap());
    assert!(!a.same_material(&other));
    let ed = sample_key(Kind::Ed25519);
    assert!(!a.same_material(&ed), "different key types");
}

#[test]
fn equality_covers_every_field() {
    let base = decorated(Kind::Ed25519);
    assert_eq!(base, base.clone());

    let mut k = base.clone();
    k.role = Some(Role::Holder);
    assert_ne!(k, base, "role");
    let mut k = base.clone();
    k.kid = Some(Kid::Bytes(b"k1".to_vec()));
    assert_ne!(k, base, "kid variant matters");
    let mut k = base.clone();
    k.alg = Some(DeclaredAlg::Known(Alg::EdDSA));
    assert_ne!(k, base, "alg");
    let mut k = base.clone();
    k.key_use = None;
    assert_ne!(k, base, "use");
    let mut k = base.clone();
    k.key_ops = Some(vec![KeyOp::Verify]);
    assert_ne!(k, base, "key_ops");
    let mut k = base.clone();
    k.extras.clear();
    assert_ne!(k, base, "extras");
    let mut k = base.clone();
    k.derived = true;
    assert_ne!(k, base, "derived");
    let mut k = Key::from_private(generate_from_seed(KeySpec::Ed25519, &[9; 32]).unwrap());
    k.role = base.role;
    k.kid = base.kid.clone();
    k.alg = base.alg.clone();
    k.key_use = base.key_use.clone();
    k.key_ops = base.key_ops.clone();
    k.extras = base.extras.clone();
    assert_ne!(k, base, "material");
}

#[test]
fn ml_dsa_seed_and_expanded_forms_are_the_same_material() {
    let seed = import_fixture("openssl/mldsa65-seed.pem");
    let expanded = import_fixture("openssl/mldsa65-expanded.pem");
    assert!(seed.same_material(&expanded));
    assert_eq!(seed, expanded, "no metadata either way");
}

#[test]
fn debug_does_not_print_secrets() {
    let key = import_fixture("rfc8037/ed25519-private.json");
    let debug = format!("{key:?}");
    // RFC 8037 d = 9d61b19d...; neither hex nor decimal bytes may appear.
    assert!(!debug.to_lowercase().contains("9d61b19d"), "{debug}");
    assert!(!debug.contains("157, 97, 177"), "{debug}");
}
