//! Round trips: every key type × every format × public/private, plus
//! re-export stability.

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_crypto::alg_from_jose;
use tokenator_keys::{
    DeclaredAlg, Key, KeyFormat, KeyOp, Kid, Visibility, export, export_set, import, to_public,
};

fn alg_for(kind: Kind) -> DeclaredAlg {
    let name = match kind {
        Kind::P256 => "ES256",
        Kind::P384 => "ES384",
        Kind::P521 => "ES512",
        Kind::Ed25519 => "Ed25519",
        Kind::Rsa2048 => "PS256",
        Kind::MlDsa44 => "ML-DSA-44",
        Kind::MlDsa65 => "ML-DSA-65",
        Kind::MlDsa87 => "ML-DSA-87",
    };
    DeclaredAlg::Known(alg_from_jose(name).unwrap())
}

/// A key with JOSE-flavoured metadata (text kid, `use`).
fn jose_key(kind: Kind) -> Key {
    let mut key = sample_key(kind);
    key.kid = Some(Kid::Text(format!("{kind:?}-kid")));
    key.alg = Some(alg_for(kind));
    key.key_use = Some("sig".into());
    key.key_ops = Some(vec![KeyOp::Sign, KeyOp::Verify]);
    key
}

/// A key with COSE-flavoured metadata (binary kid, no `use`).
fn cose_key(kind: Kind) -> Key {
    let mut key = sample_key(kind);
    key.kid = Some(Kid::Bytes(vec![0xde, 0xad, 0xbe, 0xef, kind as u8]));
    key.alg = Some(alg_for(kind));
    key.key_ops = Some(vec![KeyOp::Sign]);
    key
}

/// What an export with `visibility` should import back as, metadata
/// included (except `derived`, which is never serialized).
fn expected(key: &Key, visibility: Visibility) -> Key {
    let mut e = match visibility {
        Visibility::Private => key.clone(),
        Visibility::Public => to_public(key),
    };
    e.derived = false;
    e
}

fn is_jose(f: KeyFormat) -> bool {
    matches!(f, KeyFormat::Jwk | KeyFormat::JwkSet)
}

fn is_cose(f: KeyFormat) -> bool {
    matches!(f, KeyFormat::CoseKey | KeyFormat::CoseKeySet)
}

#[test]
fn every_kind_format_and_visibility() {
    for kind in ALL_KINDS {
        for vis in [Visibility::Public, Visibility::Private] {
            for fmt in formats_for(kind, vis) {
                let key = if is_cose(fmt) {
                    cose_key(kind)
                } else {
                    jose_key(kind)
                };
                let ctx = format!("{kind:?} {fmt:?} {vis:?}");
                let bytes = export(&key, fmt, vis).unwrap_or_else(|e| panic!("{ctx}: {e:?}"));

                let back = import_one(&bytes, None);
                let hinted = import_one(&bytes, Some(fmt));
                assert_eq!(back, hinted, "{ctx}: hint changes the result");

                let want = expected(&key, vis);
                assert_same_material(&back, &want, &ctx);
                assert_eq!(back.is_private(), vis == Visibility::Private, "{ctx}");
                assert_eq!(back.role, None, "{ctx}: role is never serialized");
                assert!(!back.derived, "{ctx}");

                if is_jose(fmt) || is_cose(fmt) {
                    // JOSE and COSE keep all of their own metadata.
                    assert_eq!(back, want, "{ctx}: import(export(k)) == k");
                } else {
                    // PEM has no metadata.
                    assert_eq!(back.kid, None, "{ctx}");
                    assert_eq!(back.alg, None, "{ctx}");
                    assert_eq!(back.key_use, None, "{ctx}");
                    assert_eq!(back.key_ops, None, "{ctx}");
                }

                // Exporting the imported key again gives the same bytes.
                assert_eq!(export(&back, fmt, vis).unwrap(), bytes, "{ctx}: re-export");
            }
        }
    }
}

#[test]
fn private_round_trip_keeps_the_secret() {
    for kind in ALL_KINDS {
        let key = sample_key(kind);
        let original = key.private_key().unwrap().to_material();
        for fmt in formats_for(kind, Visibility::Private) {
            let back = import_one(&export(&key, fmt, Visibility::Private).unwrap(), None);
            let got = back.private_key().unwrap().to_material();
            match (&original, &got) {
                // The expanded-only ML-DSA form loses the seed by design.
                (
                    tokenator_crypto::PrivateKeyMaterial::MlDsa { expanded: a, .. },
                    tokenator_crypto::PrivateKeyMaterial::MlDsa {
                        seed: None,
                        expanded: b,
                        ..
                    },
                ) => assert_eq!(a, b, "{kind:?} {fmt:?}"),
                _ => assert_eq!(got, original, "{kind:?} {fmt:?}"),
            }
        }
    }
}

#[test]
fn openssl_fixtures_round_trip_through_jwk_and_cose() {
    for kind in ALL_KINDS {
        let key = fixture_key(kind);
        for fmt in [KeyFormat::Jwk, KeyFormat::CoseKey] {
            for vis in [Visibility::Public, Visibility::Private] {
                let back = import_one(&export(&key, fmt, vis).unwrap(), None);
                assert_eq!(back, expected(&key, vis), "{kind:?} {fmt:?} {vis:?}");
            }
        }
    }
}

#[test]
fn sets_round_trip_every_kind_at_once() {
    let keys: Vec<Key> = ALL_KINDS.iter().map(|k| jose_key(*k)).collect();
    for fmt in [
        KeyFormat::JwkSet,
        KeyFormat::Pem(tokenator_keys::PemEncoding::Auto),
    ] {
        for vis in [Visibility::Public, Visibility::Private] {
            let bytes = export_set(&keys, fmt, vis).unwrap();
            let back = import(&bytes, None).unwrap();
            assert_eq!(back.len(), keys.len(), "{fmt:?} {vis:?}");
            for (b, k) in back.iter().zip(&keys) {
                assert_same_material(b, &expected(k, vis), &format!("{fmt:?} {vis:?}"));
                if is_jose(fmt) {
                    assert_eq!(b, &expected(k, vis));
                }
            }
        }
    }
    let keys: Vec<Key> = ALL_KINDS.iter().map(|k| cose_key(*k)).collect();
    for vis in [Visibility::Public, Visibility::Private] {
        let bytes = export_set(&keys, KeyFormat::CoseKeySet, vis).unwrap();
        let back = import(&bytes, None).unwrap();
        let want: Vec<Key> = keys.iter().map(|k| expected(k, vis)).collect();
        assert_eq!(back, want, "{vis:?}");
    }
}

#[test]
fn single_key_sets_have_set_shape() {
    let key = jose_key(Kind::P256);
    let jwks = export(&key, KeyFormat::JwkSet, Visibility::Public).unwrap();
    assert_eq!(json_member_names(&jwks), ["keys"]);
    let v: serde_json::Value = serde_json::from_slice(&jwks).unwrap();
    let jwk: serde_json::Value =
        serde_json::from_slice(&export(&key, KeyFormat::Jwk, Visibility::Public).unwrap()).unwrap();
    assert_eq!(v["keys"], serde_json::Value::Array(vec![jwk]));

    let key = cose_key(Kind::P256);
    let set = export(&key, KeyFormat::CoseKeySet, Visibility::Public).unwrap();
    let single = export(&key, KeyFormat::CoseKey, Visibility::Public).unwrap();
    assert_eq!(set[0], 0x81, "array of one");
    assert_eq!(&set[1..], &single[..]);
}

#[test]
fn empty_sets() {
    assert_eq!(
        export_set(&[], KeyFormat::JwkSet, Visibility::Public).unwrap(),
        br#"{"keys":[]}"#
    );
    assert_eq!(
        export_set(&[], KeyFormat::CoseKeySet, Visibility::Public).unwrap(),
        [0x80]
    );
    assert!(import(br#"{"keys":[]}"#, None).unwrap().is_empty());
    assert!(import(&[0x80], None).unwrap().is_empty());
}

#[test]
fn jwk_and_cose_key_exports_need_exactly_one_key() {
    let a = jose_key(Kind::P256);
    let b = jose_key(Kind::Ed25519);
    for fmt in [KeyFormat::Jwk, KeyFormat::CoseKey] {
        assert!(
            matches!(
                export_set(&[a.clone(), b.clone()], fmt, Visibility::Public),
                Err(tokenator_keys::KeyError::FormatNotApplicable { .. })
            ),
            "{fmt:?} with two keys"
        );
        assert!(
            matches!(
                export_set(&[], fmt, Visibility::Public),
                Err(tokenator_keys::KeyError::FormatNotApplicable { .. })
            ),
            "{fmt:?} with no keys"
        );
        assert_eq!(
            export_set(std::slice::from_ref(&a), fmt, Visibility::Public).unwrap(),
            export(&a, fmt, Visibility::Public).unwrap()
        );
    }
}

#[test]
fn private_export_of_public_key_fails_in_every_format() {
    for kind in ALL_KINDS {
        let key = to_public(&jose_key(kind));
        for fmt in [
            KeyFormat::Jwk,
            KeyFormat::JwkSet,
            KeyFormat::CoseKey,
            KeyFormat::CoseKeySet,
        ] {
            assert_eq!(
                export(&key, fmt, Visibility::Private).unwrap_err(),
                tokenator_keys::KeyError::NoPrivateKey,
                "{kind:?} {fmt:?}"
            );
        }
    }
}
