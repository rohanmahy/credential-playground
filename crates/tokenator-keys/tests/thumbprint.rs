//! Thumbprints (RFC 7638, RFC 9679, RFC 9964 §6) and `assign_kid`. The RFC
//! known answers are in `rfc_jwk.rs` and `rfc_cose.rs`; this file checks
//! the invariants.

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use proptest::prelude::*;
use tokenator_cbor::{EncodeMode, Item, Value, Width};
use tokenator_crypto::{Alg, HashAlg, digest};
use tokenator_keys::{
    CoseKey, DeclaredAlg, Jwk, Key, KeyError, KeyOp, Kid, KidSource, ThumbprintKind, Visibility,
    assign_kid, cose_thumbprint, jwk_thumbprint, thumbprint, to_cwk, to_jwk, to_public,
};

const RFC7638_THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
const RFC7638_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

const RFC9679_X: &str = "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d";
const RFC9679_Y: &str = "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c";
const RFC9679_THUMBPRINT: &str = "496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec";

const HASHES: [HashAlg; 3] = [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512];

fn rfc7638_members() -> Vec<(String, String)> {
    vec![
        ("kty".into(), r#""RSA""#.into()),
        ("n".into(), format!(r#""{RFC7638_N}""#)),
        ("e".into(), r#""AQAB""#.into()),
        ("alg".into(), r#""RS256""#.into()),
        ("kid".into(), r#""2011-04-29""#.into()),
    ]
}

fn object(members: &[(String, String)], sep: &str) -> String {
    let body: Vec<String> = members
        .iter()
        .map(|(k, v)| format!(r#""{k}":{sep}{v}"#))
        .collect();
    format!("{{{sep}{}{sep}}}", body.join(&format!(",{sep}")))
}

// -------------------------------------------------------- JWK invariants

proptest! {
    #[test]
    fn jwk_thumbprint_ignores_member_order(perm in Just(rfc7638_members()).prop_shuffle()) {
        let jwk = Jwk::parse(object(&perm, "").as_bytes()).unwrap();
        prop_assert_eq!(b64u(&jwk_thumbprint(&jwk, HashAlg::Sha256).unwrap()), RFC7638_THUMBPRINT);
    }

    #[test]
    fn jwk_thumbprint_ignores_extra_members_and_whitespace(
        extra in proptest::collection::btree_map("[a-z]{1,6}", "[a-zA-Z0-9 ]{0,10}", 0..5),
        ws in prop_oneof![Just(""), Just(" "), Just("\n  "), Just("\t")],
    ) {
        let mut members = rfc7638_members();
        for (k, v) in extra {
            if ["kty", "n", "e"].contains(&k.as_str()) {
                continue;
            }
            members.push((format!("x-{k}"), format!("\"{v}\"")));
        }
        let jwk = Jwk::parse(object(&members, ws).as_bytes()).unwrap();
        prop_assert_eq!(b64u(&jwk_thumbprint(&jwk, HashAlg::Sha256).unwrap()), RFC7638_THUMBPRINT);
        let key = tokenator_keys::from_jwk(&jwk).unwrap();
        prop_assert_eq!(
            b64u(&thumbprint(&key, ThumbprintKind::Jwk, HashAlg::Sha256)),
            RFC7638_THUMBPRINT
        );
    }
}

#[test]
fn jwk_thumbprint_hashes_the_canonical_members_exactly() {
    // Spelled-out RFC 7638 §3 computation for an EC key.
    let x = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
    let y = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";
    let jwk = Jwk::parse(
        format!(r#"{{"y":"{y}","use":"enc","x":"{x}","kid":"1","crv":"P-256","kty":"EC"}}"#)
            .as_bytes(),
    )
    .unwrap();
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    for h in HASHES {
        assert_eq!(
            jwk_thumbprint(&jwk, h).unwrap(),
            digest(h, canonical.as_bytes()),
            "{h:?}"
        );
    }
}

#[test]
fn jwk_thumbprint_needs_no_valid_material() {
    // Not a valid point, but the thumbprint is only a hash of members.
    let jwk = Jwk::parse(br#"{"kty":"EC","crv":"P-256","x":"AAAA","y":"BBBB"}"#).unwrap();
    assert_eq!(
        jwk_thumbprint(&jwk, HashAlg::Sha256).unwrap(),
        digest(
            HashAlg::Sha256,
            br#"{"crv":"P-256","kty":"EC","x":"AAAA","y":"BBBB"}"#
        )
    );
}

#[test]
fn jwk_thumbprint_errors() {
    let cases = [
        (
            r#"{"kty":"EC","crv":"P-256","x":"AAAA"}"#,
            KeyError::MissingParameter("y".into()),
        ),
        (
            r#"{"kty":"RSA","n":"AAAA"}"#,
            KeyError::MissingParameter("e".into()),
        ),
        (
            r#"{"kty":"AKP","pub":"AAAA"}"#,
            KeyError::MissingParameter("alg".into()),
        ),
        (
            r#"{"crv":"Ed25519","x":"AAAA"}"#,
            KeyError::MissingParameter("kty".into()),
        ),
        (
            r#"{"kty":"oct","k":"AAAA"}"#,
            KeyError::UnsupportedKeyType("oct".into()),
        ),
    ];
    for (json, expected) in cases {
        let jwk = Jwk::parse(json.as_bytes()).unwrap();
        assert_eq!(
            jwk_thumbprint(&jwk, HashAlg::Sha256).unwrap_err(),
            expected,
            "{json}"
        );
    }
    // A required member that is not a string.
    let jwk = Jwk::parse(br#"{"kty":"OKP","crv":"Ed25519","x":5}"#).unwrap();
    assert!(matches!(
        jwk_thumbprint(&jwk, HashAlg::Sha256).unwrap_err(),
        KeyError::InvalidParameter { name, .. } if name == "x"
    ));
}

// ------------------------------------------------------- COSE invariants

fn rfc9679_entries() -> Vec<(Item<'static>, Item<'static>)> {
    vec![
        (Item::int(1), Item::int(2)),
        (Item::int(-1), Item::int(1)),
        (Item::int(-2), Item::bytes(hex::decode(RFC9679_X).unwrap())),
        (Item::int(-3), Item::bytes(hex::decode(RFC9679_Y).unwrap())),
        (Item::int(2), Item::bytes(b"kid".to_vec())),
        (Item::int(3), Item::int(-7)),
    ]
}

proptest! {
    #[test]
    fn cose_thumbprint_ignores_order_extras_and_encoding(
        perm in Just(rfc9679_entries()).prop_shuffle(),
        widen in proptest::collection::vec(any::<bool>(), 6),
        extra in proptest::collection::btree_map(-1000i64..-10, any::<u8>(), 0..4),
    ) {
        let mut entries: Vec<_> = perm
            .into_iter()
            .zip(widen)
            .map(|((k, v), w)| if w { (k.with_width(Width::U32), v.with_width(Width::U16)) } else { (k, v) })
            .collect();
        for (label, v) in extra {
            entries.push((Item::int(label), Item::int(i64::from(v))));
        }
        let bytes = tokenator_cbor::encode(&Item::map(entries), EncodeMode::Preserve).unwrap();
        let cwk = CoseKey::decode(&bytes).unwrap();
        prop_assert_eq!(hex::encode(cose_thumbprint(&cwk, HashAlg::Sha256).unwrap()), RFC9679_THUMBPRINT);
    }
}

#[test]
fn cose_thumbprint_hashes_the_deterministic_map() {
    let item = Item::map(rfc9679_entries());
    let cwk =
        CoseKey::decode(&tokenator_cbor::encode(&item, EncodeMode::Preserve).unwrap()).unwrap();
    let mut canonical = vec![0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20];
    canonical.extend(hex::decode(RFC9679_X).unwrap());
    canonical.extend([0x22, 0x58, 0x20]);
    canonical.extend(hex::decode(RFC9679_Y).unwrap());
    for h in HASHES {
        assert_eq!(
            cose_thumbprint(&cwk, h).unwrap(),
            digest(h, &canonical),
            "{h:?}"
        );
    }
}

#[test]
fn cose_thumbprint_needs_no_valid_material_and_reports_missing() {
    let ok = CoseKey::decode(
        &tokenator_cbor::encode(
            &Item::map(vec![
                (Item::int(1), Item::int(1)),
                (Item::int(-1), Item::int(6)),
                (Item::int(-2), Item::bytes(vec![0; 3])),
            ]),
            EncodeMode::Preserve,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        cose_thumbprint(&ok, HashAlg::Sha256).unwrap(),
        digest(
            HashAlg::Sha256,
            &[0xa3, 0x01, 0x01, 0x20, 0x06, 0x21, 0x43, 0, 0, 0]
        )
    );
    let missing = CoseKey::decode(
        &tokenator_cbor::encode(
            &Item::map(vec![
                (Item::int(1), Item::int(7)),
                (Item::int(-1), Item::bytes(vec![1])),
            ]),
            EncodeMode::Preserve,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        cose_thumbprint(&missing, HashAlg::Sha256).unwrap_err(),
        KeyError::MissingParameter("3".into()),
        "AKP needs alg (RFC 9964 §6)"
    );
}

// --------------------------------------------------- Key-level invariants

#[test]
fn key_thumbprints_match_format_thumbprints() {
    for kind in ALL_KINDS {
        let key = sample_key(kind);
        for h in HASHES {
            let jkt = thumbprint(&key, ThumbprintKind::Jwk, h);
            let ckt = thumbprint(&key, ThumbprintKind::Cose, h);
            assert_eq!(jkt.len(), h.output_len());
            assert_eq!(ckt.len(), h.output_len());
            assert_ne!(jkt, ckt, "{kind:?}: RFC 9679 §5.5 says they differ");
            for vis in [Visibility::Public, Visibility::Private] {
                let jwk = to_jwk(&key, vis).unwrap();
                assert_eq!(jwk_thumbprint(&jwk, h).unwrap(), jkt, "{kind:?} {vis:?}");
                let cwk = to_cwk(&key, vis).unwrap();
                assert_eq!(cose_thumbprint(&cwk, h).unwrap(), ckt, "{kind:?} {vis:?}");
            }
        }
    }
}

#[test]
fn private_and_public_thumbprints_agree() {
    for kind in ALL_KINDS {
        let key = sample_key(kind);
        let public = to_public(&key);
        for tk in [ThumbprintKind::Jwk, ThumbprintKind::Cose] {
            assert_eq!(
                thumbprint(&key, tk, HashAlg::Sha256),
                thumbprint(&public, tk, HashAlg::Sha256),
                "{kind:?} {tk:?}"
            );
        }
    }
}

#[test]
fn metadata_does_not_change_thumbprints() {
    for kind in ALL_KINDS {
        let plain = sample_key(kind);
        let mut decorated = plain.clone();
        decorated.kid = Some(Kid::Text("x".into()));
        decorated.key_use = Some("sig".into());
        decorated.key_ops = Some(vec![KeyOp::Sign]);
        decorated.alg = Some(DeclaredAlg::Known(Alg::ES256)); // even a wrong one
        for tk in [ThumbprintKind::Jwk, ThumbprintKind::Cose] {
            assert_eq!(
                thumbprint(&plain, tk, HashAlg::Sha256),
                thumbprint(&decorated, tk, HashAlg::Sha256),
                "{kind:?} {tk:?}"
            );
        }
    }
}

#[test]
fn akp_thumbprint_uses_the_parameter_set_alg() {
    let key = sample_key(Kind::MlDsa65);
    let tokenator_crypto::PublicKeyMaterial::MlDsa { public, .. } = key.public_key().to_material()
    else {
        unreachable!()
    };
    let canonical = format!(
        r#"{{"alg":"ML-DSA-65","kty":"AKP","pub":"{}"}}"#,
        b64u(&public)
    );
    assert_eq!(
        thumbprint(&key, ThumbprintKind::Jwk, HashAlg::Sha256),
        digest(HashAlg::Sha256, canonical.as_bytes())
    );
}

#[test]
fn different_keys_have_different_thumbprints() {
    let a = sample_key(Kind::P256);
    let b = Key::from_private(
        tokenator_crypto::generate_from_seed(tokenator_crypto::KeySpec::P256, &[3; 32]).unwrap(),
    );
    assert_ne!(
        thumbprint(&a, ThumbprintKind::Jwk, HashAlg::Sha256),
        thumbprint(&b, ThumbprintKind::Jwk, HashAlg::Sha256)
    );
}

// --------------------------------------------------------------- assign_kid

#[test]
fn assign_kid_from_every_source() {
    let mut key = sample_key(Kind::Ed25519);
    key.kid = Some(Kid::Text("old".into()));

    assign_kid(&mut key, KidSource::JwkThumbprint(HashAlg::Sha256));
    let jkt = thumbprint(&key, ThumbprintKind::Jwk, HashAlg::Sha256);
    assert_eq!(key.kid, Some(Kid::Text(b64u(&jkt))));

    assign_kid(&mut key, KidSource::CoseThumbprint(HashAlg::Sha384));
    let ckt = thumbprint(&key, ThumbprintKind::Cose, HashAlg::Sha384);
    assert_eq!(key.kid, Some(Kid::Bytes(ckt)));

    assign_kid(&mut key, KidSource::Text("user".into()));
    assert_eq!(key.kid, Some(Kid::Text("user".into())));

    assign_kid(&mut key, KidSource::Bytes(vec![0, 1, 2]));
    assert_eq!(key.kid, Some(Kid::Bytes(vec![0, 1, 2])));
}

#[test]
fn assign_kid_reproduces_rfc9964_kids() {
    for p in ["44", "65", "87"] {
        let jose = import_fixture(&format!("rfc9964/ml-dsa-{p}-private.jwk.json"));
        let cose = import_fixture(&format!("rfc9964/ml-dsa-{p}-private.cbor"));
        // Swap: the JOSE key gets the COSE kid and vice versa.
        let mut j = jose.clone();
        assign_kid(&mut j, KidSource::CoseThumbprint(HashAlg::Sha256));
        assert_eq!(j.kid, cose.kid, "ML-DSA-{p}");
        let mut c = cose.clone();
        assign_kid(&mut c, KidSource::JwkThumbprint(HashAlg::Sha256));
        assert_eq!(c.kid, jose.kid, "ML-DSA-{p}");
    }
}

#[test]
fn assign_kid_rfc9679() {
    let mut key = import_fixture("rfc9679/ec2-p256.cbor");
    let original = key.kid.clone();
    key.kid = None;
    assign_kid(&mut key, KidSource::CoseThumbprint(HashAlg::Sha256));
    assert_eq!(key.kid, original);
}

#[test]
fn thumbprint_of_cbor_value_types() {
    // kty given with a non-preferred argument width still canonicalizes.
    let entries = vec![
        (
            Item::int(1),
            Item::new(Value::Uint(1)).with_width(Width::U64),
        ),
        (Item::int(-1), Item::int(6)),
        (Item::int(-2), Item::bytes(vec![7; 32])),
    ];
    let cwk = CoseKey::decode(
        &tokenator_cbor::encode(&Item::map(entries), EncodeMode::Preserve).unwrap(),
    )
    .unwrap();
    let mut canonical = vec![0xa3, 0x01, 0x01, 0x20, 0x06, 0x21, 0x58, 0x20];
    canonical.extend([7; 32]);
    assert_eq!(
        cose_thumbprint(&cwk, HashAlg::Sha256).unwrap(),
        digest(HashAlg::Sha256, &canonical)
    );
}
