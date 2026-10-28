//! `params`, `params_from_jwk`, and `params_from_cwk`, including keys whose
//! material is missing or broken (linting `cnf` keys).

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_cbor::{EncodeMode, Item};
use tokenator_crypto::{Alg, Curve, KeyMismatch, KeyType, MlDsaParams, check_key};
use tokenator_keys::{
    CoseKey, DeclaredAlg, Jwk, KeyError, from_cwk, from_jwk, params, params_from_cwk,
    params_from_jwk,
};

fn pj(json: &str) -> Result<tokenator_keys::KeyParams, KeyError> {
    params_from_jwk(&Jwk::parse(json.as_bytes()).unwrap())
}

fn cose(entries: Vec<(i64, Item<'static>)>) -> CoseKey {
    let item = Item::map(
        entries
            .into_iter()
            .map(|(k, v)| (Item::int(k), v))
            .collect(),
    );
    CoseKey::decode(&tokenator_cbor::encode(&item, EncodeMode::Preserve)).unwrap()
}

fn pc(entries: Vec<(i64, Item<'static>)>) -> Result<tokenator_keys::KeyParams, KeyError> {
    params_from_cwk(&cose(entries))
}

// ------------------------------------------------------------------ params

#[test]
fn params_from_material_for_every_kind() {
    for kind in ALL_KINDS {
        let key = sample_key(kind);
        let p = params(&key);
        assert_eq!(
            p,
            key.private_key().unwrap().params(),
            "{kind:?}: no declared alg"
        );
        assert_eq!(p.kty, key.key_type());
        match kind {
            Kind::P256 => assert_eq!(p.crv, Some(Curve::P256)),
            Kind::P384 => assert_eq!(p.crv, Some(Curve::P384)),
            Kind::P521 => assert_eq!(p.crv, Some(Curve::P521)),
            Kind::Ed25519 => assert_eq!(p.crv, Some(Curve::Ed25519)),
            Kind::Rsa2048 => assert_eq!(p.rsa_bits, Some(2048)),
            _ => assert_eq!(p.ml_dsa, kind.ml_dsa()),
        }
    }
}

#[test]
fn params_include_declared_alg() {
    let mut key = sample_key(Kind::P256);
    key.alg = Some(DeclaredAlg::Known(Alg::ES384));
    let p = params(&key);
    assert_eq!(p.declared_alg, Some(DeclaredAlg::Known(Alg::ES384)));
    assert_eq!(
        check_key(Alg::ES256, &p),
        [KeyMismatch::DeclaredAlg {
            alg: Alg::ES256,
            declared: DeclaredAlg::Known(Alg::ES384)
        }]
    );
    // Public half: same params.
    assert_eq!(params(&tokenator_keys::to_public(&key)), p);
}

#[test]
fn params_agree_across_sources() {
    for kind in ALL_KINDS {
        let mut key = sample_key(kind);
        key.alg = Some(DeclaredAlg::UnknownJose("X".into()));
        let jwk = tokenator_keys::to_jwk(&key, tokenator_keys::Visibility::Public).unwrap();
        assert_eq!(params_from_jwk(&jwk).unwrap(), params(&key), "{kind:?}");
        key.alg = Some(DeclaredAlg::UnknownCose(-65536));
        let cwk = tokenator_keys::to_cwk(&key, tokenator_keys::Visibility::Public).unwrap();
        assert_eq!(params_from_cwk(&cwk).unwrap(), params(&key), "{kind:?}");
    }
}

// ---------------------------------------------------------- params_from_jwk

#[test]
fn jwk_params_without_material() {
    let p = pj(r#"{"kty":"EC","crv":"P-384"}"#).unwrap();
    assert_eq!(
        (p.kty, p.crv, p.rsa_bits, p.ml_dsa),
        (KeyType::Ec, Some(Curve::P384), None, None)
    );
    assert_eq!(p.declared_alg, None);

    let p = pj(r#"{"kty":"OKP","crv":"Ed25519","alg":"EdDSA"}"#).unwrap();
    assert_eq!(p.crv, Some(Curve::Ed25519));
    assert_eq!(p.declared_alg, Some(DeclaredAlg::Known(Alg::EdDSA)));

    let p = pj(r#"{"kty":"RSA","alg":"RS256"}"#).unwrap();
    assert_eq!((p.kty, p.rsa_bits), (KeyType::Rsa, None));

    let p = pj(r#"{"kty":"AKP","alg":"ML-DSA-65"}"#).unwrap();
    assert_eq!(p.kty, KeyType::Akp);
    assert_eq!(p.ml_dsa, Some(MlDsaParams::MlDsa65));
    assert_eq!(p.declared_alg, Some(DeclaredAlg::Known(Alg::MlDsa65)));
}

#[test]
fn jwk_params_report_contradictions_faithfully() {
    // kty EC with an OKP curve: reported as is, so check_key can flag it.
    let p = pj(r#"{"kty":"EC","crv":"Ed25519"}"#).unwrap();
    assert_eq!((p.kty, p.crv), (KeyType::Ec, Some(Curve::Ed25519)));
    assert!(!check_key(Alg::ES256, &p).is_empty());
    assert!(!check_key(Alg::EdDSA, &p).is_empty());

    // Unknown curves are None.
    for crv in ["X25519", "secp256k1", "P-256K", "p-256"] {
        let p = pj(&format!(r#"{{"kty":"OKP","crv":"{crv}"}}"#)).unwrap();
        assert_eq!(p.crv, None, "{crv}");
    }
    let p = pj(r#"{"kty":"EC","crv":7}"#).unwrap();
    assert_eq!(p.crv, None);

    // Unsupported declared algs are kept.
    let p = pj(r#"{"kty":"EC","crv":"P-256","alg":"HS256"}"#).unwrap();
    assert_eq!(
        p.declared_alg,
        Some(DeclaredAlg::UnknownJose("HS256".into()))
    );
}

#[test]
fn jwk_rsa_bits_from_n() {
    // 2048-bit n with and without a (non-conformant) leading zero byte.
    let mut n = vec![0xc5u8; 256];
    let p = pj(&format!(r#"{{"kty":"RSA","n":"{}","e":"AQAB"}}"#, b64u(&n))).unwrap();
    assert_eq!(p.rsa_bits, Some(2048));
    n.insert(0, 0);
    let p = pj(&format!(r#"{{"kty":"RSA","n":"{}"}}"#, b64u(&n))).unwrap();
    assert_eq!(p.rsa_bits, Some(2048));
    // Top byte 0x01: 2041 bits.
    let mut n = vec![0xffu8; 256];
    n[0] = 1;
    let p = pj(&format!(r#"{{"kty":"RSA","n":"{}"}}"#, b64u(&n))).unwrap();
    assert_eq!(p.rsa_bits, Some(2041));
    // 1024 bits: too small for every RSA alg.
    let p = pj(&format!(r#"{{"kty":"RSA","n":"{}"}}"#, b64u(&[0x80; 128]))).unwrap();
    assert_eq!(p.rsa_bits, Some(1024));
    assert_eq!(
        check_key(Alg::RS256, &p),
        [KeyMismatch::RsaTooSmall {
            min_bits: 2048,
            found_bits: 1024
        }]
    );
    // Undecodable or wrongly typed n: unknown size.
    for n in [r#""!!!""#, "5", "null", r#""""#] {
        let p = pj(&format!(r#"{{"kty":"RSA","n":{n}}}"#)).unwrap();
        assert_eq!(p.rsa_bits, None, "n = {n}");
    }
}

#[test]
fn jwk_akp_parameter_set_from_pub_length_when_alg_missing() {
    for set in [
        MlDsaParams::MlDsa44,
        MlDsaParams::MlDsa65,
        MlDsaParams::MlDsa87,
    ] {
        let pubk = b64u(&vec![0u8; set.public_key_len()]);
        let p = pj(&format!(r#"{{"kty":"AKP","pub":"{pubk}"}}"#)).unwrap();
        assert_eq!(p.ml_dsa, Some(set));
        assert_eq!(p.declared_alg, None);
    }
    let p = pj(r#"{"kty":"AKP","pub":"AAAA"}"#).unwrap();
    assert_eq!(p.ml_dsa, None);
    // alg wins over the length.
    let pubk = b64u(&vec![0u8; 1312]);
    let p = pj(&format!(
        r#"{{"kty":"AKP","alg":"ML-DSA-87","pub":"{pubk}"}}"#
    ))
    .unwrap();
    assert_eq!(p.ml_dsa, Some(MlDsaParams::MlDsa87));
    // A non-ML-DSA alg on an AKP key: no parameter set.
    let p = pj(r#"{"kty":"AKP","alg":"ES256"}"#).unwrap();
    assert_eq!(p.ml_dsa, None);
    assert_eq!(p.declared_alg, Some(DeclaredAlg::Known(Alg::ES256)));
}

#[test]
fn jwk_params_errors() {
    assert_eq!(
        pj("{}").unwrap_err(),
        KeyError::MissingParameter("kty".into())
    );
    assert_eq!(
        pj(r#"{"kty":"oct","k":"AAAA"}"#).unwrap_err(),
        KeyError::UnsupportedKeyType("oct".into())
    );
    assert_eq!(
        pj(r#"{"kty":"ec"}"#).unwrap_err(),
        KeyError::UnsupportedKeyType("ec".into()),
        "kty is case-sensitive"
    );
    assert!(matches!(
        pj(r#"{"kty":2}"#).unwrap_err(),
        KeyError::InvalidParameter { name, .. } if name == "kty"
    ));
}

#[test]
fn jwk_params_work_when_from_jwk_fails() {
    let cases = [
        // Point not on the curve.
        r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyQ"}"#,
        // Bad base64url.
        r#"{"kty":"OKP","crv":"Ed25519","x":"$$$"}"#,
        // Missing x.
        r#"{"kty":"EC","crv":"P-521","y":"AAAA"}"#,
        // crv / kty mismatch.
        r#"{"kty":"OKP","crv":"P-256","x":"AAAA"}"#,
    ];
    for json in cases {
        let jwk = Jwk::parse(json.as_bytes()).unwrap();
        assert!(from_jwk(&jwk).is_err(), "{json}");
        assert!(params_from_jwk(&jwk).is_ok(), "{json}");
    }
}

// ---------------------------------------------------------- params_from_cwk

#[test]
fn cwk_params_without_material() {
    let p = pc(vec![(1, Item::int(2)), (-1, Item::int(2))]).unwrap();
    assert_eq!((p.kty, p.crv), (KeyType::Ec, Some(Curve::P384)));

    let p = pc(vec![
        (1, Item::int(1)),
        (-1, Item::int(6)),
        (3, Item::int(-8)),
    ])
    .unwrap();
    assert_eq!((p.kty, p.crv), (KeyType::Okp, Some(Curve::Ed25519)));
    assert_eq!(p.declared_alg, Some(DeclaredAlg::Known(Alg::EdDSA)));

    let p = pc(vec![(1, Item::int(7)), (3, Item::int(-49))]).unwrap();
    assert_eq!(p.ml_dsa, Some(MlDsaParams::MlDsa65));
    assert_eq!(p.declared_alg, Some(DeclaredAlg::Known(Alg::MlDsa65)));

    let p = pc(vec![(1, Item::int(7)), (-1, Item::bytes(vec![0; 2592]))]).unwrap();
    assert_eq!(p.ml_dsa, Some(MlDsaParams::MlDsa87));

    let p = pc(vec![(1, Item::int(3)), (-1, Item::bytes(vec![0x80; 384]))]).unwrap();
    assert_eq!((p.kty, p.rsa_bits), (KeyType::Rsa, Some(3072)));

    // Unknown curve label (X25519 = 4), unknown alg.
    let p = pc(vec![
        (1, Item::int(1)),
        (-1, Item::int(4)),
        (3, Item::int(-9)),
    ])
    .unwrap();
    assert_eq!(p.crv, None);
    assert_eq!(p.declared_alg, Some(DeclaredAlg::UnknownCose(-9)));

    // Contradiction kept: EC2 with Ed25519.
    let p = pc(vec![(1, Item::int(2)), (-1, Item::int(6))]).unwrap();
    assert_eq!((p.kty, p.crv), (KeyType::Ec, Some(Curve::Ed25519)));
}

#[test]
fn cwk_params_errors() {
    assert_eq!(
        pc(vec![]).unwrap_err(),
        KeyError::MissingParameter("1".into())
    );
    assert_eq!(
        pc(vec![(1, Item::int(4)), (-1, Item::bytes(vec![1]))]).unwrap_err(),
        KeyError::UnsupportedKeyType("4".into())
    );
    assert!(matches!(
        pc(vec![(1, Item::bytes(vec![2]))]).unwrap_err(),
        KeyError::InvalidParameter { name, .. } if name == "1"
    ));
}

#[test]
fn cwk_params_work_when_from_cwk_fails() {
    let x = vec![0x11; 32];
    let cases = vec![
        // EC2 point not on the curve.
        cose(vec![
            (1, Item::int(2)),
            (-1, Item::int(1)),
            (-2, Item::bytes(x.clone())),
            (-3, Item::bytes(x.clone())),
        ]),
        // x as text.
        cose(vec![
            (1, Item::int(1)),
            (-1, Item::int(6)),
            (-2, Item::text("x")),
        ]),
        // Missing y.
        cose(vec![
            (1, Item::int(2)),
            (-1, Item::int(1)),
            (-2, Item::bytes(x.clone())),
        ]),
        // Wrong pub length for the alg.
        cose(vec![
            (1, Item::int(7)),
            (3, Item::int(-48)),
            (-1, Item::bytes(vec![0; 10])),
        ]),
    ];
    for cwk in cases {
        assert!(from_cwk(&cwk).is_err(), "{cwk:?}");
        assert!(params_from_cwk(&cwk).is_ok(), "{cwk:?}");
    }
}
