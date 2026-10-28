//! JOSE known-answer tests: RFC 7517 Appendix A/B, RFC 8037 Appendix A,
//! RFC 7638 §3.1, RFC 9278 §3 (via RFC 7638), and RFC 9964 Appendix A.1.

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_crypto::{
    Alg, Curve, KeyType, MlDsaParams, PrivateKeyMaterial, PublicKeyMaterial, verify,
};
use tokenator_keys::{
    DeclaredAlg, Extra, HashAlg, Jwk, KeyError, KeyFormat, Kid, ThumbprintKind, Visibility, export,
    from_jwk, import, import_each, jwk_thumbprint, jwk_thumbprint_uri, params, thumbprint, to_jwk,
    to_public,
};

const RFC7517_RSA_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
const RFC7517_EC_X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
const RFC7517_EC_Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";
const RFC7517_EC_D: &str = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE";

const RFC8037_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const RFC8037_D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
const RFC8037_THUMBPRINT: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";

const RFC7638_THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

// ---------------------------------------------------------------- RFC 7517

#[test]
fn rfc7517_a1_public_set_imports_two_keys() {
    let keys = import(&fixture("rfc7517/a1-public-set.json"), None).unwrap();
    assert_eq!(keys.len(), 2);

    let ec = &keys[0];
    assert!(!ec.is_private());
    assert_eq!(ec.key_type(), KeyType::Ec);
    assert_eq!(ec.kid, Some(Kid::Text("1".into())));
    assert_eq!(ec.key_use.as_deref(), Some("enc"));
    assert_eq!(ec.alg, None);
    assert_eq!(ec.role, None);
    assert!(!ec.derived);
    assert_eq!(
        ec.public_key().to_material(),
        PublicKeyMaterial::Ec {
            curve: Curve::P256,
            x: unb64u(RFC7517_EC_X),
            y: unb64u(RFC7517_EC_Y),
        }
    );

    let rsa = &keys[1];
    assert!(!rsa.is_private());
    assert_eq!(rsa.key_type(), KeyType::Rsa);
    assert_eq!(rsa.kid, Some(Kid::Text("2011-04-29".into())));
    assert_eq!(rsa.alg, Some(DeclaredAlg::Known(Alg::RS256)));
    assert_eq!(rsa.key_use, None);
    assert_eq!(
        rsa.public_key().to_material(),
        PublicKeyMaterial::Rsa {
            n: unb64u(RFC7517_RSA_N),
            e: vec![1, 0, 1],
        }
    );
    assert_eq!(params(rsa).rsa_bits, Some(2048));
}

#[test]
fn rfc7517_a1_same_result_with_set_or_key_hint() {
    let input = fixture("rfc7517/a1-public-set.json");
    let detected = import(&input, None).unwrap();
    for hint in [KeyFormat::JwkSet, KeyFormat::Jwk] {
        assert_eq!(import(&input, Some(hint)).unwrap(), detected, "{hint:?}");
    }
}

#[test]
fn rfc7517_a2_private_set_imports_two_private_keys() {
    let keys = import(&fixture("rfc7517/a2-private-set.json"), None).unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().all(|k| k.is_private()));

    match keys[0].private_key().unwrap().to_material() {
        PrivateKeyMaterial::Ec { curve, d } => {
            assert_eq!(curve, Curve::P256);
            assert_eq!(d, unb64u(RFC7517_EC_D));
        }
        other => panic!("{other:?}"),
    }
    match keys[1].private_key().unwrap().to_material() {
        PrivateKeyMaterial::Rsa(m) => {
            let j = fixture_json("rfc7517/a2-private-set.json");
            let r = &j["keys"][1];
            for (name, got) in [
                ("n", Some(m.n.clone())),
                ("e", Some(m.e.clone())),
                ("d", Some(m.d.clone())),
                ("p", m.p.clone()),
                ("q", m.q.clone()),
                ("dp", m.dp.clone()),
                ("dq", m.dq.clone()),
                ("qi", m.qi.clone()),
            ] {
                assert_eq!(got, Some(unb64u(r[name].as_str().unwrap())), "{name}");
            }
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(keys[1].alg, Some(DeclaredAlg::Known(Alg::RS256)));
    assert_eq!(keys[1].kid, Some(Kid::Text("2011-04-29".into())));
}

#[test]
fn rfc7517_a2_public_halves_equal_a1() {
    let public = import(&fixture("rfc7517/a1-public-set.json"), None).unwrap();
    let private = import(&fixture("rfc7517/a2-private-set.json"), None).unwrap();
    for (pubk, privk) in public.iter().zip(&private) {
        let derived = to_public(privk);
        assert_same_material(&derived, pubk, "A.2 public half vs A.1");
        assert_eq!(derived.kid, pubk.kid);
        assert_eq!(derived.alg, pubk.alg);
        assert_eq!(derived.key_use, pubk.key_use);
        assert!(derived.derived);
    }
}

#[test]
fn rfc7517_a3_symmetric_keys_are_unsupported() {
    let input = fixture("rfc7517/a3-symmetric-set.json");
    assert_eq!(
        import(&input, None).unwrap_err(),
        KeyError::UnsupportedKeyType("oct".into())
    );
    let each = import_each(&input, None).unwrap();
    assert_eq!(each.len(), 2);
    for r in each {
        assert_eq!(r.unwrap_err(), KeyError::UnsupportedKeyType("oct".into()));
    }
}

#[test]
fn rfc7517_b_x5c_is_kept_as_an_extra() {
    let key = import_fixture("rfc7517/b-x5c.json");
    assert_eq!(key.kid, Some(Kid::Text("1b94c".into())));
    assert_eq!(key.key_use.as_deref(), Some("sig"));
    assert_eq!(params(&key).rsa_bits, Some(2048));
    assert_eq!(key.extras.len(), 1);
    let original = fixture_json("rfc7517/b-x5c.json");
    match &key.extras[0] {
        Extra::Jose { name, json } => {
            assert_eq!(name, "x5c");
            let v: serde_json::Value = serde_json::from_str(json).unwrap();
            assert_eq!(v, original["x5c"]);
            assert!(
                !json.contains(' ') && !json.contains('\n'),
                "compact: {json}"
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn rfc7517_b_x5c_survives_jwk_export() {
    let key = import_fixture("rfc7517/b-x5c.json");
    let out = export(&key, KeyFormat::Jwk, Visibility::Public).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let original = fixture_json("rfc7517/b-x5c.json");
    assert_eq!(
        v, original,
        "every member survives (order checked elsewhere)"
    );
    assert_eq!(
        json_member_names(&out),
        ["kty", "kid", "use", "n", "e", "x5c"],
        "known members in canonical order, then extras"
    );
}

// ---------------------------------------------------------------- RFC 8037

#[test]
fn rfc8037_a1_private_key() {
    let key = import_fixture("rfc8037/ed25519-private.json");
    assert!(key.is_private());
    assert_eq!(key.key_type(), KeyType::Okp);
    assert_eq!(
        key.private_key().unwrap().to_material(),
        PrivateKeyMaterial::Ed25519 {
            d: unb64u(RFC8037_D)
        }
    );
    assert_eq!(
        key.public_key().to_material(),
        PublicKeyMaterial::Ed25519 {
            x: unb64u(RFC8037_X)
        }
    );
    assert_eq!(params(&key).crv, Some(Curve::Ed25519));
}

#[test]
fn rfc8037_a2_public_key_matches_private() {
    let public = import_fixture("rfc8037/ed25519-public.json");
    let private = import_fixture("rfc8037/ed25519-private.json");
    assert!(!public.is_private());
    assert_same_material(&to_public(&private), &public, "RFC 8037 A.2");
}

#[test]
fn rfc8037_a3_thumbprint() {
    for rel in [
        "rfc8037/ed25519-private.json",
        "rfc8037/ed25519-public.json",
    ] {
        let key = import_fixture(rel);
        assert_eq!(
            b64u(&thumbprint(&key, ThumbprintKind::Jwk, HashAlg::Sha256)),
            RFC8037_THUMBPRINT,
            "{rel}"
        );
        let jwk = Jwk::parse(&fixture(rel)).unwrap();
        assert_eq!(
            b64u(&jwk_thumbprint(&jwk, HashAlg::Sha256).unwrap()),
            RFC8037_THUMBPRINT
        );
    }
    assert_eq!(
        hex::encode(unb64u(RFC8037_THUMBPRINT)),
        "90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89"
    );
}

#[test]
fn rfc8037_to_jwk_exact_text() {
    let key = import_fixture("rfc8037/ed25519-private.json");
    assert_eq!(
        to_jwk(&key, Visibility::Private).unwrap().to_json(),
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{RFC8037_X}","d":"{RFC8037_D}"}}"#)
    );
    assert_eq!(
        to_jwk(&key, Visibility::Public).unwrap().to_json(),
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{RFC8037_X}"}}"#)
    );
    // export() is the same text as bytes.
    assert_eq!(
        export(&key, KeyFormat::Jwk, Visibility::Public).unwrap(),
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{RFC8037_X}"}}"#).into_bytes()
    );
}

#[test]
fn rfc8037_a4_signature_verifies_with_imported_key() {
    let v = testdata_json("rfc/rfc8037-ed25519.json");
    let key = import_fixture("rfc8037/ed25519-public.json");
    let input = v["signing_input"].as_str().unwrap().as_bytes();
    let sig = hexv(&v["signature_hex"]);
    verify(Alg::EdDSA, &key.public_key(), input, &sig).unwrap();
}

// ---------------------------------------------------------- RFC 7638 / 9278

#[test]
fn rfc7638_s3_1_thumbprint() {
    let key = import_fixture("rfc7638/rsa.json");
    let tp = thumbprint(&key, ThumbprintKind::Jwk, HashAlg::Sha256);
    assert_eq!(b64u(&tp), RFC7638_THUMBPRINT);
    // The RFC also lists the hash octets.
    assert_eq!(
        tp,
        [
            55, 54, 203, 177, 120, 124, 184, 48, 156, 119, 238, 140, 55, 5, 197, 225, 111, 251,
            158, 133, 151, 21, 144, 31, 30, 76, 89, 177, 17, 130, 245, 123
        ]
    );
    let jwk = Jwk::parse(&fixture("rfc7638/rsa.json")).unwrap();
    assert_eq!(
        b64u(&jwk_thumbprint(&jwk, HashAlg::Sha256).unwrap()),
        RFC7638_THUMBPRINT
    );
}

#[test]
fn rfc7638_kid_and_alg_do_not_change_the_thumbprint() {
    // The RFC 7517 A.1 RSA key is the RFC 7638 key with the same kid/alg.
    let keys = import(&fixture("rfc7517/a1-public-set.json"), None).unwrap();
    assert_eq!(
        b64u(&thumbprint(&keys[1], ThumbprintKind::Jwk, HashAlg::Sha256)),
        RFC7638_THUMBPRINT
    );
    // And so is the private A.2 key: the thumbprint is of the public part.
    let keys = import(&fixture("rfc7517/a2-private-set.json"), None).unwrap();
    assert_eq!(
        b64u(&thumbprint(&keys[1], ThumbprintKind::Jwk, HashAlg::Sha256)),
        RFC7638_THUMBPRINT
    );
}

#[test]
fn rfc9278_jwk_thumbprint_uri() {
    let key = import_fixture("rfc7638/rsa.json");
    assert_eq!(
        jwk_thumbprint_uri(&key, HashAlg::Sha256),
        format!("urn:ietf:params:oauth:jwk-thumbprint:sha-256:{RFC7638_THUMBPRINT}")
    );
    let uri = jwk_thumbprint_uri(&key, HashAlg::Sha384);
    let prefix = "urn:ietf:params:oauth:jwk-thumbprint:sha-384:";
    assert!(uri.starts_with(prefix), "{uri}");
    assert_eq!(
        unb64u(&uri[prefix.len()..]),
        thumbprint(&key, ThumbprintKind::Jwk, HashAlg::Sha384)
    );
}

// ---------------------------------------------------------------- RFC 9964

fn rfc9964_kat(p: &str) -> serde_json::Value {
    testdata_json(&format!("rfc9964/ml-dsa-{p}-jose.json"))
}

const ML_DSA: [(&str, MlDsaParams, Alg); 3] = [
    ("44", MlDsaParams::MlDsa44, Alg::MlDsa44),
    ("65", MlDsaParams::MlDsa65, Alg::MlDsa65),
    ("87", MlDsaParams::MlDsa87, Alg::MlDsa87),
];

#[test]
fn rfc9964_private_jwk_imports() {
    for (p, params_set, alg) in ML_DSA {
        let kat = rfc9964_kat(p);
        let key = import_fixture(&format!("rfc9964/ml-dsa-{p}-private.jwk.json"));
        assert!(key.is_private(), "{p}");
        assert_eq!(key.key_type(), KeyType::Akp);
        assert_eq!(key.alg, Some(DeclaredAlg::Known(alg)));
        assert!(matches!(&key.kid, Some(Kid::Text(_))));
        assert_eq!(
            key.public_key().to_material(),
            PublicKeyMaterial::MlDsa {
                params: params_set,
                public: hexv(&kat["raw_public_key"]),
            }
        );
        match key.private_key().unwrap().to_material() {
            PrivateKeyMaterial::MlDsa { params, seed, .. } => {
                assert_eq!(params, params_set);
                assert_eq!(seed, Some(vec![0; 32]), "priv is the seed (RFC 9964 §4)");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(tokenator_keys::params(&key).ml_dsa, Some(params_set));
    }
}

#[test]
fn rfc9964_kid_is_the_jwk_thumbprint() {
    for (p, ..) in ML_DSA {
        for vis in ["private", "public"] {
            let rel = format!("rfc9964/ml-dsa-{p}-{vis}.jwk.json");
            let key = import_fixture(&rel);
            let Some(Kid::Text(kid)) = &key.kid else {
                panic!("{rel}: kid")
            };
            assert_eq!(
                &b64u(&thumbprint(&key, ThumbprintKind::Jwk, HashAlg::Sha256)),
                kid,
                "{rel}"
            );
            let jwk = Jwk::parse(&fixture(&rel)).unwrap();
            assert_eq!(&b64u(&jwk_thumbprint(&jwk, HashAlg::Sha256).unwrap()), kid);
        }
    }
}

#[test]
fn rfc9964_public_jwk_matches_private() {
    for (p, ..) in ML_DSA {
        let public = import_fixture(&format!("rfc9964/ml-dsa-{p}-public.jwk.json"));
        let private = import_fixture(&format!("rfc9964/ml-dsa-{p}-private.jwk.json"));
        assert!(!public.is_private());
        assert_same_material(&to_public(&private), &public, p);
    }
}

#[test]
fn rfc9964_jws_verifies_with_imported_key() {
    for (p, _, alg) in ML_DSA {
        let kat = rfc9964_kat(p);
        let key = import_fixture(&format!("rfc9964/ml-dsa-{p}-public.jwk.json"));
        let jws = kat["jws"].as_str().unwrap();
        let (input, sig) = jws.rsplit_once('.').unwrap();
        verify(alg, &key.public_key(), input.as_bytes(), &unb64u(sig)).unwrap();
    }
}

#[test]
fn rfc9964_to_jwk_member_order_and_values() {
    for (p, ..) in ML_DSA {
        let rel = format!("rfc9964/ml-dsa-{p}-private.jwk.json");
        let key = import_fixture(&rel);
        let out = to_jwk(&key, Visibility::Private).unwrap().to_json();
        assert_eq!(
            json_member_names(out.as_bytes()),
            ["kty", "kid", "alg", "pub", "priv"]
        );
        let got: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            got,
            fixture_json(&rel),
            "same members and values as the RFC"
        );
    }
}

#[test]
fn akp_jwk_always_has_alg() {
    // A generated ML-DSA key has no declared alg, but RFC 9964 §3 requires
    // one, so the JWK and COSE_Key get it from the parameter set.
    for (p, params_set, alg) in ML_DSA {
        let key = sample_key(match params_set {
            MlDsaParams::MlDsa44 => Kind::MlDsa44,
            MlDsaParams::MlDsa65 => Kind::MlDsa65,
            MlDsaParams::MlDsa87 => Kind::MlDsa87,
        });
        assert_eq!(key.alg, None);
        let jwk = to_jwk(&key, Visibility::Public).unwrap();
        assert_eq!(jwk.get_str("alg"), Some(format!("ML-DSA-{p}").as_str()));
        let cwk = tokenator_keys::to_cwk(&key, Visibility::Public).unwrap();
        let label = tokenator_crypto::alg_to_cose(alg);
        assert_eq!(
            cbor_get(&cwk.to_cbor(), 3).map(|i| int(&i.value)),
            Some(label)
        );
    }
}

#[test]
fn from_jwk_matches_import() {
    for rel in [
        "rfc8037/ed25519-private.json",
        "rfc7638/rsa.json",
        "rfc9964/ml-dsa-44-private.jwk.json",
        "rfc7517/b-x5c.json",
    ] {
        let jwk = Jwk::parse(&fixture(rel)).unwrap();
        assert_eq!(from_jwk(&jwk).unwrap(), import_fixture(rel), "{rel}");
    }
}
