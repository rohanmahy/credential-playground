//! JWK <-> COSE_Key conversion and metadata mapping: kid, alg, key_ops,
//! use, unknown parameters, and output member order.

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_cbor::{EncodeMode, Item, Value};
use tokenator_crypto::{Alg, alg_to_cose, alg_to_jose};
use tokenator_keys::{
    CoseKey, DeclaredAlg, Extra, Jwk, Key, KeyFormat, KeyOp, Kid, Label, Visibility, export,
    from_cwk, from_jwk, import, to_cwk, to_jwk,
};

fn jwk_of(key: &Key, vis: Visibility) -> Key {
    from_jwk(&to_jwk(key, vis).unwrap()).unwrap()
}

fn cwk_of(key: &Key, vis: Visibility) -> Key {
    from_cwk(&to_cwk(key, vis).unwrap()).unwrap()
}

#[test]
fn jwk_to_cwk_to_jwk_preserves_material_kid_and_alg() {
    for kind in ALL_KINDS {
        let mut key = sample_key(kind);
        key.kid = Some(Kid::Text("issuer-key-1".into()));
        key.alg = Some(DeclaredAlg::Known(match kind {
            Kind::P256 => Alg::ES256,
            Kind::P384 => Alg::ES384,
            Kind::P521 => Alg::ES512,
            Kind::Ed25519 => Alg::EdDSA,
            Kind::Rsa2048 => Alg::RS256,
            Kind::MlDsa44 => Alg::MlDsa44,
            Kind::MlDsa65 => Alg::MlDsa65,
            Kind::MlDsa87 => Alg::MlDsa87,
        }));
        for vis in [Visibility::Public, Visibility::Private] {
            let via_cose = cwk_of(&jwk_of(&key, vis), vis);
            assert_eq!(
                via_cose.kid,
                Some(Kid::Bytes(b"issuer-key-1".to_vec())),
                "{kind:?}"
            );
            assert_eq!(via_cose.alg, key.alg, "{kind:?}");
            let back = jwk_of(&via_cose, vis);
            assert_eq!(back.kid, key.kid, "{kind:?}: the kid string survives");
            assert_eq!(back.alg, key.alg);
            assert_eq!(back.is_private(), vis == Visibility::Private);
            let want = if vis == Visibility::Private {
                key.clone()
            } else {
                tokenator_keys::to_public(&key)
            };
            assert_same_material(&back, &want, &format!("{kind:?} {vis:?}"));
        }
    }
}

#[test]
fn cwk_to_jwk_to_cwk_preserves_binary_kid_bytes_when_utf8() {
    let mut key = sample_key(Kind::P256);
    key.kid = Some(Kid::Bytes(b"11".to_vec()));
    let jwk = to_jwk(&key, Visibility::Public).unwrap();
    assert_eq!(jwk.get_str("kid"), Some("11"));
    let back = cwk_of(&from_jwk(&jwk).unwrap(), Visibility::Public);
    assert_eq!(back.kid, Some(Kid::Bytes(b"11".to_vec())));
}

#[test]
fn non_utf8_binary_kid_becomes_base64url_in_jwk() {
    let mut key = sample_key(Kind::Ed25519);
    key.kid = Some(Kid::Bytes(vec![0xff, 0x00, 0xfe]));
    let jwk = to_jwk(&key, Visibility::Public).unwrap();
    assert_eq!(jwk.get_str("kid"), Some("_wD-"));
}

#[test]
fn kid_helpers() {
    assert_eq!(Kid::Text("abc".into()).as_bytes(), b"abc");
    assert_eq!(Kid::Bytes(vec![1, 2]).as_bytes(), [1, 2]);
    assert_eq!(Kid::Text("é".into()).as_bytes(), "é".as_bytes());
    assert_eq!(Kid::Text("abc".into()).to_jose_string(), "abc");
    assert_eq!(Kid::Bytes(b"abc".to_vec()).to_jose_string(), "abc");
    assert_eq!(Kid::Bytes(vec![0xff, 0x00, 0xfe]).to_jose_string(), "_wD-");
    assert_eq!(Kid::Bytes(vec![]).to_jose_string(), "");
}

#[test]
fn key_ops_map_between_names_and_labels() {
    let all = [
        (KeyOp::Sign, "sign", 1),
        (KeyOp::Verify, "verify", 2),
        (KeyOp::Encrypt, "encrypt", 3),
        (KeyOp::Decrypt, "decrypt", 4),
        (KeyOp::WrapKey, "wrapKey", 5),
        (KeyOp::UnwrapKey, "unwrapKey", 6),
        (KeyOp::DeriveKey, "deriveKey", 7),
        (KeyOp::DeriveBits, "deriveBits", 8),
    ];
    let mut key = sample_key(Kind::P256);
    key.key_ops = Some(all.iter().map(|(op, ..)| op.clone()).collect());

    let jwk_text = to_jwk(&key, Visibility::Public).unwrap().to_json();
    let v: serde_json::Value = serde_json::from_str(&jwk_text).unwrap();
    let names: Vec<_> = all.iter().map(|(_, n, _)| serde_json::json!(n)).collect();
    assert_eq!(v["key_ops"], serde_json::Value::Array(names));

    let cbor = to_cwk(&key, Visibility::Public).unwrap().to_cbor();
    let ops = cbor_get(&cbor, 4).unwrap();
    let Value::Array(items) = ops.value else {
        panic!("{ops:?}")
    };
    assert_eq!(
        items.iter().map(|i| int(&i.value)).collect::<Vec<_>>(),
        all.iter().map(|(.., l)| *l).collect::<Vec<i64>>()
    );

    // Both directions parse back to the same list.
    assert_eq!(jwk_of(&key, Visibility::Public).key_ops, key.key_ops);
    assert_eq!(cwk_of(&key, Visibility::Public).key_ops, key.key_ops);
    assert_eq!(
        cwk_of(&jwk_of(&key, Visibility::Public), Visibility::Public).key_ops,
        key.key_ops
    );
}

#[test]
fn unknown_key_ops_are_kept_verbatim() {
    let jwk = br#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","key_ops":["sign","frobnicate"]}"#;
    let key = import_one(jwk, None);
    assert_eq!(
        key.key_ops,
        Some(vec![
            KeyOp::Sign,
            KeyOp::Other(Label::Text("frobnicate".into()))
        ])
    );
    let out = export(&key, KeyFormat::Jwk, Visibility::Public).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["key_ops"], serde_json::json!(["sign", "frobnicate"]));
    // COSE MAC create (9) has no JOSE name.
    let mut key = key;
    key.key_ops = Some(vec![KeyOp::Other(Label::Int(9))]);
    let cbor = export(&key, KeyFormat::CoseKey, Visibility::Public).unwrap();
    assert_eq!(
        cwk_of(&import_one(&cbor, None), Visibility::Public).key_ops,
        key.key_ops
    );
    let v: serde_json::Value =
        serde_json::from_slice(&export(&key, KeyFormat::Jwk, Visibility::Public).unwrap()).unwrap();
    assert_eq!(v["key_ops"], serde_json::json!([9]));
}

#[test]
fn known_alg_maps_between_name_and_label() {
    for alg in Alg::ALL {
        let kind = match alg {
            Alg::ES256 => Kind::P256,
            Alg::ES384 => Kind::P384,
            Alg::ES512 => Kind::P521,
            Alg::EdDSA | Alg::Ed25519 => Kind::Ed25519,
            Alg::MlDsa44 => Kind::MlDsa44,
            Alg::MlDsa65 => Kind::MlDsa65,
            Alg::MlDsa87 => Kind::MlDsa87,
            _ => Kind::Rsa2048,
        };
        let mut key = sample_key(kind);
        key.alg = Some(DeclaredAlg::Known(alg));
        let jwk = to_jwk(&key, Visibility::Public).unwrap();
        assert_eq!(jwk.get_str("alg"), Some(alg_to_jose(alg)), "{alg:?}");
        let cbor = to_cwk(&key, Visibility::Public).unwrap().to_cbor();
        assert_eq!(
            cbor_get(&cbor, 3).map(|i| int(&i.value)),
            Some(alg_to_cose(alg))
        );
        assert_eq!(
            cwk_of(&jwk_of(&key, Visibility::Public), Visibility::Public).alg,
            key.alg
        );
    }
}

#[test]
fn unknown_alg_is_kept_across_formats() {
    // A JOSE-only name on an EC key.
    let jwk = br#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","alg":"HS256"}"#;
    let key = import_one(jwk, None);
    assert_eq!(key.alg, Some(DeclaredAlg::UnknownJose("HS256".into())));
    let cbor = to_cwk(&key, Visibility::Public).unwrap().to_cbor();
    assert_eq!(
        cbor_get(&cbor, 3).map(|i| i.value),
        Some(Value::Text("HS256".into())),
        "unknown JOSE alg becomes a tstr alg"
    );
    assert_eq!(cwk_of(&key, Visibility::Public).alg, key.alg);

    // A COSE-only label (-9, ESP256) on the same key.
    let mut key = key;
    key.alg = Some(DeclaredAlg::UnknownCose(-9));
    let jwk_text = to_jwk(&key, Visibility::Public).unwrap().to_json();
    let v: serde_json::Value = serde_json::from_str(&jwk_text).unwrap();
    assert_eq!(
        v["alg"],
        serde_json::json!(-9),
        "unknown COSE alg becomes a JSON number"
    );
    assert_eq!(jwk_of(&key, Visibility::Public).alg, key.alg);
    assert_eq!(cwk_of(&key, Visibility::Public).alg, key.alg);
}

#[test]
fn use_is_dropped_in_cose() {
    let mut key = sample_key(Kind::P384);
    key.key_use = Some("sig".into());
    assert_eq!(
        jwk_of(&key, Visibility::Public).key_use.as_deref(),
        Some("sig")
    );
    let back = cwk_of(&key, Visibility::Public);
    assert_eq!(back.key_use, None);
    assert_eq!(
        cbor_int_labels(&to_cwk(&key, Visibility::Public).unwrap().to_cbor()),
        [1, -1, -2, -3]
    );
}

const ED_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

#[test]
fn jose_extras_keep_order_and_lexemes() {
    let text = format!(
        r#"{{ "x-first": 1.0, "kty": "OKP", "ext": true, "crv": "Ed25519",
             "x": "{ED_X}", "x5t#S256": "abc", "nested": {{"b": [1, 2e0], "a": null}} }}"#
    );
    let key = import_one(text.as_bytes(), None);
    assert_eq!(
        key.extras,
        vec![
            Extra::Jose {
                name: "x-first".into(),
                json: "1.0".into()
            },
            Extra::Jose {
                name: "ext".into(),
                json: "true".into()
            },
            Extra::Jose {
                name: "x5t#S256".into(),
                json: r#""abc""#.into()
            },
            Extra::Jose {
                name: "nested".into(),
                json: r#"{"b":[1,2e0],"a":null}"#.into()
            },
        ]
    );
    let out = to_jwk(&key, Visibility::Public).unwrap().to_json();
    assert_eq!(
        out,
        format!(
            r#"{{"kty":"OKP","crv":"Ed25519","x":"{ED_X}","x-first":1.0,"ext":true,"x5t#S256":"abc","nested":{{"b":[1,2e0],"a":null}}}}"#
        )
    );
}

#[test]
fn extras_do_not_cross_families() {
    let text = format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{ED_X}","ext":true}}"#);
    let key = import_one(text.as_bytes(), None);
    assert_eq!(key.extras.len(), 1);
    let via_cose = cwk_of(&key, Visibility::Public);
    assert!(
        via_cose.extras.is_empty(),
        "JOSE extras are dropped in COSE"
    );

    let mut key = sample_key(Kind::Ed25519);
    key.extras = vec![Extra::Cose {
        label: Label::Int(-65537),
        cbor: vec![0x01],
    }];
    let via_cose = cwk_of(&key, Visibility::Public);
    assert_eq!(via_cose.extras, key.extras, "COSE extras survive COSE");
    let via_jose = jwk_of(&key, Visibility::Public);
    assert!(
        via_jose.extras.is_empty(),
        "COSE extras are dropped in JOSE"
    );
}

#[test]
fn private_only_parameters_absent_from_public_exports() {
    for kind in ALL_KINDS {
        let key = sample_key(kind);
        let jwk = to_jwk(&key, Visibility::Public).unwrap();
        for private in ["d", "p", "q", "dp", "dq", "qi", "priv"] {
            assert!(jwk.get_str(private).is_none(), "{kind:?}: {private}");
        }
        let cwk = to_cwk(&key, Visibility::Public).unwrap();
        let private_labels: &[i64] = match kind {
            k if k.is_ec() => &[-4],
            Kind::Ed25519 => &[-4],
            Kind::Rsa2048 => &[-3, -4, -5, -6, -7, -8],
            _ => &[-2],
        };
        for l in private_labels {
            assert!(cwk.get(*l).is_none(), "{kind:?}: label {l}");
        }
    }
}

#[test]
fn jwk_member_order_per_key_type() {
    let expected: [(Kind, &[&str]); 5] = [
        (
            Kind::P256,
            &["kty", "kid", "alg", "use", "key_ops", "crv", "x", "y", "d"],
        ),
        (
            Kind::Ed25519,
            &["kty", "kid", "alg", "use", "key_ops", "crv", "x", "d"],
        ),
        (
            Kind::Rsa2048,
            &[
                "kty", "kid", "alg", "use", "key_ops", "n", "e", "d", "p", "q", "dp", "dq", "qi",
            ],
        ),
        (
            Kind::MlDsa44,
            &["kty", "kid", "alg", "use", "key_ops", "pub", "priv"],
        ),
        (
            Kind::P521,
            &["kty", "kid", "alg", "use", "key_ops", "crv", "x", "y", "d"],
        ),
    ];
    for (kind, names) in expected {
        let mut key = sample_key(kind);
        key.kid = Some(Kid::Text("k".into()));
        key.alg = Some(DeclaredAlg::UnknownJose("x".into()));
        key.key_use = Some("sig".into());
        key.key_ops = Some(vec![KeyOp::Sign]);
        let out = to_jwk(&key, Visibility::Private).unwrap().to_json();
        assert_eq!(json_member_names(out.as_bytes()), names, "{kind:?}");
    }
}

#[test]
fn cose_label_order_per_key_type() {
    let expected: [(Kind, &[i64]); 4] = [
        (Kind::P256, &[1, 2, 3, 4, -1, -2, -3, -4]),
        (Kind::Ed25519, &[1, 2, 3, 4, -1, -2, -4]),
        (Kind::Rsa2048, &[1, 2, 3, 4, -1, -2, -3, -4, -5, -6, -7, -8]),
        (Kind::MlDsa65, &[1, 2, 3, 4, -1, -2]),
    ];
    for (kind, labels) in expected {
        let mut key = sample_key(kind);
        key.kid = Some(Kid::Bytes(vec![1]));
        key.alg = Some(DeclaredAlg::UnknownCose(-65535));
        key.key_ops = Some(vec![KeyOp::Sign]);
        let out = to_cwk(&key, Visibility::Private).unwrap().to_cbor();
        assert_eq!(cbor_int_labels(&out), labels, "{kind:?}");
        // Preferred encoding throughout: re-encoding deterministically
        // without sorting changes nothing.
        let item = tokenator_cbor::decode(&out).unwrap();
        assert!(
            tokenator_cbor::preferred_plus_findings(&item).is_empty(),
            "{kind:?}"
        );
    }
}

#[test]
fn cose_values_have_the_right_types_and_widths() {
    for kind in ALL_KINDS {
        let key = sample_key(kind);
        let cbor = to_cwk(&key, Visibility::Private).unwrap().to_cbor();
        let kty = int(&cbor_get(&cbor, 1).unwrap().value);
        assert_eq!(kty, key.key_type().cose_kty(), "{kind:?}");
        match kind {
            k if k.is_ec() => {
                let crv = tokenator_crypto::Curve::from_cose_label(int(&cbor_get(&cbor, -1)
                    .unwrap()
                    .value))
                .unwrap();
                for l in [-2, -3, -4] {
                    assert_eq!(
                        cbor_bytes(&cbor_get(&cbor, l).unwrap()).len(),
                        crv.field_len(),
                        "{kind:?} {l}"
                    );
                }
            }
            Kind::Ed25519 => {
                assert_eq!(int(&cbor_get(&cbor, -1).unwrap().value), 6);
                assert_eq!(cbor_bytes(&cbor_get(&cbor, -2).unwrap()).len(), 32);
                assert_eq!(cbor_bytes(&cbor_get(&cbor, -4).unwrap()).len(), 32);
            }
            Kind::Rsa2048 => {
                let n = cbor_bytes(&cbor_get(&cbor, -1).unwrap());
                assert_eq!(n.len(), 256);
                assert_ne!(n[0], 0, "no leading zero");
                assert_eq!(cbor_bytes(&cbor_get(&cbor, -2).unwrap()), [1, 0, 1]);
            }
            _ => {
                let p = kind.ml_dsa().unwrap();
                assert_eq!(
                    cbor_bytes(&cbor_get(&cbor, -1).unwrap()).len(),
                    p.public_key_len()
                );
                assert_eq!(
                    cbor_bytes(&cbor_get(&cbor, -2).unwrap()).len(),
                    32,
                    "priv is the seed"
                );
            }
        }
    }
}

#[test]
fn jwk_values_have_the_right_widths() {
    for kind in [Kind::P256, Kind::P384, Kind::P521, Kind::Ed25519] {
        let key = sample_key(kind);
        let jwk = to_jwk(&key, Visibility::Private).unwrap();
        let len = if kind == Kind::P384 {
            48
        } else if kind == Kind::P521 {
            66
        } else {
            32
        };
        for m in ["x", "d"] {
            assert_eq!(unb64u(jwk.get_str(m).unwrap()).len(), len, "{kind:?} {m}");
        }
    }
    let jwk = to_jwk(&sample_key(Kind::Rsa2048), Visibility::Public).unwrap();
    assert_eq!(jwk.get_str("e"), Some("AQAB"));
}

#[test]
fn expanded_only_ml_dsa_key_has_no_private_jwk_or_cwk() {
    let key = import_fixture("rfc9881/ml-dsa-44-expanded.pem");
    assert_eq!(
        to_jwk(&key, Visibility::Private).unwrap_err(),
        tokenator_keys::KeyError::MlDsaSeedUnknown
    );
    assert_eq!(
        to_cwk(&key, Visibility::Private).unwrap_err(),
        tokenator_keys::KeyError::MlDsaSeedUnknown
    );
    // The public forms are fine.
    let public = jwk_of(&key, Visibility::Public);
    assert_same_material(&public, &tokenator_keys::to_public(&key), "expanded public");
}

#[test]
fn jwk_type_helpers() {
    let text = br#"{"kty":"OKP", "crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","n":5,"kty":"dup"}"#;
    let jwk = Jwk::parse(text).unwrap();
    assert_eq!(jwk.member_names(), ["kty", "crv", "x", "n", "kty"]);
    assert_eq!(jwk.get_str("kty"), Some("OKP"), "first of duplicates");
    assert_eq!(jwk.get_str("n"), None, "not a string");
    assert_eq!(jwk.get_str("missing"), None);
    assert_eq!(
        jwk.to_json(),
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","n":5,"kty":"dup"}"#
    );
    assert!(jwk.node().members().is_some());

    // Not an object.
    for bad in [&b"[]"[..], b"\"kty\"", b"1", b"null", b"", b"{"] {
        assert!(
            Jwk::parse(bad).is_err(),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
    // from_node on an embedded cnf.jwk.
    let doc = tokenator_json::parse(br#"{"cnf":{"jwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}}"#).unwrap();
    let inner = doc.pointer("/cnf/jwk").unwrap();
    let jwk = Jwk::from_node(inner).unwrap();
    assert_eq!(
        from_jwk(&jwk).unwrap(),
        import_fixture("rfc8037/ed25519-public.json")
    );
    assert!(Jwk::from_node(doc.pointer("/cnf").unwrap()).is_ok());
    assert!(Jwk::from_node(&tokenator_json::Node::new(tokenator_json::Value::Null)).is_err());
}

#[test]
fn cose_key_from_embedded_item() {
    // A cnf-style wrapper {1: COSE_Key}.
    let key_bytes = fixture("rfc9679/ec2-p256.cbor");
    let inner = tokenator_cbor::decode(&key_bytes).unwrap();
    let wrapper = Item::map(vec![(Item::int(1), inner)]);
    let encoded = tokenator_cbor::encode(&wrapper, EncodeMode::Preserve).unwrap();
    let decoded = tokenator_cbor::decode(&encoded).unwrap();
    let Value::Map(entries) = &decoded.value else {
        panic!()
    };
    let cwk = CoseKey::from_item(&entries[0].1).unwrap();
    assert_eq!(
        from_cwk(&cwk).unwrap(),
        import_fixture("rfc9679/ec2-p256.cbor")
    );
}

#[test]
fn jwk_import_into_cose_matches_rfc_cose_key() {
    // RFC 9964 publishes the same key as JWK and as COSE_Key.
    for p in ["44", "65", "87"] {
        let jose = import_fixture(&format!("rfc9964/ml-dsa-{p}-private.jwk.json"));
        let cose = import_fixture(&format!("rfc9964/ml-dsa-{p}-private.cbor"));
        let mut converted = cwk_of(&jose, Visibility::Private);
        converted.kid = cose.kid.clone();
        assert_eq!(converted, cose, "ML-DSA-{p}");
    }
}

#[test]
fn import_detects_json_and_cbor() {
    let jwk = export(&sample_key(Kind::P256), KeyFormat::Jwk, Visibility::Public).unwrap();
    let mut padded = b"  \n\t".to_vec();
    padded.extend(&jwk);
    padded.extend(b"\n");
    assert_eq!(import(&padded, None).unwrap().len(), 1);
}
