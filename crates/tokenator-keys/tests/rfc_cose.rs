//! COSE known-answer tests: RFC 8152 Appendix C.7 COSE_KeySets (the same
//! keys as the RFC 9052 examples), RFC 9679 §5.7/§6, RFC 9964 Appendix A.2.

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_cbor::{Item, Value};
use tokenator_crypto::{
    Alg, Curve, KeyType, MlDsaParams, PrivateKeyMaterial, PublicKeyMaterial, verify,
};
use tokenator_keys::{
    CoseKey, DeclaredAlg, HashAlg, KeyError, KeyFormat, Kid, ThumbprintKind, Visibility,
    cose_thumbprint, cose_thumbprint_uri, export, from_cwk, import, import_each, params,
    thumbprint, to_cwk, to_public,
};

const RFC9679_X: &str = "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d";
const RFC9679_Y: &str = "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c";
const RFC9679_THUMBPRINT: &str = "496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec";

const RFC8152_KIDS: [&str; 4] = [
    "meriadoc.brandybuck@buckland.example",
    "11",
    "bilbo.baggins@hobbiton.example",
    "peregrin.took@tuckborough.example",
];

// ---------------------------------------------------------------- RFC 8152

#[test]
fn rfc8152_c7_1_public_keyset() {
    let keys = import(&fixture("rfc8152/c7-1-public-keyset.cbor"), None).unwrap();
    assert_eq!(keys.len(), 4);
    for (key, kid) in keys.iter().zip(RFC8152_KIDS) {
        assert!(!key.is_private(), "{kid}");
        assert_eq!(key.key_type(), KeyType::Ec);
        assert_eq!(key.kid, Some(Kid::Bytes(kid.as_bytes().to_vec())));
        assert_eq!(key.alg, None);
    }
    assert_eq!(params(&keys[0]).crv, Some(Curve::P256));
    assert_eq!(params(&keys[2]).crv, Some(Curve::P521));
    assert_eq!(
        keys[0].public_key().to_material(),
        PublicKeyMaterial::Ec {
            curve: Curve::P256,
            x: hex::decode(RFC9679_X).unwrap(),
            y: hex::decode(RFC9679_Y).unwrap(),
        }
    );
}

#[test]
fn rfc8152_same_result_with_set_or_key_hint() {
    let input = fixture("rfc8152/c7-1-public-keyset.cbor");
    let detected = import(&input, None).unwrap();
    for hint in [KeyFormat::CoseKeySet, KeyFormat::CoseKey] {
        assert_eq!(import(&input, Some(hint)).unwrap(), detected, "{hint:?}");
    }
}

#[test]
fn rfc8152_c7_2_private_keyset_with_symmetric_keys() {
    let input = fixture("rfc8152/c7-2-private-keyset.cbor");
    // Symmetric (kty 4) keys are not supported, so the strict import fails...
    assert_eq!(
        import(&input, None).unwrap_err(),
        KeyError::UnsupportedKeyType("4".into())
    );
    // ...and import_each reports each key separately, in order.
    let each = import_each(&input, None).unwrap();
    assert_eq!(each.len(), 7);
    for i in [3, 5, 6] {
        assert_eq!(
            each[i].as_ref().unwrap_err(),
            &KeyError::UnsupportedKeyType("4".into()),
            "#{i}"
        );
    }
    let ok: Vec<_> = [0, 1, 2, 4]
        .into_iter()
        .map(|i| each[i].clone().unwrap())
        .collect();
    let public = import(&fixture("rfc8152/c7-1-public-keyset.cbor"), None).unwrap();
    for (privk, pubk) in ok.iter().zip(&public) {
        assert!(privk.is_private());
        assert_eq!(privk.kid, pubk.kid);
        assert_same_material(&to_public(privk), pubk, "C.7.2 vs C.7.1");
    }
    match ok[0].private_key().unwrap().to_material() {
        PrivateKeyMaterial::Ec { curve, d } => {
            assert_eq!(curve, Curve::P256);
            assert_eq!(
                hex::encode(d),
                "aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf"
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn rfc8152_first_key_thumbprint_is_rfc9679() {
    let keys = import(&fixture("rfc8152/c7-1-public-keyset.cbor"), None).unwrap();
    assert_eq!(
        hex::encode(thumbprint(&keys[0], ThumbprintKind::Cose, HashAlg::Sha256)),
        RFC9679_THUMBPRINT
    );
}

// ---------------------------------------------------------------- RFC 9679

#[test]
fn rfc9679_s6_thumbprint() {
    let bytes = fixture("rfc9679/ec2-p256.cbor");
    let key = import_one(&bytes, None);
    let tp = thumbprint(&key, ThumbprintKind::Cose, HashAlg::Sha256);
    assert_eq!(hex::encode(&tp), RFC9679_THUMBPRINT);
    assert_eq!(
        key.kid,
        Some(Kid::Bytes(tp.clone())),
        "the example's kid is its thumbprint"
    );

    let cwk = CoseKey::decode(&bytes).unwrap();
    assert_eq!(cose_thumbprint(&cwk, HashAlg::Sha256).unwrap(), tp);
}

#[test]
fn rfc9679_s5_7_uri() {
    let key = import_fixture("rfc9679/ec2-p256.cbor");
    assert_eq!(
        cose_thumbprint_uri(&key, HashAlg::Sha256),
        "urn:ietf:params:oauth:ckt:sha-256:SWvYr63zB-WwjGSwQhv53AFSijRKQ72oj63RZp2iU-w"
    );
    let uri = cose_thumbprint_uri(&key, HashAlg::Sha512);
    let prefix = "urn:ietf:params:oauth:ckt:sha-512:";
    assert!(uri.starts_with(prefix), "{uri}");
    assert_eq!(
        unb64u(&uri[prefix.len()..]),
        thumbprint(&key, ThumbprintKind::Cose, HashAlg::Sha512)
    );
}

#[test]
fn rfc9679_to_cwk_exact_bytes() {
    // Canonical order 1, 2, -1, -2, -3 with preferred encoding.
    let key = import_fixture("rfc9679/ec2-p256.cbor");
    let tp = hex::decode(RFC9679_THUMBPRINT).unwrap();
    let mut expected = vec![0xa5, 0x01, 0x02, 0x02, 0x58, 0x20];
    expected.extend(&tp);
    expected.extend([0x20, 0x01, 0x21, 0x58, 0x20]);
    expected.extend(hex::decode(RFC9679_X).unwrap());
    expected.extend([0x22, 0x58, 0x20]);
    expected.extend(hex::decode(RFC9679_Y).unwrap());
    assert_eq!(
        to_cwk(&key, Visibility::Public).unwrap().to_cbor(),
        expected
    );
    assert_eq!(
        export(&key, KeyFormat::CoseKey, Visibility::Public).unwrap(),
        expected
    );
}

#[test]
fn cose_key_decode_preserves_bytes() {
    for rel in [
        "rfc9679/ec2-p256.cbor",
        "rfc9964/ml-dsa-44-private.cbor",
        "rfc9964/ml-dsa-87-public.cbor",
    ] {
        let bytes = fixture(rel);
        let cwk = CoseKey::decode(&bytes).unwrap();
        assert_eq!(cwk.to_cbor(), bytes, "{rel}");
    }
}

#[test]
fn cose_key_accessors() {
    let cwk = CoseKey::decode(&fixture("rfc9679/ec2-p256.cbor")).unwrap();
    assert_eq!(
        cwk.labels(),
        [1, -1, -2, -3, 2].map(tokenator_keys::Label::Int).to_vec(),
        "arrival order"
    );
    assert_eq!(cwk.get(1).map(|i| int(&i.value)), Some(2));
    assert_eq!(cwk.get(-1).map(|i| int(&i.value)), Some(1));
    assert_eq!(
        cwk.get(-2).map(cbor_bytes),
        Some(hex::decode(RFC9679_X).unwrap())
    );
    assert!(cwk.get(-4).is_none());
    assert!(matches!(cwk.item().value, Value::Map(_)));
}

#[test]
fn cose_key_from_item_matches_decode() {
    let bytes = fixture("rfc9679/ec2-p256.cbor");
    let item = tokenator_cbor::decode(&bytes).unwrap();
    assert_eq!(
        CoseKey::from_item(&item).unwrap(),
        CoseKey::decode(&bytes).unwrap()
    );
    // Not a map.
    assert!(CoseKey::from_item(&Item::int(1)).is_err());
    assert!(CoseKey::decode(&[0x80]).is_err());
}

#[test]
fn from_cwk_matches_import() {
    for rel in [
        "rfc9679/ec2-p256.cbor",
        "rfc9964/ml-dsa-65-private.cbor",
        "rfc9964/ml-dsa-65-public.cbor",
    ] {
        let cwk = CoseKey::decode(&fixture(rel)).unwrap();
        assert_eq!(from_cwk(&cwk).unwrap(), import_fixture(rel), "{rel}");
    }
}

// ---------------------------------------------------------------- RFC 9964

const ML_DSA: [(&str, MlDsaParams, Alg); 3] = [
    ("44", MlDsaParams::MlDsa44, Alg::MlDsa44),
    ("65", MlDsaParams::MlDsa65, Alg::MlDsa65),
    ("87", MlDsaParams::MlDsa87, Alg::MlDsa87),
];

#[test]
fn rfc9964_cose_private_key_imports() {
    for (p, params_set, alg) in ML_DSA {
        let kat = testdata_json(&format!("rfc9964/ml-dsa-{p}-cose.json"));
        let key = import_fixture(&format!("rfc9964/ml-dsa-{p}-private.cbor"));
        assert!(key.is_private());
        assert_eq!(key.key_type(), KeyType::Akp);
        assert_eq!(key.alg, Some(DeclaredAlg::Known(alg)));
        assert!(matches!(&key.kid, Some(Kid::Bytes(k)) if k.len() == 32));
        assert_eq!(
            key.public_key().to_material(),
            PublicKeyMaterial::MlDsa {
                params: params_set,
                public: hexv(&kat["raw_public_key"]),
            }
        );
        match key.private_key().unwrap().to_material() {
            PrivateKeyMaterial::MlDsa { seed, .. } => assert_eq!(seed, Some(vec![0; 32])),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn rfc9964_cose_kid_is_the_cose_thumbprint() {
    for (p, ..) in ML_DSA {
        for vis in ["private", "public"] {
            let rel = format!("rfc9964/ml-dsa-{p}-{vis}.cbor");
            let key = import_fixture(&rel);
            let tp = thumbprint(&key, ThumbprintKind::Cose, HashAlg::Sha256);
            assert_eq!(key.kid, Some(Kid::Bytes(tp.clone())), "{rel}");
            let cwk = CoseKey::decode(&fixture(&rel)).unwrap();
            assert_eq!(cose_thumbprint(&cwk, HashAlg::Sha256).unwrap(), tp);
        }
    }
}

#[test]
fn rfc9964_cose_and_jose_keys_agree() {
    for (p, ..) in ML_DSA {
        let cose = import_fixture(&format!("rfc9964/ml-dsa-{p}-private.cbor"));
        let jose = import_fixture(&format!("rfc9964/ml-dsa-{p}-private.jwk.json"));
        assert_same_material(&cose, &jose, p);
        assert_eq!(cose.alg, jose.alg);
        // Different kids: one is the COSE thumbprint, the other the JWK one.
        assert_ne!(
            cose.kid.as_ref().unwrap().as_bytes(),
            jose.kid.as_ref().unwrap().as_bytes()
        );
    }
}

#[test]
fn rfc9964_cose_sign1_verifies_with_imported_key() {
    for (p, _, alg) in ML_DSA {
        let kat = testdata_json(&format!("rfc9964/ml-dsa-{p}-cose.json"));
        let key = import_fixture(&format!("rfc9964/ml-dsa-{p}-public.cbor"));
        verify(
            alg,
            &key.public_key(),
            &hexv(&kat["raw_to_be_signed"]),
            &hexv(&kat["raw_signature"]),
        )
        .unwrap();
    }
}

#[test]
fn rfc9964_to_cwk_order_and_values() {
    for (p, ..) in ML_DSA {
        let rel = format!("rfc9964/ml-dsa-{p}-private.cbor");
        let original = fixture(&rel);
        let key = import_one(&original, None);
        let out = export(&key, KeyFormat::CoseKey, Visibility::Private).unwrap();
        assert_eq!(cbor_int_labels(&out), [1, 2, 3, -1, -2]);
        // The RFC map starts with the kid, so compare values, not spans.
        for label in [1, 2, 3, -1, -2] {
            assert_eq!(
                cbor_get(&out, label).map(|i| i.value),
                cbor_get(&original, label).map(|i| i.value),
                "label {label}"
            );
        }
        let public = export(&key, KeyFormat::CoseKey, Visibility::Public).unwrap();
        assert_eq!(cbor_int_labels(&public), [1, 2, 3, -1]);
    }
}

// ----------------------------------------------------- COSE-specific shapes

/// `{1: 2, -1: 1, -2: x, -3: y}` plus `extra` entries, preferred encoding.
fn ec2_map(extra: Vec<(Item<'static>, Item<'static>)>) -> Vec<u8> {
    let mut entries = vec![
        (Item::int(1), Item::int(2)),
        (Item::int(-1), Item::int(1)),
        (Item::int(-2), Item::bytes(hex::decode(RFC9679_X).unwrap())),
        (Item::int(-3), Item::bytes(hex::decode(RFC9679_Y).unwrap())),
    ];
    entries.extend(extra);
    tokenator_cbor::encode(&Item::map(entries), tokenator_cbor::EncodeMode::Preserve).unwrap()
}

#[test]
fn cose_text_kid_imports_as_text_and_exports_as_bstr() {
    let bytes = ec2_map(vec![(Item::int(2), Item::text("text-kid"))]);
    let key = import_one(&bytes, None);
    assert_eq!(key.kid, Some(Kid::Text("text-kid".into())));
    let out = export(&key, KeyFormat::CoseKey, Visibility::Public).unwrap();
    assert_eq!(
        cbor_get(&out, 2).map(|i| cbor_bytes(&i)),
        Some(b"text-kid".to_vec())
    );
}

#[test]
fn cose_unknown_labels_are_extras_in_order() {
    let bytes = ec2_map(vec![
        (Item::int(-70000), Item::text("private use")),
        (Item::int(5), Item::bytes(vec![1, 2, 3])),
        (
            Item::text("note"),
            Item::array(vec![Item::int(1), Item::new(Value::Bool(true))]),
        ),
    ]);
    let key = import_one(&bytes, None);
    assert_eq!(key.extras.len(), 3);
    let out = export(&key, KeyFormat::CoseKey, Visibility::Public).unwrap();
    let decoded = tokenator_cbor::decode(&out).unwrap();
    let Value::Map(entries) = decoded.value else {
        panic!()
    };
    let tail: Vec<_> = entries[entries.len() - 3..]
        .iter()
        .map(|(k, v)| {
            (
                k.value.clone(),
                tokenator_cbor::encode(v, tokenator_cbor::EncodeMode::Preserve).unwrap(),
            )
        })
        .collect();
    assert_eq!(tail[0].0, Value::Nint(69999));
    assert_eq!(tail[1].0, Value::Uint(5));
    assert_eq!(tail[1].1, [0x43, 1, 2, 3]);
    assert_eq!(tail[2].0, Value::Text("note".into()));
    assert_eq!(tail[2].1, [0x82, 0x01, 0xf5]);
}

#[test]
fn cose_compressed_point_is_an_error_not_a_panic() {
    // y as a bool (RFC 9053 §7.1.1 point compression) is not supported yet.
    let bytes = tokenator_cbor::encode(
        &Item::map(vec![
            (Item::int(1), Item::int(2)),
            (Item::int(-1), Item::int(1)),
            (Item::int(-2), Item::bytes(hex::decode(RFC9679_X).unwrap())),
            (Item::int(-3), Item::new(Value::Bool(true))),
        ]),
        tokenator_cbor::EncodeMode::Preserve,
    )
    .unwrap();
    assert!(import(&bytes, None).is_err());
    // params work without the material.
    let cwk = CoseKey::decode(&bytes).unwrap();
    assert_eq!(
        tokenator_keys::params_from_cwk(&cwk).unwrap().crv,
        Some(Curve::P256)
    );
}
