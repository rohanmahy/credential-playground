//! Key panel flows: import every fixture, export, derive public, generate,
//! thumbprints, kids, JWK ↔ CWK.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use base64ct::{Base64UrlUnpadded, Encoding};
use common::*;
use tokenator_core::{
    AssignKidRequest, Bytes, Engine, ErrorCode, HashName, KeyConvertRequest, KeyExportRequest,
    KeyFormat, KeyGenRequest, KeyImportRequest, KeyInfo, KeyRef, KeySeed, KeySpec, KidSource,
    KidValue, Kind, PemEncoding, Role, ThumbprintKind, ThumbprintRequest, Visibility,
};

const RFC7638_THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
const RFC8037_THUMBPRINT: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
const RFC9679_THUMBPRINT: &str = "496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec";
const RFC9964_44_KID: &str = "T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o";

fn import(e: &Engine, bytes: Vec<u8>) -> Vec<KeyInfo> {
    e.key_import(&KeyImportRequest {
        bytes: bytes.into(),
        format: None,
    })
    .unwrap()
}

fn import_one(e: &Engine, name: &str) -> KeyInfo {
    let mut keys = import(e, key_file(name));
    assert_eq!(keys.len(), 1, "{name}");
    keys.remove(0)
}

fn export(e: &Engine, key: &KeyRef, format: KeyFormat, visibility: Visibility) -> Vec<u8> {
    e.key_export(&KeyExportRequest {
        key: key.clone(),
        format,
        visibility,
    })
    .unwrap()
    .bytes
    .0
}

fn generate(e: &Engine, spec: KeySpec, seed: KeySeed) -> KeyInfo {
    e.key_generate(&KeyGenRequest {
        spec,
        role: None,
        seed,
        kid: None,
    })
    .unwrap()
}

// ---------------------------------------------------------------- import

#[test]
fn every_openssl_pem_imports() {
    let e = engine();
    let dir = testdata("keys/openssl");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|x| x.to_str()) != Some("pem") {
            continue;
        }
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let k = import_one(&e, &format!("openssl/{name}"));
        seen += 1;
        let public = name.contains("spki") || name.contains("pkcs1-pub");
        assert_eq!(k.private, !public, "{name}");
        let (kty, crv, bits, set) = match &name[..name.find(['-', '.']).unwrap()] {
            "p256" => ("EC", Some("P-256"), None, None),
            "p384" => ("EC", Some("P-384"), None, None),
            "p521" => ("EC", Some("P-521"), None, None),
            "ed25519" => ("OKP", Some("Ed25519"), None, None),
            "rsa2048" | "rsapss2048" => ("RSA", None, Some(2048), None),
            "rsa3072" => ("RSA", None, Some(3072), None),
            "rsa4096" => ("RSA", None, Some(4096), None),
            "mldsa44" => ("AKP", None, None, Some("ML-DSA-44")),
            "mldsa65" => ("AKP", None, None, Some("ML-DSA-65")),
            "mldsa87" => ("AKP", None, None, Some("ML-DSA-87")),
            other => panic!("unexpected fixture {other}"),
        };
        assert_eq!(k.kty, kty, "{name}");
        assert_eq!(k.crv.as_deref(), crv, "{name}");
        assert_eq!(k.bits, bits, "{name}");
        assert_eq!(k.param_set.as_deref(), set, "{name}");
        assert!(!k.algs.is_empty(), "{name}");
    }
    assert!(seen >= 40, "{seen} PEM fixtures");
}

#[test]
fn unsupported_keys_fail_cleanly() {
    let e = engine();
    for entry in std::fs::read_dir(testdata("keys/openssl/unsupported")).unwrap() {
        let path = entry.unwrap().path();
        let err = e
            .key_import(&KeyImportRequest {
                bytes: std::fs::read(&path).unwrap().into(),
                format: None,
            })
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Key, "{}", path.display());
    }
    for name in [
        "rfc7517-a3-symmetric.jwks.json",
        "rfc8410-s10.2-x25519-cert.pem",
    ] {
        let err = e
            .key_import(&KeyImportRequest {
                bytes: key_file(name).into(),
                format: None,
            })
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Key, "{name}");
    }
}

#[test]
fn top_level_key_fixtures_import() {
    let e = engine();
    let cases = [
        ("rfc7517-a1-public.jwks.json", 2, false),
        ("rfc7517-a2-private.jwks.json", 2, true),
        ("rfc9901-a5-ec-p256-public.jwk.json", 1, false),
        ("sd-cwt-08-c1-holder-private.jwk.json", 1, true),
        ("sd-cwt-08-c1-holder-private.cosekey.cbor", 1, true),
        ("sd-cwt-08-c2-issuer-private.cosekey.cbor", 1, true),
        ("rfc8392-a2.3-ec-p256.cosekey.cbor", 1, true),
        ("rfc8152-c7.1-public.cosekeyset.cbor", 4, false),
        ("sd-cwt-08-c1-holder-public.pem", 1, false),
        ("sd-cwt-08-c1-holder-private.pem", 1, true),
        ("derived-sd-cwt-08-c1-holder-private.sec1.pem", 1, true),
        ("rfc8410-s10.1-ed25519-public.pem", 1, false),
        ("rfc8410-s10.3-ed25519-private.pem", 1, true),
    ];
    for (name, count, private) in cases {
        let keys = import(&e, key_file(name));
        assert_eq!(keys.len(), count, "{name}");
        assert!(keys.iter().all(|k| k.private == private), "{name}");
    }
    // The three encodings of the sd-cwt-08 C.1 holder key are one key.
    let a = import_one(&e, "sd-cwt-08-c1-holder-private.jwk.json");
    let b = import_one(&e, "sd-cwt-08-c1-holder-private.cosekey.cbor");
    let c = import_one(&e, "sd-cwt-08-c1-holder-private.pem");
    assert_eq!(a.jwk_thumbprint, b.jwk_thumbprint);
    assert_eq!(a.cose_thumbprint, c.cose_thumbprint);
}

#[test]
fn imported_kids_keep_their_type() {
    let e = engine();
    let k = import_one(&e, "rfc8392-a2.3-ec-p256.cosekey.cbor");
    assert_eq!(
        k.kid,
        Some(KidValue::Bytes {
            value: Bytes(b"AsymmetricECDSA256".to_vec())
        })
    );
    let k = import_one(&e, "rfc9901-a5-ec-p256-public.jwk.json");
    assert_eq!(k.kid, None);
    let set = import(&e, key_file("rfc7517-a1-public.jwks.json"));
    assert!(matches!(&set[0].kid, Some(KidValue::Text { .. })));
}

#[test]
fn each_set_member_gets_a_self_contained_reference() {
    let e = engine();
    for name in [
        "rfc7517-a1-public.jwks.json",
        "rfc8152-c7.1-public.cosekeyset.cbor",
    ] {
        for k in import(&e, key_file(name)) {
            assert_eq!(k.key.index, 0, "{name}");
            let again = e.key_import(&KeyImportRequest {
                bytes: k.key.bytes.clone(),
                format: k.key.format,
            });
            let again = again.unwrap();
            assert_eq!(again.len(), 1, "{name}");
            assert_eq!(again[0].jwk_thumbprint, k.jwk_thumbprint, "{name}");
            assert_eq!(again[0].kid, k.kid, "{name}");
        }
    }
}

#[test]
fn key_refs_can_point_into_a_set() {
    let e = engine();
    let set = key_file("rfc8152-c7.1-public.cosekeyset.cbor");
    let all = import(&e, set.clone());
    for (i, k) in all.iter().enumerate() {
        let mut r = KeyRef::new(set.clone());
        r.index = i as u32;
        assert_eq!(e.key_public(&r).unwrap().cose_thumbprint, k.cose_thumbprint);
    }
    let mut r = KeyRef::new(set);
    r.index = 4;
    assert_eq!(e.key_public(&r).unwrap_err().code, ErrorCode::Key);
}

#[test]
fn edn_cose_keys_import() {
    // SPEC §4.2: COSE_Key in binary CBOR or EDN.
    let e = engine();
    let bytes = key_file("rfc9679/ec2-p256.cbor");
    let item = tokenator_cbor::decode(&bytes).unwrap();
    let text = tokenator_edn::print(&item, &tokenator_edn::PrintOptions::default()).text;
    let keys = import(&e, text.into_bytes());
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].cose_thumbprint, RFC9679_THUMBPRINT);
}

#[test]
fn format_hints_are_honored() {
    let e = engine();
    let err = e
        .key_import(&KeyImportRequest {
            bytes: key_file("rfc9901-a5-ec-p256-public.jwk.json").into(),
            format: Some(KeyFormat::CoseKey),
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Key);
    let ok = e
        .key_import(&KeyImportRequest {
            bytes: key_file("sd-cwt-08-c1-holder-public.pem").into(),
            format: Some(KeyFormat::Pem {
                encoding: PemEncoding::Auto,
            }),
        })
        .unwrap();
    assert_eq!(ok.len(), 1);
}

// ---------------------------------------------------------------- thumbprints

#[test]
fn rfc_thumbprints() {
    let e = engine();
    let k = import_one(&e, "rfc7638/rsa.json");
    assert_eq!(k.jwk_thumbprint, RFC7638_THUMBPRINT);
    assert_eq!(
        k.jwk_thumbprint_uri,
        format!("urn:ietf:params:oauth:jwk-thumbprint:sha-256:{RFC7638_THUMBPRINT}")
    );
    let k = import_one(&e, "rfc8037/ed25519-public.json");
    assert_eq!(k.jwk_thumbprint, RFC8037_THUMBPRINT);
    let k = import_one(&e, "rfc9679/ec2-p256.cbor");
    assert_eq!(k.cose_thumbprint, RFC9679_THUMBPRINT);
    let b64 = Base64UrlUnpadded::encode_string(&hexd(RFC9679_THUMBPRINT));
    assert_eq!(
        k.cose_thumbprint_uri,
        format!("urn:ietf:params:oauth:ckt:sha-256:{b64}")
    );
    let k = import_one(&e, "rfc9964/ml-dsa-44-public.jwk.json");
    assert_eq!(k.jwk_thumbprint, RFC9964_44_KID);
}

#[test]
fn key_thumbprint_forms_and_hashes() {
    let e = engine();
    let key = key_ref("rfc9679/ec2-p256.cbor");
    let t = e
        .key_thumbprint(&ThumbprintRequest {
            key: key.clone(),
            kind: ThumbprintKind::Cose,
            hash: HashName::Sha256,
        })
        .unwrap();
    assert_eq!(t.hex, RFC9679_THUMBPRINT);
    assert_eq!(
        t.base64url,
        Base64UrlUnpadded::encode_string(&hexd(RFC9679_THUMBPRINT))
    );
    assert!(t.uri.starts_with("urn:ietf:params:oauth:ckt:sha-256:"));
    for (hash, len, name) in [
        (HashName::Sha384, 48, "sha-384"),
        (HashName::Sha512, 64, "sha-512"),
    ] {
        let t = e
            .key_thumbprint(&ThumbprintRequest {
                key: key.clone(),
                kind: ThumbprintKind::Jwk,
                hash,
            })
            .unwrap();
        assert_eq!(t.hex.len(), 2 * len);
        assert!(t.uri.contains(name), "{}", t.uri);
    }
}

// ---------------------------------------------------------------- generate

#[test]
fn well_known_seed_reproduces_rfc9964() {
    let e = engine();
    let k = e
        .key_generate(&KeyGenRequest {
            spec: KeySpec::MlDsa44,
            role: Some(Role::Issuer),
            seed: KeySeed::WellKnown,
            kid: Some(KidSource::JwkThumbprint {
                hash: HashName::Sha256,
            }),
        })
        .unwrap();
    assert_eq!(
        k.kid,
        Some(KidValue::Text {
            value: RFC9964_44_KID.into()
        })
    );
    assert_eq!(k.role, Some(Role::Issuer));
    assert_eq!(k.key.role, Some(Role::Issuer));
    assert!(k.private);
    let fixture = import_one(&e, "rfc9964/ml-dsa-44-private.jwk.json");
    assert_eq!(k.jwk_thumbprint, fixture.jwk_thumbprint);
}

#[test]
fn seeded_generation_is_deterministic() {
    let e = engine();
    let specs = [
        KeySpec::P256,
        KeySpec::P384,
        KeySpec::P521,
        KeySpec::Ed25519,
        KeySpec::MlDsa44,
        KeySpec::MlDsa65,
        KeySpec::MlDsa87,
    ];
    for spec in specs {
        let a = generate(&e, spec, KeySeed::Seed { bytes: seed(1) });
        let b = generate(&e, spec, KeySeed::Seed { bytes: seed(1) });
        let c = generate(&e, spec, KeySeed::Seed { bytes: seed(2) });
        assert_eq!(json(&a), json(&b), "{spec:?}");
        assert_ne!(a.jwk_thumbprint, c.jwk_thumbprint, "{spec:?}");
        // Short seeds are hashed, not rejected.
        generate(
            &e,
            spec,
            KeySeed::Seed {
                bytes: Bytes(b"tokenator".to_vec()),
            },
        );
    }
}

#[test]
fn entropy_generation_needs_32_bytes() {
    let e = engine();
    let a = generate(&e, KeySpec::P256, KeySeed::Entropy { bytes: seed(9) });
    let b = generate(&e, KeySpec::P256, KeySeed::Entropy { bytes: seed(9) });
    assert_eq!(a.jwk_thumbprint, b.jwk_thumbprint, "no ambient randomness");
    let err = e
        .key_generate(&KeyGenRequest {
            spec: KeySpec::P256,
            role: None,
            seed: KeySeed::Entropy {
                bytes: Bytes(vec![1; 5]),
            },
            kid: None,
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Randomness);
}

#[test]
fn generated_key_cards_describe_the_key() {
    let e = engine();
    let cases = [
        (
            KeySpec::P256,
            "EC",
            Some("P-256"),
            "EC P-256",
            vec!["ES256"],
        ),
        (
            KeySpec::P384,
            "EC",
            Some("P-384"),
            "EC P-384",
            vec!["ES384"],
        ),
        (
            KeySpec::P521,
            "EC",
            Some("P-521"),
            "EC P-521",
            vec!["ES512"],
        ),
        (
            KeySpec::Ed25519,
            "OKP",
            Some("Ed25519"),
            "Ed25519",
            vec!["EdDSA", "Ed25519"],
        ),
        (
            KeySpec::MlDsa65,
            "AKP",
            None,
            "ML-DSA-65",
            vec!["ML-DSA-65"],
        ),
    ];
    for (spec, kty, crv, description, algs) in cases {
        let k = gen_key(&e, spec, 1);
        assert_eq!(k.kty, kty);
        assert_eq!(k.crv.as_deref(), crv);
        assert_eq!(k.description, description);
        for alg in algs {
            assert!(k.algs.iter().any(|a| a == alg), "{spec:?}: {:?}", k.algs);
        }
    }
}

// ---------------------------------------------------------------- public, export

#[test]
fn derive_public_key() {
    let e = engine();
    let private = gen_key(&e, KeySpec::P256, 1);
    let public = e.key_public(&private.key).unwrap();
    assert!(!public.private);
    assert_eq!(public.jwk_thumbprint, private.jwk_thumbprint);
    assert_eq!(public.cose_thumbprint, private.cose_thumbprint);
    let err = e
        .key_export(&KeyExportRequest {
            key: public.key,
            format: KeyFormat::Jwk,
            visibility: Visibility::Private,
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::NoPrivateKey);
}

#[test]
fn export_formats() {
    let e = engine();
    let k = gen_key(&e, KeySpec::P256, 1);
    let pkcs8 = e
        .key_export(&KeyExportRequest {
            key: k.key.clone(),
            format: KeyFormat::Pem {
                encoding: PemEncoding::Pkcs8,
            },
            visibility: Visibility::Private,
        })
        .unwrap();
    assert!(pkcs8.private);
    assert!(
        pkcs8
            .text
            .unwrap()
            .starts_with("-----BEGIN PRIVATE KEY-----")
    );

    let spki = e
        .key_export(&KeyExportRequest {
            key: k.key.clone(),
            format: KeyFormat::Pem {
                encoding: PemEncoding::Auto,
            },
            visibility: Visibility::Public,
        })
        .unwrap();
    assert!(!spki.private);
    assert!(spki.text.unwrap().starts_with("-----BEGIN PUBLIC KEY-----"));

    let sec1 = export(
        &e,
        &k.key,
        KeyFormat::Pem {
            encoding: PemEncoding::Sec1,
        },
        Visibility::Private,
    );
    assert!(sec1.starts_with(b"-----BEGIN EC PRIVATE KEY-----"));

    let jwk: serde_json::Value =
        serde_json::from_slice(&export(&e, &k.key, KeyFormat::Jwk, Visibility::Public)).unwrap();
    assert_eq!(jwk["kty"], "EC");
    assert!(jwk.get("d").is_none());

    let cbor = e
        .key_export(&KeyExportRequest {
            key: k.key.clone(),
            format: KeyFormat::CoseKey,
            visibility: Visibility::Private,
        })
        .unwrap();
    assert!(cbor.text.is_none());
    let back = import(&e, cbor.bytes.0);
    assert!(back[0].private);
    assert_eq!(back[0].cose_thumbprint, k.cose_thumbprint);

    let set = export(&e, &k.key, KeyFormat::JwkSet, Visibility::Public);
    let set: serde_json::Value = serde_json::from_slice(&set).unwrap();
    assert_eq!(set["keys"].as_array().unwrap().len(), 1);

    let err = e
        .key_export(&KeyExportRequest {
            key: k.key,
            format: KeyFormat::Pem {
                encoding: PemEncoding::Pkcs1,
            },
            visibility: Visibility::Private,
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Key, "PKCS#1 is RSA only");
}

#[test]
fn ml_dsa_private_forms() {
    let e = engine();
    let k = generate(&e, KeySpec::MlDsa44, KeySeed::WellKnown);
    for (encoding, needle) in [
        (PemEncoding::Pkcs8MlDsaSeed, "PRIVATE KEY"),
        (PemEncoding::Pkcs8MlDsaExpanded, "PRIVATE KEY"),
        (PemEncoding::Pkcs8MlDsaBoth, "PRIVATE KEY"),
    ] {
        let pem = export(&e, &k.key, KeyFormat::Pem { encoding }, Visibility::Private);
        assert!(String::from_utf8(pem.clone()).unwrap().contains(needle));
        assert_eq!(import(&e, pem)[0].jwk_thumbprint, k.jwk_thumbprint);
    }
}

// ---------------------------------------------------------------- kid

#[test]
fn assign_kid_from_each_source() {
    let e = engine();
    let k = gen_key(&e, KeySpec::P256, 1);
    let assign = |source| {
        e.key_assign_kid(&AssignKidRequest {
            key: k.key.clone(),
            source,
        })
        .unwrap()
    };
    let t = assign(KidSource::JwkThumbprint {
        hash: HashName::Sha256,
    });
    assert_eq!(
        t.kid,
        Some(KidValue::Text {
            value: k.jwk_thumbprint.clone()
        })
    );
    let c = assign(KidSource::CoseThumbprint {
        hash: HashName::Sha256,
    });
    assert_eq!(
        c.kid,
        Some(KidValue::Bytes {
            value: Bytes(hexd(&k.cose_thumbprint))
        })
    );
    // A binary kid survives the trip through the card's own reference.
    assert_eq!(e.key_public(&c.key).unwrap().kid, c.kid);
    let s = assign(KidSource::Text {
        value: "issuer-1".into(),
    });
    assert_eq!(
        s.kid,
        Some(KidValue::Text {
            value: "issuer-1".into()
        })
    );
    let b = assign(KidSource::Bytes {
        value: Bytes(vec![0xff, 0x00]),
    });
    assert_eq!(e.key_public(&b.key).unwrap().kid, b.kid);
    // Thumbprints never depend on the kid.
    assert_eq!(s.jwk_thumbprint, k.jwk_thumbprint);
}

// ---------------------------------------------------------------- JWK ↔ CWK

#[test]
fn key_to_jwk_public_and_private() {
    let e = engine();
    let k = key_ref("sd-cwt-08-c1-holder-private.cosekey.cbor");
    let to = |visibility| {
        e.key_to_jwk(&KeyConvertRequest {
            key: k.clone(),
            visibility,
        })
        .unwrap()
    };
    let public: serde_json::Value = serde_json::from_str(&to(Visibility::Public)).unwrap();
    let private: serde_json::Value = serde_json::from_str(&to(Visibility::Private)).unwrap();
    assert_eq!(public["crv"], "P-256");
    assert!(public.get("d").is_none());
    assert!(private.get("d").is_some());
    let expected: serde_json::Value =
        serde_json::from_slice(&key_file("sd-cwt-08-c1-holder-private.jwk.json")).unwrap();
    for m in ["kty", "crv", "x", "y", "d"] {
        assert_eq!(private[m], expected[m], "{m}");
    }
}

#[test]
fn key_to_cwk_is_a_cose_key_document() {
    let e = engine();
    let k = key_ref("sd-cwt-08-c1-holder-private.jwk.json");
    let doc = e
        .key_to_cwk(&KeyConvertRequest {
            key: k,
            visibility: Visibility::Public,
        })
        .unwrap();
    assert_eq!(doc.kind, Kind::CoseKey);
    assert!(!doc.signed);
    assert_eq!(main_text(&doc, "1"), "2", "kty EC2");
    assert_eq!(main_text(&doc, "-1"), "1", "crv P-256");
    assert!(has_node(&doc, "-2") && has_node(&doc, "-3"));
    assert!(!has_node(&doc, "-4"), "public only");
    assert!(doc.main.text.contains("/ kty /"), "{}", doc.main.text);
    assert_eq!(hex_bytes(&doc), &doc.bytes[..]);
    let back = import(&e, doc.bytes.0.clone());
    let original = import_one(&e, "sd-cwt-08-c1-holder-private.jwk.json");
    assert_eq!(back[0].cose_thumbprint, original.cose_thumbprint);
}

#[test]
fn jwk_cwk_round_trip_keeps_kid_and_material() {
    let e = engine();
    for name in [
        "rfc7517-a2-private.jwks.json",
        "rfc9964/ml-dsa-65-private.jwk.json",
    ] {
        for k in import(&e, key_file(name)) {
            let cwk = e
                .key_to_cwk(&KeyConvertRequest {
                    key: k.key.clone(),
                    visibility: Visibility::Private,
                })
                .unwrap();
            let jwk = e
                .key_to_jwk(&KeyConvertRequest {
                    key: KeyRef::new(cwk.bytes.clone()),
                    visibility: Visibility::Private,
                })
                .unwrap();
            let back = import(&e, jwk.into_bytes()).remove(0);
            assert_eq!(back.jwk_thumbprint, k.jwk_thumbprint, "{name}");
            assert_eq!(back.private, k.private, "{name}");
            if let Some(KidValue::Text { value }) = &k.kid {
                assert_eq!(
                    back.kid,
                    Some(KidValue::Text {
                        value: value.clone()
                    }),
                    "{name}"
                );
            }
        }
    }
}

#[test]
fn key_operations_reject_garbage() {
    let e = engine();
    let bad = KeyRef::new(b"not a key".to_vec());
    assert_eq!(e.key_public(&bad).unwrap_err().code, ErrorCode::Key);
    assert_eq!(
        e.key_to_jwk(&KeyConvertRequest {
            key: bad.clone(),
            visibility: Visibility::Public
        })
        .unwrap_err()
        .code,
        ErrorCode::Key
    );
    assert_eq!(
        e.key_thumbprint(&ThumbprintRequest {
            key: bad,
            kind: ThumbprintKind::Jwk,
            hash: HashName::Sha256
        })
        .unwrap_err()
        .code,
        ErrorCode::Key
    );
}
