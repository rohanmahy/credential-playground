//! Malformed and mismatched JWK / COSE_Key input must give errors, never
//! panics. (PEM errors are in `pem.rs`.)

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
use tokenator_keys::{KeyError, KeyFormat, PemEncoding, import, import_each};

const EC_X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
const EC_Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";
const EC_D: &str = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE";
const ED_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const ED_D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";

fn jwk_err(json: &str) -> KeyError {
    match import(json.as_bytes(), None) {
        Ok(keys) => panic!("{json} imported: {keys:?}"),
        Err(e) => e,
    }
}

fn invalid(name: &str) -> impl Fn(&KeyError) -> bool + '_ {
    move |e| matches!(e, KeyError::InvalidParameter { name: n, .. } if n == name)
}

// --------------------------------------------------------------- JWK shape

#[test]
fn not_json_or_not_an_object() {
    assert!(matches!(jwk_err("{"), KeyError::Json(_)));
    assert!(matches!(jwk_err(r#"{"kty":"EC",}"#), KeyError::Json(_)));
    for text in ["[1]", "\"kty\"", "{\"keys\":5}", "{\"keys\":{}}"] {
        // JSON, but not a JWK or JWK Set. ("[1]" and the string are CBOR
        // by detection, so only check that they fail.)
        assert!(
            import(text.as_bytes(), Some(KeyFormat::Jwk)).is_err(),
            "{text}"
        );
    }
}

#[test]
fn missing_or_unsupported_kty() {
    assert_eq!(
        jwk_err(r#"{"crv":"P-256"}"#),
        KeyError::MissingParameter("kty".into())
    );
    assert_eq!(
        jwk_err(r#"{"kty":"oct","k":"AAAA"}"#),
        KeyError::UnsupportedKeyType("oct".into())
    );
    assert_eq!(
        jwk_err(r#"{"kty":"Ec"}"#),
        KeyError::UnsupportedKeyType("Ec".into())
    );
    assert!(invalid("kty")(&jwk_err(r#"{"kty":null}"#)));
}

#[test]
fn missing_required_members() {
    let cases = [
        (
            format!(r#"{{"kty":"EC","x":"{EC_X}","y":"{EC_Y}"}}"#),
            "crv",
        ),
        (format!(r#"{{"kty":"EC","crv":"P-256","y":"{EC_Y}"}}"#), "x"),
        (format!(r#"{{"kty":"EC","crv":"P-256","x":"{EC_X}"}}"#), "y"),
        (r#"{"kty":"OKP","crv":"Ed25519"}"#.to_string(), "x"),
        (format!(r#"{{"kty":"OKP","x":"{ED_X}"}}"#), "crv"),
        (r#"{"kty":"RSA","e":"AQAB"}"#.to_string(), "n"),
        (r#"{"kty":"RSA","n":"AQAB"}"#.to_string(), "e"),
        (r#"{"kty":"AKP","alg":"ML-DSA-44"}"#.to_string(), "pub"),
    ];
    for (json, member) in cases {
        assert_eq!(
            jwk_err(&json),
            KeyError::MissingParameter(member.into()),
            "{json}"
        );
    }
}

#[test]
fn akp_requires_alg() {
    let pubk = b64u(&vec![0u8; 1312]);
    assert_eq!(
        jwk_err(&format!(r#"{{"kty":"AKP","pub":"{pubk}"}}"#)),
        KeyError::MissingParameter("alg".into()),
        "RFC 9964 §3: alg is REQUIRED for AKP"
    );
}

#[test]
fn unsupported_curves() {
    assert_eq!(
        jwk_err(&format!(
            r#"{{"kty":"EC","crv":"secp256k1","x":"{EC_X}","y":"{EC_Y}"}}"#
        )),
        KeyError::UnsupportedCurve("secp256k1".into())
    );
    assert_eq!(
        jwk_err(&format!(r#"{{"kty":"OKP","crv":"X25519","x":"{ED_X}"}}"#)),
        KeyError::UnsupportedCurve("X25519".into())
    );
    assert_eq!(
        jwk_err(&format!(r#"{{"kty":"OKP","crv":"Ed448","x":"{ED_X}"}}"#)),
        KeyError::UnsupportedCurve("Ed448".into())
    );
}

#[test]
fn crv_kty_mismatch() {
    let e = jwk_err(&format!(
        r#"{{"kty":"EC","crv":"Ed25519","x":"{ED_X}","y":"{EC_Y}"}}"#
    ));
    assert!(matches!(e, KeyError::InconsistentKey(_)), "{e:?}");
    let e = jwk_err(&format!(r#"{{"kty":"OKP","crv":"P-256","x":"{EC_X}"}}"#));
    assert!(matches!(e, KeyError::InconsistentKey(_)), "{e:?}");
}

#[test]
fn bad_base64url() {
    let cases = [
        (
            format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{}$"}}"#, &ED_X[..42]),
            "x",
        ),
        // Standard alphabet is not base64url.
        (
            r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#
                .into(),
            "x",
        ),
        (
            format!(r#"{{"kty":"EC","crv":"P-256","x":"{EC_X}","y":"{EC_Y} "}}"#),
            "y",
        ),
        // A length that no base64url string can have.
        (
            format!(r#"{{"kty":"EC","crv":"P-256","x":"{EC_X}","y":"{EC_Y}","d":"A"}}"#),
            "d",
        ),
        (
            format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{ED_X}","d":"%%%%"}}"#),
            "d",
        ),
        (r#"{"kty":"RSA","n":"!!","e":"AQAB"}"#.into(), "n"),
    ];
    for (json, member) in cases {
        let e = jwk_err(&json);
        assert!(invalid(member)(&e), "{json}: {e:?}");
    }
}

#[test]
fn wrong_member_types() {
    let cases = [
        (r#"{"kty":"OKP","crv":"Ed25519","x":5}"#.to_string(), "x"),
        (format!(r#"{{"kty":"OKP","crv":1,"x":"{ED_X}"}}"#), "crv"),
        (
            format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{ED_X}","kid":7}}"#),
            "kid",
        ),
        (
            format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{ED_X}","use":["sig"]}}"#),
            "use",
        ),
        (
            format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{ED_X}","key_ops":"sign"}}"#),
            "key_ops",
        ),
        (
            format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{ED_X}","key_ops":[true]}}"#),
            "key_ops",
        ),
        (
            format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{ED_X}","alg":true}}"#),
            "alg",
        ),
        (
            format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{ED_X}","alg":1.5}}"#),
            "alg",
        ),
    ];
    for (json, member) in cases {
        let e = jwk_err(&json);
        assert!(invalid(member)(&e), "{json}: {e:?}");
    }
}

#[test]
fn duplicate_members_are_rejected() {
    let e = jwk_err(&format!(
        r#"{{"kty":"OKP","crv":"Ed25519","x":"{ED_X}","x":"{ED_X}"}}"#
    ));
    assert!(invalid("x")(&e), "{e:?}");
    let e = jwk_err(&format!(
        r#"{{"kty":"OKP","kty":"OKP","crv":"Ed25519","x":"{ED_X}"}}"#
    ));
    assert!(invalid("kty")(&e), "{e:?}");
    let e = jwk_err(&format!(
        r#"{{"kty":"OKP","crv":"Ed25519","x":"{ED_X}","kid":"a","kid":"b"}}"#
    ));
    assert!(invalid("kid")(&e), "{e:?}");
}

// ---------------------------------------------------------- JWK material

#[test]
fn wrong_lengths() {
    let short = b64u(&[1u8; 31]);
    let long = b64u(&[1u8; 33]);
    for json in [
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{short}"}}"#),
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{long}"}}"#),
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{ED_X}","d":"{short}"}}"#),
        format!(r#"{{"kty":"EC","crv":"P-256","x":"{long}","y":"{EC_Y}"}}"#),
        format!(r#"{{"kty":"EC","crv":"P-256","x":"{EC_X}","y":"{EC_Y}","d":"{long}"}}"#),
        // 32-byte coordinates padded to 48 are not a P-384 point.
        format!(r#"{{"kty":"EC","crv":"P-384","x":"{EC_X}","y":"{EC_Y}"}}"#),
    ] {
        let e = jwk_err(&json);
        assert!(
            matches!(e, KeyError::InvalidParameter { .. } | KeyError::Crypto(_)),
            "{json}: {e:?}"
        );
    }
}

/// A P-256 key whose x coordinate starts with a zero byte.
fn p256_key_with_leading_zero_x() -> tokenator_keys::Key {
    for i in 0u16.. {
        let mut seed = [0u8; 32];
        seed[..2].copy_from_slice(&i.to_be_bytes());
        let pk =
            tokenator_crypto::generate_from_seed(tokenator_crypto::KeySpec::P256, &seed).unwrap();
        if let tokenator_crypto::PublicKeyMaterial::Ec { x, .. } = pk.public_key().to_material()
            && x[0] == 0
        {
            return tokenator_keys::Key::from_private(pk);
        }
    }
    unreachable!()
}

#[test]
fn short_ec_values_are_left_padded() {
    let key = p256_key_with_leading_zero_x();
    let tokenator_crypto::PublicKeyMaterial::Ec { x, y, .. } = key.public_key().to_material()
    else {
        unreachable!()
    };
    let tokenator_crypto::PrivateKeyMaterial::Ec { d, .. } =
        key.private_key().unwrap().to_material()
    else {
        unreachable!()
    };
    // JWK with x stripped of its leading zero.
    let json = format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","d":"{}"}}"#,
        b64u(&x[1..]),
        b64u(&y),
        b64u(&d)
    );
    let back = import_one(json.as_bytes(), None);
    assert_same_material(&back, &key, "padded x");
    // Re-export is fixed-width.
    let jwk = tokenator_keys::to_jwk(&back, tokenator_keys::Visibility::Public).unwrap();
    assert_eq!(unb64u(jwk.get_str("x").unwrap()), x);
    // Same in COSE.
    let cbor = cose_map(vec![
        (1, Item::int(2)),
        (-1, Item::int(1)),
        (-2, Item::bytes(x[1..].to_vec())),
        (-3, Item::bytes(y.clone())),
    ]);
    let back = import_one(&cbor, None);
    assert_same_material(&back, &tokenator_keys::to_public(&key), "padded COSE x");
}

#[test]
fn point_not_on_curve() {
    // y of the RFC 7517 key with the last base64url digit changed.
    let bad_y = format!("{}Q", &EC_Y[..42]);
    let e = jwk_err(&format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{EC_X}","y":"{bad_y}"}}"#
    ));
    assert!(matches!(e, KeyError::Crypto(_)), "{e:?}");
}

#[test]
fn private_part_disagreeing_with_public_part() {
    // RFC 7517 EC d with the RFC 9679 public point.
    let other = import_fixture("rfc9679/ec2-p256.cbor");
    let tokenator_crypto::PublicKeyMaterial::Ec { x, y, .. } = other.public_key().to_material()
    else {
        unreachable!()
    };
    let (ox, oy) = (b64u(&x), b64u(&y));
    let cases = [
        format!(r#"{{"kty":"EC","crv":"P-256","x":"{ox}","y":"{oy}","d":"{EC_D}"}}"#),
        // Swapped coordinates of the right key.
        format!(r#"{{"kty":"EC","crv":"P-256","x":"{EC_Y}","y":"{EC_X}","d":"{EC_D}"}}"#),
        // Ed25519 secret with another public key.
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{ox}","d":"{ED_D}"}}"#),
    ];
    for json in cases {
        let e = jwk_err(&json);
        assert!(
            matches!(e, KeyError::InconsistentKey(_) | KeyError::Crypto(_)),
            "{json}: {e:?}"
        );
    }
    // With the right public key it imports.
    assert!(
        import(
            format!(r#"{{"kty":"EC","crv":"P-256","x":"{EC_X}","y":"{EC_Y}","d":"{EC_D}"}}"#)
                .as_bytes(),
            None
        )
        .is_ok()
    );
}

#[test]
fn rsa_inconsistent_components() {
    let set = fixture_json("rfc7517/a2-private-set.json");
    let good = set["keys"][1].clone();
    // Wrong e for this n / d.
    let mut bad = good.clone();
    bad["e"] = serde_json::json!("AQAD");
    assert!(import(bad.to_string().as_bytes(), None).is_err());
    // p swapped for q's value (p * p != n).
    let mut bad = good.clone();
    bad["p"] = good["q"].clone();
    assert!(import(bad.to_string().as_bytes(), None).is_err());
    // Corrupted qi.
    let mut bad = good.clone();
    bad["qi"] = serde_json::json!("AQAB");
    assert!(import(bad.to_string().as_bytes(), None).is_err());
    // Only some of the CRT members.
    let mut bad = good.clone();
    bad.as_object_mut().unwrap().remove("q");
    assert!(import(bad.to_string().as_bytes(), None).is_err());
    // n, e, d alone is fine (RFC 7518 §6.3.2).
    let mut minimal = good.clone();
    for m in ["p", "q", "dp", "dq", "qi"] {
        minimal.as_object_mut().unwrap().remove(m);
    }
    let key = import_one(minimal.to_string().as_bytes(), None);
    assert!(key.is_private());
}

#[test]
fn akp_mismatches() {
    let kat = fixture_json("rfc9964/ml-dsa-44-private.jwk.json");
    let pubk = kat["pub"].as_str().unwrap();
    // alg says 65 but pub is a 44 key.
    let e = jwk_err(&format!(
        r#"{{"kty":"AKP","alg":"ML-DSA-65","pub":"{pubk}"}}"#
    ));
    assert!(
        matches!(
            e,
            KeyError::InconsistentKey(_) | KeyError::InvalidParameter { .. }
        ),
        "{e:?}"
    );
    // A non-ML-DSA alg on an AKP key.
    assert!(
        import(
            format!(r#"{{"kty":"AKP","alg":"ES256","pub":"{pubk}"}}"#).as_bytes(),
            None
        )
        .is_err()
    );
    // priv must be the 32-byte seed.
    let e = jwk_err(&format!(
        r#"{{"kty":"AKP","alg":"ML-DSA-44","pub":"{pubk}","priv":"{}"}}"#,
        b64u(&[0u8; 64])
    ));
    assert!(invalid("priv")(&e), "{e:?}");
    // A seed for a different key.
    let e = jwk_err(&format!(
        r#"{{"kty":"AKP","alg":"ML-DSA-44","pub":"{pubk}","priv":"{}"}}"#,
        b64u(&[1u8; 32])
    ));
    assert!(matches!(e, KeyError::InconsistentKey(_)), "{e:?}");
}

#[test]
fn jwk_set_shapes() {
    // keys not an array: the set itself is unusable.
    assert!(import_each(br#"{"keys":"nope"}"#, None).is_err());
    // A non-object element fails only that element.
    let text = format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{ED_X}"}}, 5, []]}}"#);
    let each = import_each(text.as_bytes(), None).unwrap();
    assert_eq!(each.len(), 3);
    assert!(each[0].is_ok());
    assert!(each[1].is_err() && each[2].is_err());
    assert!(import(text.as_bytes(), None).is_err());
}

#[test]
fn deeply_nested_json_is_an_error() {
    let text = format!(
        r#"{{"kty":"OKP","x-deep":{}{}}}"#,
        "[".repeat(100_000),
        "]".repeat(100_000)
    );
    assert!(import(text.as_bytes(), None).is_err());
}

// ------------------------------------------------------------ COSE_Key

fn cbor(item: Item<'_>) -> Vec<u8> {
    tokenator_cbor::encode(&item, EncodeMode::Preserve).unwrap()
}

fn cose_map(entries: Vec<(i64, Item<'static>)>) -> Vec<u8> {
    cbor(Item::map(
        entries
            .into_iter()
            .map(|(k, v)| (Item::int(k), v))
            .collect(),
    ))
}

fn ec2(extra: Vec<(i64, Item<'static>)>) -> Vec<(i64, Item<'static>)> {
    let mut e = vec![
        (1, Item::int(2)),
        (-1, Item::int(1)),
        (-2, Item::bytes(unb64u(EC_X))),
        (-3, Item::bytes(unb64u(EC_Y))),
    ];
    e.extend(extra);
    e
}

fn cose_err(bytes: &[u8]) -> KeyError {
    match import(bytes, None) {
        Ok(keys) => panic!("{} imported: {keys:?}", hex::encode(bytes)),
        Err(e) => e,
    }
}

#[test]
fn cose_baseline_imports() {
    assert!(import(&cose_map(ec2(vec![])), None).is_ok());
    assert!(import(&cose_map(ec2(vec![(-4, Item::bytes(unb64u(EC_D)))])), None).is_ok());
}

#[test]
fn cose_malformed_cbor() {
    assert!(matches!(cose_err(&[0xff]), KeyError::Cbor(_)));
    assert!(
        matches!(cose_err(&[0xa1, 0x01]), KeyError::Cbor(_)),
        "truncated"
    );
    let mut trailing = cose_map(ec2(vec![]));
    trailing.push(0x00);
    assert!(matches!(cose_err(&trailing), KeyError::Cbor(_)));
    // Well-formed but not a map or array of maps.
    assert_eq!(cose_err(&[0x01]), KeyError::UnrecognizedFormat);
    assert_eq!(
        cose_err(&[0x60]),
        KeyError::UnrecognizedFormat,
        "empty text string"
    );
    assert_eq!(
        cose_err(&[0xc1, 0xa0]),
        KeyError::UnrecognizedFormat,
        "tagged map"
    );
}

#[test]
fn cose_missing_and_unsupported() {
    assert_eq!(
        cose_err(&cose_map(vec![(-1, Item::int(1))])),
        KeyError::MissingParameter("1".into())
    );
    assert_eq!(
        cose_err(&cose_map(vec![
            (1, Item::int(4)),
            (-1, Item::bytes(vec![1; 16]))
        ])),
        KeyError::UnsupportedKeyType("4".into())
    );
    assert_eq!(
        cose_err(&cose_map(vec![(1, Item::int(99))])),
        KeyError::UnsupportedKeyType("99".into())
    );
    // secp256k1 (RFC 8812 crv 8).
    let mut e = ec2(vec![]);
    e[1] = (-1, Item::int(8));
    assert_eq!(
        cose_err(&cose_map(e)),
        KeyError::UnsupportedCurve("8".into())
    );
    // X25519 (crv 4) on OKP.
    assert_eq!(
        cose_err(&cose_map(vec![
            (1, Item::int(1)),
            (-1, Item::int(4)),
            (-2, Item::bytes(vec![9; 32]))
        ])),
        KeyError::UnsupportedCurve("4".into())
    );
    for label in [-1, -2, -3] {
        let e: Vec<_> = ec2(vec![])
            .into_iter()
            .filter(|(l, _)| *l != label)
            .collect();
        assert_eq!(
            cose_err(&cose_map(e)),
            KeyError::MissingParameter(label.to_string()),
            "{label}"
        );
    }
}

#[test]
fn cose_crv_kty_mismatch() {
    let mut e = ec2(vec![]);
    e[1] = (-1, Item::int(6));
    assert!(matches!(
        cose_err(&cose_map(e)),
        KeyError::InconsistentKey(_)
    ));
    let e = vec![
        (1, Item::int(1)),
        (-1, Item::int(1)),
        (-2, Item::bytes(unb64u(ED_X))),
    ];
    assert!(matches!(
        cose_err(&cose_map(e)),
        KeyError::InconsistentKey(_)
    ));
}

#[test]
fn cose_wrong_value_types() {
    let cases = [
        (
            ec2(vec![])
                .into_iter()
                .map(|(l, v)| {
                    if l == -2 {
                        (l, Item::text("x"))
                    } else {
                        (l, v)
                    }
                })
                .collect::<Vec<_>>(),
            "-2",
        ),
        (ec2(vec![(2, Item::int(5))]), "2"),
        (ec2(vec![(4, Item::int(1))]), "4"),
        (ec2(vec![(3, Item::bytes(vec![1]))]), "3"),
        (ec2(vec![(-4, Item::text("d"))]), "-4"),
        (vec![(1, Item::bytes(vec![2]))], "1"),
    ];
    for (entries, label) in cases {
        let e = cose_err(&cose_map(entries));
        assert!(invalid(label)(&e), "label {label}: {e:?}");
    }
}

#[test]
fn cose_duplicate_labels() {
    let e = cose_err(&cose_map(ec2(vec![(-2, Item::bytes(unb64u(EC_X)))])));
    assert!(invalid("-2")(&e), "{e:?}");
}

#[test]
fn cose_private_part_disagreeing() {
    let other = fixture_private_material(Kind::P256);
    let tokenator_crypto::PrivateKeyMaterial::Ec { d, .. } = other else {
        unreachable!()
    };
    let e = cose_err(&cose_map(ec2(vec![(-4, Item::bytes(d))])));
    assert!(matches!(e, KeyError::InconsistentKey(_)), "{e:?}");
    // AKP: RFC 9964 key with a different seed.
    let bytes = fixture("rfc9964/ml-dsa-44-private.cbor");
    let mut item = tokenator_cbor::decode(&bytes).unwrap().into_owned();
    if let Value::Map(entries) = &mut item.value {
        for (k, v) in entries.iter_mut() {
            if k.value == Value::Nint(1) {
                *v = Item::bytes(vec![7; 32]);
            }
        }
    }
    let e = cose_err(&cbor(item));
    assert!(matches!(e, KeyError::InconsistentKey(_)), "{e:?}");
}

#[test]
fn cose_set_shapes() {
    let good = tokenator_cbor::decode(&cose_map(ec2(vec![])))
        .unwrap()
        .into_owned();
    let set = cbor(Item::array(vec![good, Item::int(1), Item::text("x")]));
    let each = import_each(&set, None).unwrap();
    assert_eq!(each.len(), 3);
    assert!(each[0].is_ok());
    assert!(each[1].is_err() && each[2].is_err());
    assert!(import(&set, None).is_err());
}

#[test]
fn deeply_nested_cbor_is_an_error() {
    let mut bytes = vec![0x81; 100_000];
    bytes.push(0x01);
    assert!(import(&bytes, None).is_err());
}

// ------------------------------------------------------------------ hints

#[test]
fn hint_mismatches_fail() {
    let jwk = fixture("rfc8037/ed25519-public.json");
    let cwk = fixture("rfc9679/ec2-p256.cbor");
    let pem = fixture("openssl/p256-spki.pem");
    for (input, wrong) in [
        (&jwk, KeyFormat::CoseKey),
        (&jwk, KeyFormat::CoseKeySet),
        (&jwk, KeyFormat::Pem(PemEncoding::Auto)),
        (&cwk, KeyFormat::Jwk),
        (&cwk, KeyFormat::Pem(PemEncoding::Spki)),
        (&pem, KeyFormat::Jwk),
        (&pem, KeyFormat::CoseKey),
    ] {
        assert!(import(input, Some(wrong)).is_err(), "{wrong:?}");
    }
}

#[test]
fn empty_and_blank_input() {
    for input in [&b""[..], b"   ", b"\n\n", b"\t"] {
        assert!(import(input, None).is_err(), "{input:?}");
        assert!(import_each(input, None).is_err(), "{input:?}");
    }
}

#[test]
fn garbage_is_unrecognized() {
    let e = import(b"hello world", None).unwrap_err();
    assert!(
        matches!(e, KeyError::UnrecognizedFormat | KeyError::Cbor(_)),
        "{e:?}"
    );
}
