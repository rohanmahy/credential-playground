//! PEM import and export: SPKI, PKCS#8 (v1 and v2), SEC1, PKCS#1, and the
//! RFC 9881 ML-DSA private key forms. Fixtures are OpenSSL output
//! (`testdata/keys/openssl/`) and RFC 8410 / RFC 9881 examples.

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use pem_rfc7468::LineEnding;
use tokenator_crypto::{Curve, KeyType, MlDsaParams, PrivateKeyMaterial};
use tokenator_keys::{
    KeyError, KeyFormat, MlDsaPrivateForm, PemEncoding, Visibility, export, export_set, import,
    import_each, params, to_public,
};

fn pem(enc: PemEncoding) -> KeyFormat {
    KeyFormat::Pem(enc)
}

fn export_str(key: &tokenator_keys::Key, enc: PemEncoding, vis: Visibility) -> String {
    String::from_utf8(export(key, pem(enc), vis).unwrap()).unwrap()
}

/// Re-armors DER with a label (64-column LF lines).
fn armor(label: &str, der: &[u8]) -> Vec<u8> {
    pem_rfc7468::encode_string(label, LineEnding::LF, der)
        .unwrap()
        .into_bytes()
}

fn dearmor(text: &[u8]) -> (String, Vec<u8>) {
    let (label, der) = pem_rfc7468::decode_vec(text).unwrap();
    (label.to_string(), der)
}

/// Replaces the single occurrence of `needle` in `hay`.
fn replace_once(hay: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    assert_eq!(needle.len(), with.len());
    let pos = hay
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("needle present");
    assert!(
        hay[pos + 1..].windows(needle.len()).all(|w| w != needle),
        "needle unique"
    );
    let mut out = hay.to_vec();
    out[pos..pos + needle.len()].copy_from_slice(with);
    out
}

fn uncompressed_point(kind: Kind) -> Vec<u8> {
    match fixture_public_material(kind) {
        tokenator_crypto::PublicKeyMaterial::Ec { x, y, .. } => {
            let mut p = vec![4];
            p.extend(x);
            p.extend(y);
            p
        }
        other => panic!("{other:?}"),
    }
}

// ------------------------------------------------- import: OpenSSL fixtures

fn check_private(rel: &str, kind: Kind) {
    let key = import_fixture(rel);
    assert!(key.is_private(), "{rel}");
    assert_eq!(key.kid, None, "{rel}: PEM has no kid");
    assert_eq!(key.alg, None, "{rel}: PEM has no alg");
    assert_eq!(
        key.private_key().unwrap().to_material(),
        fixture_private_material(kind),
        "{rel}"
    );
    assert_eq!(
        key.public_key().to_material(),
        fixture_public_material(kind),
        "{rel}"
    );
}

fn check_public(rel: &str, kind: Kind) {
    let key = import_fixture(rel);
    assert!(!key.is_private(), "{rel}");
    assert_eq!(
        key.public_key().to_material(),
        fixture_public_material(kind),
        "{rel}"
    );
}

#[test]
fn ec_pkcs8_sec1_spki() {
    for kind in [Kind::P256, Kind::P384, Kind::P521] {
        let s = kind.stem();
        check_private(&format!("openssl/{s}-pkcs8.pem"), kind);
        check_private(&format!("openssl/{s}-sec1.pem"), kind);
        check_private(&format!("openssl/{s}-sec1-nopub.pem"), kind);
        check_public(&format!("openssl/{s}-spki.pem"), kind);
    }
}

#[test]
fn ed25519_pkcs8_spki() {
    check_private("openssl/ed25519-pkcs8.pem", Kind::Ed25519);
    check_public("openssl/ed25519-spki.pem", Kind::Ed25519);
}

#[test]
fn rsa_pkcs8_pkcs1_spki() {
    check_private("openssl/rsa2048-pkcs8.pem", Kind::Rsa2048);
    check_private("openssl/rsa2048-pkcs1.pem", Kind::Rsa2048);
    check_public("openssl/rsa2048-pkcs1-pub.pem", Kind::Rsa2048);
    check_public("openssl/rsa2048-spki.pem", Kind::Rsa2048);
}

#[test]
fn rsa_sizes() {
    for bits in [2048u32, 3072, 4096] {
        for form in ["pkcs8", "pkcs1", "pkcs1-pub", "spki"] {
            let rel = format!("openssl/rsa{bits}-{form}.pem");
            let key = import_fixture(&rel);
            assert_eq!(key.key_type(), KeyType::Rsa, "{rel}");
            assert_eq!(params(&key).rsa_bits, Some(bits), "{rel}");
            assert_eq!(key.is_private(), !form.ends_with("pub") && form != "spki");
        }
    }
}

#[test]
fn rsa_pss_oid_imports_as_rsa() {
    // id-RSASSA-PSS (1.2.840.113549.1.1.10) keys are accepted as plain RSA.
    let private = import_fixture("openssl/rsapss2048-pkcs8.pem");
    let public = import_fixture("openssl/rsapss2048-spki.pem");
    assert_eq!(private.key_type(), KeyType::Rsa);
    assert_eq!(params(&private).rsa_bits, Some(2048));
    assert_same_material(&to_public(&private), &public, "RSA-PSS");
}

#[test]
fn ml_dsa_three_private_forms_and_spki() {
    for kind in [Kind::MlDsa44, Kind::MlDsa65, Kind::MlDsa87] {
        let s = kind.stem();
        check_private(&format!("openssl/{s}-seed.pem"), kind);
        check_private(&format!("openssl/{s}-both.pem"), kind);
        check_public(&format!("openssl/{s}-spki.pem"), kind);

        // The expanded form has no seed, but the same expanded key and
        // public key.
        let rel = format!("openssl/{s}-expanded.pem");
        let key = import_fixture(&rel);
        let PrivateKeyMaterial::MlDsa {
            params: expected_params,
            expanded: expected_expanded,
            ..
        } = fixture_private_material(kind)
        else {
            unreachable!()
        };
        match key.private_key().unwrap().to_material() {
            PrivateKeyMaterial::MlDsa {
                params,
                seed,
                expanded,
            } => {
                assert_eq!(params, expected_params);
                assert_eq!(seed, None, "{rel}");
                assert_eq!(expanded, expected_expanded, "{rel}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            key.public_key().to_material(),
            fixture_public_material(kind)
        );
        assert_same_material(
            &key,
            &import_fixture(&format!("openssl/{s}-seed.pem")),
            &rel,
        );
    }
}

#[test]
fn ec_parameters_block_is_skipped() {
    let keys = import(&fixture("openssl/p256-ecparam-genkey.pem"), None).unwrap();
    assert_eq!(keys.len(), 1);
    assert!(keys[0].is_private());
    assert_eq!(params(&keys[0]).crv, Some(Curve::P256));
}

// ----------------------------------------------------- import: RFC examples

#[test]
fn rfc8410_ed25519_examples() {
    let public = import_fixture("rfc8410/ed25519-public.pem");
    let v1 = import_fixture("rfc8410/ed25519-private.pem");
    let v2 = import_fixture("rfc8410/ed25519-private-v2.pem");
    assert!(v1.is_private() && v2.is_private());
    assert_eq!(
        v1.private_key().unwrap().to_material(),
        PrivateKeyMaterial::Ed25519 {
            d: hex::decode("d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842")
                .unwrap()
        }
    );
    // v2 adds an attribute (ignored) and the public key (checked).
    assert_same_material(&v1, &v2, "RFC 8410 v1 vs v2");
    assert_same_material(&to_public(&v1), &public, "RFC 8410 public");
}

const RFC9881_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[test]
fn rfc9881_c1_private_key_forms() {
    for p in ["44", "65", "87"] {
        let seed = import_fixture(&format!("rfc9881/ml-dsa-{p}-seed.pem"));
        let expanded = import_fixture(&format!("rfc9881/ml-dsa-{p}-expanded.pem"));
        let both = import_fixture(&format!("rfc9881/ml-dsa-{p}-both.pem"));
        match seed.private_key().unwrap().to_material() {
            PrivateKeyMaterial::MlDsa { seed: s, .. } => {
                assert_eq!(s, Some(hex::decode(RFC9881_SEED).unwrap()));
            }
            other => panic!("{other:?}"),
        }
        assert_same_material(&seed, &expanded, p);
        assert_same_material(&seed, &both, p);
        assert_eq!(
            seed.private_key().unwrap().to_material(),
            both.private_key().unwrap().to_material()
        );
    }
}

#[test]
fn rfc9881_c2_public_keys_match_c1() {
    for (p, set) in [
        ("44", MlDsaParams::MlDsa44),
        ("65", MlDsaParams::MlDsa65),
        ("87", MlDsaParams::MlDsa87),
    ] {
        let public = import_fixture(&format!("rfc9881/ml-dsa-{p}-public.pem"));
        let private = import_fixture(&format!("rfc9881/ml-dsa-{p}-seed.pem"));
        assert_eq!(params(&public).ml_dsa, Some(set));
        assert_same_material(&to_public(&private), &public, p);
    }
}

#[test]
fn rfc9881_c4_inconsistent_seed_and_expanded_is_rejected() {
    let err = import(&fixture("rfc9881/ml-dsa-44-inconsistent-1.pem"), None).unwrap_err();
    assert!(
        matches!(err, KeyError::InconsistentKey(_) | KeyError::Crypto(_)),
        "{err:?}"
    );
}

#[test]
#[ignore = "needs a tr / t0 consistency check in tokenator-crypto (#18)"]
fn rfc9881_c4_expanded_key_with_wrong_tr_or_t0_is_rejected() {
    for i in [2, 3] {
        let rel = format!("rfc9881/ml-dsa-44-inconsistent-{i}.pem");
        assert!(import(&fixture(&rel), None).is_err(), "{rel}");
    }
}

// ------------------------------------------- export: byte-exact vs OpenSSL

#[test]
fn spki_export_matches_openssl() {
    for kind in ALL_KINDS {
        let key = fixture_key(kind);
        let expected = fixture_str(&format!("openssl/{}-spki.pem", kind.stem()));
        assert_eq!(
            export_str(&key, PemEncoding::Spki, Visibility::Public),
            expected,
            "{kind:?}"
        );
        assert_eq!(
            export_str(&key, PemEncoding::Auto, Visibility::Public),
            expected,
            "{kind:?}"
        );
        // From a public key too.
        let public = fixture_public_key(kind);
        assert_eq!(
            export_str(&public, PemEncoding::Spki, Visibility::Public),
            expected
        );
    }
}

#[test]
fn pkcs8_export_matches_openssl() {
    for kind in [
        Kind::P256,
        Kind::P384,
        Kind::P521,
        Kind::Ed25519,
        Kind::Rsa2048,
    ] {
        let key = fixture_key(kind);
        let expected = fixture_str(&format!("openssl/{}-pkcs8.pem", kind.stem()));
        assert_eq!(
            export_str(&key, PemEncoding::Pkcs8, Visibility::Private),
            expected,
            "{kind:?}"
        );
        assert_eq!(
            export_str(&key, PemEncoding::Auto, Visibility::Private),
            expected,
            "{kind:?}"
        );
    }
}

#[test]
fn sec1_export_matches_openssl() {
    for kind in [Kind::P256, Kind::P384, Kind::P521] {
        let s = kind.stem();
        let expected = fixture_str(&format!("openssl/{s}-sec1.pem"));
        let key = fixture_key(kind);
        assert_eq!(
            export_str(&key, PemEncoding::Sec1, Visibility::Private),
            expected,
            "{kind:?}"
        );
        // A SEC1 key without the public key gains it on export.
        let nopub = import_fixture(&format!("openssl/{s}-sec1-nopub.pem"));
        assert_eq!(
            export_str(&nopub, PemEncoding::Sec1, Visibility::Private),
            expected
        );
    }
}

#[test]
fn pkcs1_export_matches_openssl() {
    for bits in [2048, 3072, 4096] {
        let key = import_fixture(&format!("openssl/rsa{bits}-pkcs8.pem"));
        assert_eq!(
            export_str(&key, PemEncoding::Pkcs1, Visibility::Private),
            fixture_str(&format!("openssl/rsa{bits}-pkcs1.pem"))
        );
        assert_eq!(
            export_str(&key, PemEncoding::Pkcs1, Visibility::Public),
            fixture_str(&format!("openssl/rsa{bits}-pkcs1-pub.pem"))
        );
    }
}

#[test]
fn ml_dsa_pkcs8_export_matches_openssl() {
    for kind in [Kind::MlDsa44, Kind::MlDsa65, Kind::MlDsa87] {
        let s = kind.stem();
        let key = fixture_key(kind);
        let seed = fixture_str(&format!("openssl/{s}-seed.pem"));
        for (enc, file) in [
            (PemEncoding::Pkcs8MlDsa(MlDsaPrivateForm::Seed), "seed"),
            (
                PemEncoding::Pkcs8MlDsa(MlDsaPrivateForm::Expanded),
                "expanded",
            ),
            (PemEncoding::Pkcs8MlDsa(MlDsaPrivateForm::Both), "both"),
        ] {
            assert_eq!(
                export_str(&key, enc, Visibility::Private),
                fixture_str(&format!("openssl/{s}-{file}.pem")),
                "{kind:?} {file}"
            );
        }
        // Default PKCS#8 is the seed form when the seed is known (RFC 9881 §6).
        assert_eq!(
            export_str(&key, PemEncoding::Pkcs8, Visibility::Private),
            seed
        );
    }
}

#[test]
fn ml_dsa_expanded_only_key_exports() {
    for kind in [Kind::MlDsa44, Kind::MlDsa65, Kind::MlDsa87] {
        let s = kind.stem();
        let key = import_fixture(&format!("openssl/{s}-expanded.pem"));
        let expanded = fixture_str(&format!("openssl/{s}-expanded.pem"));
        assert_eq!(
            export_str(&key, PemEncoding::Pkcs8, Visibility::Private),
            expanded
        );
        assert_eq!(
            export_str(
                &key,
                PemEncoding::Pkcs8MlDsa(MlDsaPrivateForm::Expanded),
                Visibility::Private
            ),
            expanded
        );
        for form in [MlDsaPrivateForm::Seed, MlDsaPrivateForm::Both] {
            assert_eq!(
                export(
                    &key,
                    pem(PemEncoding::Pkcs8MlDsa(form)),
                    Visibility::Private
                )
                .unwrap_err(),
                KeyError::MlDsaSeedUnknown,
                "{kind:?} {form:?}"
            );
        }
        // Public exports still work.
        assert_eq!(
            export_str(&key, PemEncoding::Spki, Visibility::Public),
            fixture_str(&format!("openssl/{s}-spki.pem"))
        );
    }
}

#[test]
fn rfc9881_export_reproduces_the_rfc_text() {
    for p in ["44", "65", "87"] {
        let key = import_fixture(&format!("rfc9881/ml-dsa-{p}-seed.pem"));
        for (form, file) in [
            (MlDsaPrivateForm::Seed, "seed"),
            (MlDsaPrivateForm::Expanded, "expanded"),
            (MlDsaPrivateForm::Both, "both"),
        ] {
            assert_eq!(
                export_str(&key, PemEncoding::Pkcs8MlDsa(form), Visibility::Private),
                fixture_str(&format!("rfc9881/ml-dsa-{p}-{file}.pem")),
                "ML-DSA-{p} {file}"
            );
        }
        assert_eq!(
            export_str(&key, PemEncoding::Spki, Visibility::Public),
            fixture_str(&format!("rfc9881/ml-dsa-{p}-public.pem"))
        );
    }
}

#[test]
fn rfc8410_export_reproduces_v1_and_spki() {
    let key = import_fixture("rfc8410/ed25519-private-v2.pem");
    assert_eq!(
        export_str(&key, PemEncoding::Pkcs8, Visibility::Private),
        fixture_str("rfc8410/ed25519-private.pem")
    );
    assert_eq!(
        export_str(&key, PemEncoding::Spki, Visibility::Public),
        fixture_str("rfc8410/ed25519-public.pem")
    );
}

#[test]
fn pem_output_shape() {
    for kind in ALL_KINDS {
        let key = sample_key(kind);
        for vis in [Visibility::Public, Visibility::Private] {
            let text = export_str(&key, PemEncoding::Auto, vis);
            assert!(text.starts_with("-----BEGIN "), "{kind:?}");
            assert!(text.ends_with("-----\n"), "{kind:?}: final newline");
            assert!(!text.contains('\r'), "LF only");
            for line in text.lines() {
                assert!(line.len() <= 64, "{kind:?}: line too long: {line}");
            }
        }
    }
}

// ------------------------------------------------------ export: not allowed

#[test]
fn export_formats_that_do_not_apply() {
    let ec = fixture_key(Kind::P256);
    let rsa = fixture_key(Kind::Rsa2048);
    let ed = fixture_key(Kind::Ed25519);
    let ml = fixture_key(Kind::MlDsa44);
    let cases = [
        (&rsa, PemEncoding::Sec1, Visibility::Private),
        (&ed, PemEncoding::Sec1, Visibility::Private),
        (&ec, PemEncoding::Sec1, Visibility::Public),
        (&ec, PemEncoding::Pkcs1, Visibility::Private),
        (&ml, PemEncoding::Pkcs1, Visibility::Public),
        (&ec, PemEncoding::Pkcs8, Visibility::Public),
        (&ec, PemEncoding::Spki, Visibility::Private),
        (
            &ec,
            PemEncoding::Pkcs8MlDsa(MlDsaPrivateForm::Seed),
            Visibility::Private,
        ),
    ];
    for (key, enc, vis) in cases {
        let err = export(key, pem(enc), vis).unwrap_err();
        assert!(
            matches!(err, KeyError::FormatNotApplicable { format, .. } if format == pem(enc)),
            "{:?} {enc:?} {vis:?}: {err:?}",
            key.key_type()
        );
    }
}

#[test]
fn private_export_of_public_key_fails() {
    for kind in ALL_KINDS {
        let key = fixture_public_key(kind);
        for enc in [PemEncoding::Auto, PemEncoding::Pkcs8] {
            assert_eq!(
                export(&key, pem(enc), Visibility::Private).unwrap_err(),
                KeyError::NoPrivateKey,
                "{kind:?}"
            );
        }
    }
}

// ------------------------------------------------------------- many blocks

#[test]
fn several_blocks_give_several_keys_in_order() {
    let mut input = fixture("openssl/p256-spki.pem");
    input.extend(fixture("openssl/ed25519-pkcs8.pem"));
    input.extend(fixture("openssl/rsa2048-pkcs1-pub.pem"));
    input.extend(fixture("openssl/mldsa44-seed.pem"));
    let keys = import(&input, None).unwrap();
    assert_eq!(keys.len(), 4);
    assert_eq!(
        keys.iter().map(|k| k.key_type()).collect::<Vec<_>>(),
        [KeyType::Ec, KeyType::Okp, KeyType::Rsa, KeyType::Akp]
    );
    assert_eq!(
        keys.iter().map(|k| k.is_private()).collect::<Vec<_>>(),
        [false, true, false, true]
    );
}

#[test]
fn text_around_blocks_and_crlf_are_tolerated() {
    let a = fixture_str("openssl/p256-pkcs8.pem");
    let b = fixture_str("openssl/ed25519-spki.pem");
    let input = format!("Key one:\n{a}\nsome explanatory text\n\n{b}trailing words\n");
    let keys = import(input.as_bytes(), None).unwrap();
    assert_eq!(keys.len(), 2);
    let crlf = input.replace('\n', "\r\n");
    assert_eq!(import(crlf.as_bytes(), None).unwrap(), keys);
    // Leading whitespace before a single block.
    let keys = import(
        format!("\n\t  {a}").as_bytes(),
        Some(pem(PemEncoding::Auto)),
    )
    .unwrap();
    assert_eq!(keys.len(), 1);
}

#[test]
fn export_set_concatenates_pem_blocks() {
    let keys = vec![fixture_key(Kind::P256), fixture_key(Kind::Ed25519)];
    let out = export_set(&keys, pem(PemEncoding::Auto), Visibility::Public).unwrap();
    let expected = fixture_str("openssl/p256-spki.pem") + &fixture_str("openssl/ed25519-spki.pem");
    assert_eq!(String::from_utf8(out.clone()).unwrap(), expected);
    let back = import(&out, None).unwrap();
    assert_eq!(back.len(), 2);
    for (a, b) in back.iter().zip(&keys) {
        assert_same_material(a, &to_public(b), "export_set PEM");
    }
}

// ---------------------------------------------------------- unsupported PEM

#[test]
fn unsupported_algorithms_and_labels() {
    let cases: [(&str, KeyError); 6] = [
        (
            "openssl/unsupported/x25519-pkcs8.pem",
            KeyError::UnsupportedAlgorithm("1.3.101.110".into()),
        ),
        (
            "openssl/unsupported/ed448-pkcs8.pem",
            KeyError::UnsupportedAlgorithm("1.3.101.113".into()),
        ),
        (
            "openssl/unsupported/secp256k1-pkcs8.pem",
            KeyError::UnsupportedCurve("1.3.132.0.10".into()),
        ),
        (
            "openssl/unsupported/secp256k1-spki.pem",
            KeyError::UnsupportedCurve("1.3.132.0.10".into()),
        ),
        (
            "openssl/unsupported/p256-pkcs8-encrypted.pem",
            KeyError::EncryptedPrivateKey,
        ),
        (
            "openssl/unsupported/p256-cert.pem",
            KeyError::UnsupportedPemLabel("CERTIFICATE".into()),
        ),
    ];
    for (rel, expected) in cases {
        assert_eq!(import(&fixture(rel), None).unwrap_err(), expected, "{rel}");
    }
}

#[test]
fn explicit_ec_parameters_are_unsupported() {
    let err = import(&fixture("openssl/unsupported/p256-sec1-explicit.pem"), None).unwrap_err();
    assert!(matches!(err, KeyError::UnsupportedCurve(_)), "{err:?}");
}

#[test]
fn one_bad_block_fails_import_but_not_import_each() {
    let mut input = fixture("openssl/p256-spki.pem");
    input.extend(fixture("openssl/unsupported/x25519-pkcs8.pem"));
    input.extend(fixture("openssl/ed25519-spki.pem"));
    assert_eq!(
        import(&input, None).unwrap_err(),
        KeyError::UnsupportedAlgorithm("1.3.101.110".into())
    );
    let each = import_each(&input, None).unwrap();
    assert_eq!(each.len(), 3);
    assert!(each[0].is_ok());
    assert!(each[1].is_err());
    assert!(each[2].is_ok());
}

// ----------------------------------------------------------- malformed PEM

#[test]
fn malformed_pem_is_an_error() {
    let good = fixture_str("openssl/p256-pkcs8.pem");
    let lines: Vec<&str> = good.lines().collect();
    let body_end = lines.len() - 1;
    let cases: Vec<(&str, String)> = vec![
        ("missing END line", lines[..body_end].join("\n")),
        (
            "truncated body",
            format!("{}\n{}\n", lines[..2].join("\n"), lines[body_end]),
        ),
        ("bad base64", good.replacen(&lines[1][..4], "!!!!", 1)),
        (
            "mismatched END label",
            good.replace("-----END PRIVATE KEY-----", "-----END PUBLIC KEY-----"),
        ),
        (
            "empty body",
            "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n".into(),
        ),
        ("only BEGIN", "-----BEGIN PRIVATE KEY-----\n".into()),
        (
            "base64 of garbage DER",
            "-----BEGIN PRIVATE KEY-----\nAAECAwQFBgcI\n-----END PRIVATE KEY-----\n".into(),
        ),
    ];
    for (what, text) in cases {
        let r = import(text.as_bytes(), None);
        assert!(r.is_err(), "{what}: {r:?}");
        let r = import(text.as_bytes(), Some(pem(PemEncoding::Auto)));
        assert!(r.is_err(), "{what} (hinted): {r:?}");
    }
}

#[test]
fn spki_der_truncated_at_every_length_is_an_error() {
    let (label, der) = dearmor(&fixture("openssl/p256-spki.pem"));
    for len in 0..der.len() {
        let text = armor(&label, &der[..len]);
        assert!(import(&text, None).is_err(), "len {len}");
    }
}

#[test]
fn trailing_der_bytes_are_an_error() {
    let (label, mut der) = dearmor(&fixture("openssl/ed25519-spki.pem"));
    der.push(0);
    assert!(import(&armor(&label, &der), None).is_err());
}

#[test]
fn wrong_label_for_contents_is_an_error() {
    // SPKI DER under a PRIVATE KEY label, and PKCS#8 under PUBLIC KEY.
    let (_, spki) = dearmor(&fixture("openssl/p256-spki.pem"));
    let (_, pkcs8) = dearmor(&fixture("openssl/p256-pkcs8.pem"));
    assert!(import(&armor("PRIVATE KEY", &spki), None).is_err());
    assert!(import(&armor("PUBLIC KEY", &pkcs8), None).is_err());
    assert!(import(&armor("RSA PRIVATE KEY", &pkcs8), None).is_err());
    assert!(import(&armor("EC PRIVATE KEY", &pkcs8), None).is_err());
}

#[test]
fn point_not_on_curve_is_an_error() {
    for kind in [Kind::P256, Kind::P384, Kind::P521] {
        let (label, der) = dearmor(&fixture(&format!("openssl/{}-spki.pem", kind.stem())));
        let point = uncompressed_point(kind);
        let mut bad = point.clone();
        *bad.last_mut().unwrap() ^= 1; // y + 1 is not on the curve
        let der = replace_once(&der, &point, &bad);
        let err = import(&armor(&label, &der), None).unwrap_err();
        assert!(matches!(err, KeyError::Crypto(_)), "{kind:?}: {err:?}");
    }
}

#[test]
fn sec1_public_key_that_disagrees_is_an_error() {
    // Put P-256 key B's public point into key A's SEC1 and PKCS#8 encodings.
    let other = import_fixture("rfc9679/ec2-p256.cbor");
    let tokenator_crypto::PublicKeyMaterial::Ec { x, y, .. } = other.public_key().to_material()
    else {
        unreachable!()
    };
    let mut wrong = vec![4];
    wrong.extend(x);
    wrong.extend(y);
    let point = uncompressed_point(Kind::P256);
    for file in ["p256-sec1.pem", "p256-pkcs8.pem"] {
        let (label, der) = dearmor(&fixture(&format!("openssl/{file}")));
        let der = replace_once(&der, &point, &wrong);
        let err = import(&armor(&label, &der), None).unwrap_err();
        assert!(
            matches!(err, KeyError::InconsistentKey(_)),
            "{file}: {err:?}"
        );
    }
}

#[test]
fn pkcs8_v2_public_key_that_disagrees_is_an_error() {
    let (label, der) = dearmor(&fixture("rfc8410/ed25519-private-v2.pem"));
    let public =
        hex::decode("19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1").unwrap();
    let mut wrong = public.clone();
    wrong[0] ^= 0xff;
    let der = replace_once(&der, &public, &wrong);
    let err = import(&armor(&label, &der), None).unwrap_err();
    assert!(matches!(err, KeyError::InconsistentKey(_)), "{err:?}");
}

#[test]
fn rsa_pkcs1_with_inconsistent_components_is_an_error() {
    // Flip a bit in the private exponent of a PKCS#1 key: CRT values then
    // disagree with d (tokenator-crypto checks them).
    let key = fixture_private_material(Kind::Rsa2048);
    let PrivateKeyMaterial::Rsa(m) = key else {
        unreachable!()
    };
    let (label, der) = dearmor(&fixture("openssl/rsa2048-pkcs1.pem"));
    let mut bad_d = m.d.clone();
    bad_d[10] ^= 1;
    let der = replace_once(&der, &m.d, &bad_d);
    let err = import(&armor(&label, &der), None).unwrap_err();
    assert!(
        matches!(err, KeyError::Crypto(_) | KeyError::InconsistentKey(_)),
        "{err:?}"
    );
}
