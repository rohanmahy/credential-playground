//! requirements(), check_key(), and algs_for_key(): the table the linter uses.

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use tokenator_crypto::{
    Alg, Curve, DeclaredAlg, KeyMismatch, KeyParams, KeyRequirements, KeyType, MlDsaParams,
    algs_for_key, check_key, requirements,
};

fn req(
    kty: KeyType,
    crv: Option<Curve>,
    akp: Option<MlDsaParams>,
    min_rsa_bits: Option<u32>,
) -> KeyRequirements {
    KeyRequirements {
        kty,
        jwk_kty: kty.jwk_kty(),
        cose_kty: kty.cose_kty(),
        crv,
        akp_param_set: akp,
        min_rsa_bits,
    }
}

#[test]
fn requirements_table_for_every_alg() {
    use Curve::*;
    use KeyType::*;
    let rsa = req(Rsa, None, None, Some(2048));
    let table = [
        (Alg::ES256, req(Ec, Some(P256), None, None)),
        (Alg::ES384, req(Ec, Some(P384), None, None)),
        (Alg::ES512, req(Ec, Some(P521), None, None)),
        (Alg::EdDSA, req(Okp, Some(Ed25519), None, None)),
        (Alg::Ed25519, req(Okp, Some(Ed25519), None, None)),
        (Alg::RS256, rsa),
        (Alg::RS384, rsa),
        (Alg::RS512, rsa),
        (Alg::PS256, rsa),
        (Alg::PS384, rsa),
        (Alg::PS512, rsa),
        (
            Alg::MlDsa44,
            req(Akp, None, Some(MlDsaParams::MlDsa44), None),
        ),
        (
            Alg::MlDsa65,
            req(Akp, None, Some(MlDsaParams::MlDsa65), None),
        ),
        (
            Alg::MlDsa87,
            req(Akp, None, Some(MlDsaParams::MlDsa87), None),
        ),
    ];
    assert_eq!(table.len(), Alg::ALL.len());
    for (alg, expected) in table {
        assert_eq!(requirements(alg), expected, "{alg:?}");
    }
}

#[test]
fn requirements_literal_kty_values() {
    // Spot-check the raw strings/labels the linter prints.
    assert_eq!(requirements(Alg::ES256).jwk_kty, "EC");
    assert_eq!(requirements(Alg::ES256).cose_kty, 2);
    assert_eq!(requirements(Alg::EdDSA).jwk_kty, "OKP");
    assert_eq!(requirements(Alg::Ed25519).cose_kty, 1);
    assert_eq!(requirements(Alg::PS512).jwk_kty, "RSA");
    assert_eq!(requirements(Alg::RS256).cose_kty, 3);
    assert_eq!(requirements(Alg::MlDsa65).jwk_kty, "AKP");
    assert_eq!(requirements(Alg::MlDsa65).cose_kty, 7);
}

#[test]
fn key_params_constructors() {
    assert_eq!(
        KeyParams::curve(Curve::P384),
        KeyParams {
            kty: KeyType::Ec,
            crv: Some(Curve::P384),
            rsa_bits: None,
            ml_dsa: None,
            declared_alg: None
        }
    );
    assert_eq!(
        KeyParams::curve(Curve::Ed25519),
        KeyParams {
            kty: KeyType::Okp,
            crv: Some(Curve::Ed25519),
            rsa_bits: None,
            ml_dsa: None,
            declared_alg: None
        }
    );
    assert_eq!(
        KeyParams::rsa(3072),
        KeyParams {
            kty: KeyType::Rsa,
            crv: None,
            rsa_bits: Some(3072),
            ml_dsa: None,
            declared_alg: None
        }
    );
    assert_eq!(
        KeyParams::ml_dsa(MlDsaParams::MlDsa87),
        KeyParams {
            kty: KeyType::Akp,
            crv: None,
            rsa_bits: None,
            ml_dsa: Some(MlDsaParams::MlDsa87),
            declared_alg: None
        }
    );
    let declared = KeyParams::rsa(2048).with_declared_alg(DeclaredAlg::Known(Alg::PS256));
    assert_eq!(declared.declared_alg, Some(DeclaredAlg::Known(Alg::PS256)));
    assert_eq!(declared.rsa_bits, Some(2048));
}

/// The canonical matching key for each alg.
fn matching(alg: Alg) -> KeyParams {
    match alg {
        Alg::ES256 => KeyParams::curve(Curve::P256),
        Alg::ES384 => KeyParams::curve(Curve::P384),
        Alg::ES512 => KeyParams::curve(Curve::P521),
        Alg::EdDSA | Alg::Ed25519 => KeyParams::curve(Curve::Ed25519),
        Alg::RS256 | Alg::RS384 | Alg::RS512 | Alg::PS256 | Alg::PS384 | Alg::PS512 => {
            KeyParams::rsa(2048)
        }
        Alg::MlDsa44 => KeyParams::ml_dsa(MlDsaParams::MlDsa44),
        Alg::MlDsa65 => KeyParams::ml_dsa(MlDsaParams::MlDsa65),
        Alg::MlDsa87 => KeyParams::ml_dsa(MlDsaParams::MlDsa87),
    }
}

#[test]
fn matching_keys_have_no_findings() {
    for alg in Alg::ALL {
        assert_eq!(check_key(alg, &matching(alg)), vec![], "{alg:?}");
        let declared = matching(alg).with_declared_alg(DeclaredAlg::Known(alg));
        assert_eq!(
            check_key(alg, &declared),
            vec![],
            "{alg:?} with matching declared alg"
        );
    }
}

#[test]
fn es256_with_p384_key_is_a_curve_mismatch() {
    assert_eq!(
        check_key(Alg::ES256, &KeyParams::curve(Curve::P384)),
        vec![KeyMismatch::Curve {
            expected: Curve::P256,
            found: Some(Curve::P384)
        }]
    );
}

#[test]
fn every_wrong_ec_curve_is_reported() {
    let algs = [
        (Alg::ES256, Curve::P256),
        (Alg::ES384, Curve::P384),
        (Alg::ES512, Curve::P521),
    ];
    for (alg, want) in algs {
        for crv in [Curve::P256, Curve::P384, Curve::P521] {
            let got = check_key(alg, &KeyParams::curve(crv));
            if crv == want {
                assert!(got.is_empty(), "{alg:?} {crv:?}");
            } else {
                assert_eq!(
                    got,
                    vec![KeyMismatch::Curve {
                        expected: want,
                        found: Some(crv)
                    }],
                    "{alg:?} {crv:?}"
                );
            }
        }
    }
}

#[test]
fn ec_key_without_curve_is_a_curve_mismatch() {
    let params = KeyParams {
        kty: KeyType::Ec,
        crv: None,
        rsa_bits: None,
        ml_dsa: None,
        declared_alg: None,
    };
    assert_eq!(
        check_key(Alg::ES384, &params),
        vec![KeyMismatch::Curve {
            expected: Curve::P384,
            found: None
        }]
    );
}

#[test]
fn ed25519_curve_on_ec_alg_is_a_key_type_mismatch() {
    // An OKP key is the wrong kty for ES256; the curve is not reported separately.
    assert_eq!(
        check_key(Alg::ES256, &KeyParams::curve(Curve::Ed25519)),
        vec![KeyMismatch::KeyType {
            expected: KeyType::Ec,
            found: KeyType::Okp
        }]
    );
}

#[test]
fn key_type_mismatch_suppresses_detail_checks() {
    // RSA 1024 used with ES256: only the kty finding, no RSA size finding.
    assert_eq!(
        check_key(Alg::ES256, &KeyParams::rsa(1024)),
        vec![KeyMismatch::KeyType {
            expected: KeyType::Ec,
            found: KeyType::Rsa
        }]
    );
    // P-384 used with ML-DSA-44: only the kty finding.
    assert_eq!(
        check_key(Alg::MlDsa44, &KeyParams::curve(Curve::P384)),
        vec![KeyMismatch::KeyType {
            expected: KeyType::Akp,
            found: KeyType::Ec
        }]
    );
    // ML-DSA key used with PS256.
    assert_eq!(
        check_key(Alg::PS256, &KeyParams::ml_dsa(MlDsaParams::MlDsa65)),
        vec![KeyMismatch::KeyType {
            expected: KeyType::Rsa,
            found: KeyType::Akp
        }]
    );
    // Ed25519 key with RS256, EC key with EdDSA.
    assert_eq!(
        check_key(Alg::RS256, &KeyParams::curve(Curve::Ed25519)),
        vec![KeyMismatch::KeyType {
            expected: KeyType::Rsa,
            found: KeyType::Okp
        }]
    );
    assert_eq!(
        check_key(Alg::EdDSA, &KeyParams::curve(Curve::P256)),
        vec![KeyMismatch::KeyType {
            expected: KeyType::Okp,
            found: KeyType::Ec
        }]
    );
}

#[test]
fn rsa_1024_bits_is_too_small_for_every_rsa_alg() {
    for alg in [
        Alg::RS256,
        Alg::RS384,
        Alg::RS512,
        Alg::PS256,
        Alg::PS384,
        Alg::PS512,
    ] {
        assert_eq!(
            check_key(alg, &KeyParams::rsa(1024)),
            vec![KeyMismatch::RsaTooSmall {
                min_bits: 2048,
                found_bits: 1024
            }],
            "{alg:?}"
        );
    }
}

#[test]
fn rsa_size_boundary() {
    assert_eq!(
        check_key(Alg::RS256, &KeyParams::rsa(2047)),
        vec![KeyMismatch::RsaTooSmall {
            min_bits: 2048,
            found_bits: 2047
        }]
    );
    for bits in [2048, 3072, 4096, 8192] {
        assert!(
            check_key(Alg::PS384, &KeyParams::rsa(bits)).is_empty(),
            "{bits}"
        );
    }
}

#[test]
fn rsa_with_unknown_size_is_not_flagged() {
    let params = KeyParams {
        kty: KeyType::Rsa,
        crv: None,
        rsa_bits: None,
        ml_dsa: None,
        declared_alg: None,
    };
    assert!(check_key(Alg::RS256, &params).is_empty());
}

#[test]
fn ml_dsa_65_key_with_ml_dsa_44_alg() {
    assert_eq!(
        check_key(Alg::MlDsa44, &KeyParams::ml_dsa(MlDsaParams::MlDsa65)),
        vec![KeyMismatch::MlDsaParamSet {
            expected: MlDsaParams::MlDsa44,
            found: Some(MlDsaParams::MlDsa65)
        }]
    );
}

#[test]
fn akp_key_without_param_set() {
    let params = KeyParams {
        kty: KeyType::Akp,
        crv: None,
        rsa_bits: None,
        ml_dsa: None,
        declared_alg: None,
    };
    assert_eq!(
        check_key(Alg::MlDsa87, &params),
        vec![KeyMismatch::MlDsaParamSet {
            expected: MlDsaParams::MlDsa87,
            found: None
        }]
    );
}

#[test]
fn declared_alg_disagreeing_with_header_alg() {
    // RSA key declared PS256 used with RS256.
    let params = KeyParams::rsa(2048).with_declared_alg(DeclaredAlg::Known(Alg::PS256));
    assert_eq!(
        check_key(Alg::RS256, &params),
        vec![KeyMismatch::DeclaredAlg {
            alg: Alg::RS256,
            declared: DeclaredAlg::Known(Alg::PS256)
        }]
    );
}

#[test]
fn declared_alg_unknown_values_are_reported() {
    let jose =
        KeyParams::curve(Curve::P256).with_declared_alg(DeclaredAlg::UnknownJose("HS256".into()));
    assert_eq!(
        check_key(Alg::ES256, &jose),
        vec![KeyMismatch::DeclaredAlg {
            alg: Alg::ES256,
            declared: DeclaredAlg::UnknownJose("HS256".into())
        }]
    );
    // COSE ESP256 (-9) declared on a key used with ES256 (-7).
    let cose = KeyParams::curve(Curve::P256).with_declared_alg(DeclaredAlg::UnknownCose(-9));
    assert_eq!(
        check_key(Alg::ES256, &cose),
        vec![KeyMismatch::DeclaredAlg {
            alg: Alg::ES256,
            declared: DeclaredAlg::UnknownCose(-9)
        }]
    );
}

#[test]
fn eddsa_and_ed25519_declared_algs_are_not_interchangeable() {
    // Default chosen in the clarification issue: compare identifiers exactly.
    let params = KeyParams::curve(Curve::Ed25519).with_declared_alg(DeclaredAlg::Known(Alg::EdDSA));
    assert_eq!(
        check_key(Alg::Ed25519, &params),
        vec![KeyMismatch::DeclaredAlg {
            alg: Alg::Ed25519,
            declared: DeclaredAlg::Known(Alg::EdDSA)
        }]
    );
    assert!(check_key(Alg::EdDSA, &params).is_empty());
}

#[test]
fn multiple_findings_are_ordered() {
    // Wrong curve and wrong declared alg.
    let params = KeyParams::curve(Curve::P521).with_declared_alg(DeclaredAlg::Known(Alg::ES512));
    assert_eq!(
        check_key(Alg::ES256, &params),
        vec![
            KeyMismatch::Curve {
                expected: Curve::P256,
                found: Some(Curve::P521)
            },
            KeyMismatch::DeclaredAlg {
                alg: Alg::ES256,
                declared: DeclaredAlg::Known(Alg::ES512)
            },
        ]
    );
    // Too small and wrong declared alg.
    let params = KeyParams::rsa(1024).with_declared_alg(DeclaredAlg::Known(Alg::RS256));
    assert_eq!(
        check_key(Alg::PS256, &params),
        vec![
            KeyMismatch::RsaTooSmall {
                min_bits: 2048,
                found_bits: 1024
            },
            KeyMismatch::DeclaredAlg {
                alg: Alg::PS256,
                declared: DeclaredAlg::Known(Alg::RS256)
            },
        ]
    );
    // Wrong kty and wrong declared alg: kty first, details skipped.
    let params =
        KeyParams::ml_dsa(MlDsaParams::MlDsa44).with_declared_alg(DeclaredAlg::Known(Alg::MlDsa44));
    assert_eq!(
        check_key(Alg::ES256, &params),
        vec![
            KeyMismatch::KeyType {
                expected: KeyType::Ec,
                found: KeyType::Akp
            },
            KeyMismatch::DeclaredAlg {
                alg: Alg::ES256,
                declared: DeclaredAlg::Known(Alg::MlDsa44)
            },
        ]
    );
}

#[test]
fn algs_for_key_table() {
    use Alg::*;
    let table: Vec<(KeyParams, Vec<Alg>)> = vec![
        (KeyParams::curve(Curve::P256), vec![ES256]),
        (KeyParams::curve(Curve::P384), vec![ES384]),
        (KeyParams::curve(Curve::P521), vec![ES512]),
        (KeyParams::curve(Curve::Ed25519), vec![EdDSA, Ed25519]),
        (
            KeyParams::rsa(2048),
            vec![RS256, RS384, RS512, PS256, PS384, PS512],
        ),
        (
            KeyParams::rsa(4096),
            vec![RS256, RS384, RS512, PS256, PS384, PS512],
        ),
        (KeyParams::rsa(1024), vec![]),
        (KeyParams::ml_dsa(MlDsaParams::MlDsa44), vec![MlDsa44]),
        (KeyParams::ml_dsa(MlDsaParams::MlDsa65), vec![MlDsa65]),
        (KeyParams::ml_dsa(MlDsaParams::MlDsa87), vec![MlDsa87]),
        (
            KeyParams::rsa(2048).with_declared_alg(DeclaredAlg::Known(PS256)),
            vec![PS256],
        ),
        (
            KeyParams::curve(Curve::Ed25519).with_declared_alg(DeclaredAlg::Known(Ed25519)),
            vec![Ed25519],
        ),
        (
            KeyParams::curve(Curve::P256).with_declared_alg(DeclaredAlg::Known(ES384)),
            vec![],
        ),
        (
            KeyParams::curve(Curve::P256)
                .with_declared_alg(DeclaredAlg::UnknownJose("ESP256".into())),
            vec![],
        ),
    ];
    for (params, expected) in table {
        assert_eq!(algs_for_key(&params), expected, "{params:?}");
    }
}

#[test]
fn algs_for_key_agrees_with_check_key() {
    let mut all_params = vec![
        KeyParams::curve(Curve::P256),
        KeyParams::curve(Curve::P384),
        KeyParams::curve(Curve::P521),
        KeyParams::curve(Curve::Ed25519),
        KeyParams::rsa(1024),
        KeyParams::rsa(2048),
        KeyParams::rsa(3072),
        KeyParams::ml_dsa(MlDsaParams::MlDsa44),
        KeyParams::ml_dsa(MlDsaParams::MlDsa65),
        KeyParams::ml_dsa(MlDsaParams::MlDsa87),
    ];
    let declared: Vec<KeyParams> = all_params
        .iter()
        .flat_map(|p| {
            Alg::ALL
                .iter()
                .map(|a| p.clone().with_declared_alg(DeclaredAlg::Known(*a)))
        })
        .collect();
    all_params.extend(declared);
    for params in &all_params {
        let expected: Vec<Alg> = Alg::ALL
            .into_iter()
            .filter(|a| check_key(*a, params).is_empty())
            .collect();
        assert_eq!(algs_for_key(params), expected, "{params:?}");
    }
}
