//! Key material parsing/validation, params(), Debug redaction, and EC /
//! Ed25519 / ML-DSA key generation. RSA generation is in `keygen_rsa.rs`.

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
    Alg, CryptoError, Curve, KeyParams, KeySpec, MlDsaParams, PrivateKey, PrivateKeyMaterial,
    PublicKey, PublicKeyMaterial, RsaPrivateMaterial, generate, generate_from_seed,
};

const NON_RSA_SPECS: [KeySpec; 7] = [
    KeySpec::P256,
    KeySpec::P384,
    KeySpec::P521,
    KeySpec::Ed25519,
    KeySpec::MlDsa(MlDsaParams::MlDsa44),
    KeySpec::MlDsa(MlDsaParams::MlDsa65),
    KeySpec::MlDsa(MlDsaParams::MlDsa87),
];

fn expected_params(spec: KeySpec) -> KeyParams {
    match spec {
        KeySpec::P256 => KeyParams::curve(Curve::P256),
        KeySpec::P384 => KeyParams::curve(Curve::P384),
        KeySpec::P521 => KeyParams::curve(Curve::P521),
        KeySpec::Ed25519 => KeyParams::curve(Curve::Ed25519),
        KeySpec::Rsa { bits } => KeyParams::rsa(bits),
        KeySpec::MlDsa(p) => KeyParams::ml_dsa(p),
    }
}

fn is_invalid_key(r: Result<impl std::fmt::Debug, CryptoError>) -> bool {
    matches!(r, Err(CryptoError::InvalidKey(_)))
}

// ---------------------------------------------------------------- KeySpec

#[test]
fn key_spec_for_alg() {
    let table = [
        (Alg::ES256, KeySpec::P256),
        (Alg::ES384, KeySpec::P384),
        (Alg::ES512, KeySpec::P521),
        (Alg::EdDSA, KeySpec::Ed25519),
        (Alg::Ed25519, KeySpec::Ed25519),
        (Alg::RS256, KeySpec::Rsa { bits: 2048 }),
        (Alg::RS384, KeySpec::Rsa { bits: 2048 }),
        (Alg::RS512, KeySpec::Rsa { bits: 2048 }),
        (Alg::PS256, KeySpec::Rsa { bits: 2048 }),
        (Alg::PS384, KeySpec::Rsa { bits: 2048 }),
        (Alg::PS512, KeySpec::Rsa { bits: 2048 }),
        (Alg::MlDsa44, KeySpec::MlDsa(MlDsaParams::MlDsa44)),
        (Alg::MlDsa65, KeySpec::MlDsa(MlDsaParams::MlDsa65)),
        (Alg::MlDsa87, KeySpec::MlDsa(MlDsaParams::MlDsa87)),
    ];
    for (alg, spec) in table {
        assert_eq!(KeySpec::for_alg(alg), spec, "{alg:?}");
    }
}

// ---------------------------------------------------------------- generation

#[test]
fn generate_produces_keys_with_expected_params() {
    for spec in NON_RSA_SPECS {
        let key = generate(spec, &mut rng(1)).unwrap();
        assert_eq!(key.params(), expected_params(spec), "{spec:?}");
        assert_eq!(key.public_key().params(), expected_params(spec), "{spec:?}");
    }
}

#[test]
fn generate_draws_all_randomness_from_the_injected_rng() {
    for spec in NON_RSA_SPECS {
        let a = generate(spec, &mut rng(9)).unwrap();
        let b = generate(spec, &mut rng(9)).unwrap();
        let c = generate(spec, &mut rng(10)).unwrap();
        assert_eq!(
            a.to_material(),
            b.to_material(),
            "{spec:?}: same rng seed, same key"
        );
        assert_ne!(
            a.to_material(),
            c.to_material(),
            "{spec:?}: different rng seed, different key"
        );
    }
}

#[test]
fn generate_from_seed_is_reproducible() {
    for spec in NON_RSA_SPECS {
        let a = generate_from_seed(spec, &[3; 32]).unwrap();
        let b = generate_from_seed(spec, &[3; 32]).unwrap();
        let c = generate_from_seed(spec, &[4; 32]).unwrap();
        assert_eq!(a.to_material(), b.to_material(), "{spec:?}");
        assert_eq!(a.public_key(), b.public_key(), "{spec:?}");
        assert_ne!(a.to_material(), c.to_material(), "{spec:?}");
        assert_eq!(a.params(), expected_params(spec), "{spec:?}");
    }
}

#[test]
fn ec_seed_keys_a_chacha20_rng() {
    // Documented derivation: generate_from_seed(EC, s) == generate(EC, ChaCha20Rng::from_seed(s)).
    use rand_core::SeedableRng;
    for spec in [KeySpec::P256, KeySpec::P384, KeySpec::P521] {
        let seed = [0x5a; 32];
        let from_seed = generate_from_seed(spec, &seed).unwrap();
        let from_rng = generate(spec, &mut rand_chacha::ChaCha20Rng::from_seed(seed)).unwrap();
        assert_eq!(from_seed.to_material(), from_rng.to_material(), "{spec:?}");
    }
}

#[test]
fn ed25519_seed_is_the_rfc8032_secret_key() {
    let v = load_json("rfc/rfc8032-ed25519.json");
    for t in v["vectors"].as_array().unwrap() {
        let secret: [u8; 32] = hex(&t["secret"]).try_into().unwrap();
        let key = generate_from_seed(KeySpec::Ed25519, &secret).unwrap();
        assert_eq!(
            key.to_material(),
            PrivateKeyMaterial::Ed25519 { d: secret.to_vec() }
        );
        assert_eq!(
            key.public_key().to_material(),
            PublicKeyMaterial::Ed25519 {
                x: hex(&t["public"])
            },
            "{}",
            t["name"]
        );
    }
}

#[test]
fn ml_dsa_seed_is_fips204_xi_rfc9964() {
    for (p, params) in [
        (44, MlDsaParams::MlDsa44),
        (65, MlDsaParams::MlDsa65),
        (87, MlDsaParams::MlDsa87),
    ] {
        let v = load_json(&format!("rfc9964/ml-dsa-{p}-jose.json"));
        let seed: [u8; 32] = hex(&v["priv"]).try_into().unwrap();
        let key = generate_from_seed(KeySpec::MlDsa(params), &seed).unwrap();
        assert_eq!(
            key.public_key().to_material(),
            PublicKeyMaterial::MlDsa {
                params,
                public: hex(&v["raw_public_key"])
            },
            "ML-DSA-{p}"
        );
        match key.to_material() {
            PrivateKeyMaterial::MlDsa {
                params: got,
                seed: s,
                expanded,
            } => {
                assert_eq!(got, params);
                assert_eq!(s, Some(seed.to_vec()));
                assert_eq!(
                    expanded.map(|e| e.len()),
                    Some(params.expanded_private_key_len())
                );
            }
            other => panic!("unexpected material {other:?}"),
        }
    }
}

#[test]
fn generated_material_has_fixed_widths() {
    for (spec, crv) in [
        (KeySpec::P256, Curve::P256),
        (KeySpec::P384, Curve::P384),
        (KeySpec::P521, Curve::P521),
    ] {
        // Several seeds so that a leading zero byte would show up eventually.
        for s in 0..16u8 {
            let key = generate_from_seed(spec, &[s; 32]).unwrap();
            match key.to_material() {
                PrivateKeyMaterial::Ec { curve, d } => {
                    assert_eq!(curve, crv);
                    assert_eq!(d.len(), crv.field_len());
                }
                other => panic!("{other:?}"),
            }
            match key.public_key().to_material() {
                PublicKeyMaterial::Ec { curve, x, y } => {
                    assert_eq!(curve, crv);
                    assert_eq!(x.len(), crv.field_len());
                    assert_eq!(y.len(), crv.field_len());
                }
                other => panic!("{other:?}"),
            }
        }
    }
    for params in [
        MlDsaParams::MlDsa44,
        MlDsaParams::MlDsa65,
        MlDsaParams::MlDsa87,
    ] {
        let key = generate_from_seed(KeySpec::MlDsa(params), &[1; 32]).unwrap();
        match key.public_key().to_material() {
            PublicKeyMaterial::MlDsa { public, .. } => {
                assert_eq!(public.len(), params.public_key_len())
            }
            other => panic!("{other:?}"),
        }
    }
}

// ---------------------------------------------------------------- material round trips

#[test]
fn private_material_round_trips() {
    for spec in NON_RSA_SPECS {
        let key = generate_from_seed(spec, &[7; 32]).unwrap();
        let m = key.to_material();
        let back = PrivateKey::from_material(&m).unwrap();
        assert_eq!(back.to_material(), m, "{spec:?}");
        assert_eq!(back.public_key(), key.public_key(), "{spec:?}");
    }
    let rsa = rfc7515_rsa_key();
    let m = rsa.to_material();
    assert_eq!(PrivateKey::from_material(&m).unwrap().to_material(), m);
}

#[test]
fn public_material_round_trips() {
    for spec in NON_RSA_SPECS {
        let public = generate_from_seed(spec, &[8; 32]).unwrap().public_key();
        let m = public.to_material();
        assert_eq!(PublicKey::from_material(&m).unwrap(), public, "{spec:?}");
    }
    let public = rfc7515_rsa_key().public_key();
    assert_eq!(
        PublicKey::from_material(&public.to_material()).unwrap(),
        public
    );
}

#[test]
fn rfc7515_jwks_parse_and_derive_their_public_keys() {
    let v = load_json("rfc/rfc7515-jws.json");
    for t in v["vectors"].as_array().unwrap() {
        let private = PrivateKey::from_material(&private_material_from_jwk(&t["jwk"])).unwrap();
        let mut public_jwk = t["jwk"].clone();
        if public_jwk["kty"] == "RSA" {
            assert_eq!(
                private.public_key().to_material(),
                public_material_from_jwk(&public_jwk),
                "{}",
                t["alg"]
            );
        } else {
            // EC: the JWK carries x and y next to d.
            public_jwk.as_object_mut().unwrap().remove("d");
            assert_eq!(
                private.public_key().to_material(),
                public_material_from_jwk(&public_jwk),
                "{}",
                t["alg"]
            );
        }
    }
}

#[test]
fn rfc8037_ed25519_jwk() {
    let v = load_json("rfc/rfc8037-ed25519.json");
    let key = PrivateKey::from_material(&private_material_from_jwk(&v["jwk"])).unwrap();
    assert_eq!(
        key.public_key().to_material(),
        PublicKeyMaterial::Ed25519 {
            x: b64(&v["jwk"]["x"])
        }
    );
}

#[test]
fn rsa_output_material_is_minimal_and_complete() {
    let v = load_json("rfc/rfc7515-jws.json");
    let jwk = &v["vectors"][0]["jwk"];
    let key = rfc7515_rsa_key();
    match key.to_material() {
        PrivateKeyMaterial::Rsa(m) => {
            assert_eq!(m.n, b64(&jwk["n"]));
            assert_eq!(m.e, vec![1, 0, 1]);
            assert_eq!(m.d, b64(&jwk["d"]));
            assert_eq!(m.p, b64_opt(&jwk["p"]));
            assert_eq!(m.q, b64_opt(&jwk["q"]));
            assert_eq!(m.dp, b64_opt(&jwk["dp"]));
            assert_eq!(m.dq, b64_opt(&jwk["dq"]));
            assert_eq!(m.qi, b64_opt(&jwk["qi"]));
        }
        other => panic!("{other:?}"),
    }
    match key.public_key().to_material() {
        PublicKeyMaterial::Rsa { n, e } => {
            assert_eq!(
                n.first().copied().map(|b| b != 0),
                Some(true),
                "no leading zero"
            );
            assert_eq!(n.len(), 256);
            assert_eq!(e, vec![1, 0, 1]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn rsa_private_from_n_e_d_only_recovers_primes() {
    let v = load_json("rfc/rfc7515-jws.json");
    let jwk = &v["vectors"][0]["jwk"];
    let m = RsaPrivateMaterial {
        n: b64(&jwk["n"]),
        e: b64(&jwk["e"]),
        d: b64(&jwk["d"]),
        p: None,
        q: None,
        dp: None,
        dq: None,
        qi: None,
    };
    let key = PrivateKey::from_material(&PrivateKeyMaterial::Rsa(m)).unwrap();
    match key.to_material() {
        PrivateKeyMaterial::Rsa(out) => {
            let mut got = vec![out.p.unwrap(), out.q.unwrap()];
            let mut want = vec![b64(&jwk["p"]), b64(&jwk["q"])];
            got.sort();
            want.sort();
            assert_eq!(got, want);
            assert!(out.dp.is_some() && out.dq.is_some() && out.qi.is_some());
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(key.public_key(), rfc7515_rsa_key().public_key());
}

#[test]
fn rsa_leading_zeros_are_accepted() {
    let public = rfc7515_rsa_key().public_key();
    let PublicKeyMaterial::Rsa { n, e } = public.to_material() else {
        panic!()
    };
    let mut padded_n = vec![0, 0];
    padded_n.extend(&n);
    let mut padded_e = vec![0];
    padded_e.extend(&e);
    let again = PublicKey::from_material(&PublicKeyMaterial::Rsa {
        n: padded_n,
        e: padded_e,
    })
    .unwrap();
    assert_eq!(again, public);
    assert_eq!(again.to_material(), PublicKeyMaterial::Rsa { n, e });
}

// ---------------------------------------------------------------- params()

#[test]
fn params_from_material() {
    assert_eq!(rfc7515_rsa_key().params(), KeyParams::rsa(2048));
    assert_eq!(
        rfc7515_rsa_key().public_key().params(),
        KeyParams::rsa(2048)
    );
    for spec in NON_RSA_SPECS {
        let key = generate_from_seed(spec, &[2; 32]).unwrap();
        assert_eq!(key.params().declared_alg, None);
        assert_eq!(key.params(), expected_params(spec));
    }
}

// ---------------------------------------------------------------- Debug

#[test]
fn private_key_debug_does_not_leak_secrets() {
    let mut keys: Vec<PrivateKey> = NON_RSA_SPECS
        .iter()
        .map(|s| generate_from_seed(*s, &[0xab; 32]).unwrap())
        .collect();
    keys.push(rfc7515_rsa_key());
    for key in keys {
        let dbg = format!("{key:?}");
        let secret: Vec<u8> = match key.to_material() {
            PrivateKeyMaterial::Ec { d, .. } | PrivateKeyMaterial::Ed25519 { d } => d,
            PrivateKeyMaterial::Rsa(m) => m.d,
            PrivateKeyMaterial::MlDsa { seed, .. } => seed.unwrap(),
        };
        assert!(!dbg.is_empty());
        assert!(
            !dbg.to_lowercase().contains(&hex::encode(&secret[..8])),
            "{dbg}"
        );
        let decimal = format!("{}, {}, {}, {}", secret[0], secret[1], secret[2], secret[3]);
        assert!(!dbg.contains(&decimal), "{dbg}");
        assert!(!dbg.contains("171, 171, 171"), "seed bytes leaked: {dbg}");
    }
}

// ---------------------------------------------------------------- invalid material

const P256_ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

#[test]
fn ec_private_scalar_validation() {
    let ec = |curve, d: Vec<u8>| PrivateKey::from_material(&PrivateKeyMaterial::Ec { curve, d });
    assert!(is_invalid_key(ec(Curve::P256, vec![0; 32])), "zero scalar");
    assert!(
        is_invalid_key(ec(Curve::P256, hex::decode(P256_ORDER).unwrap())),
        "d == n"
    );
    assert!(is_invalid_key(ec(Curve::P256, vec![0xff; 32])), "d > n");
    assert!(is_invalid_key(ec(Curve::P256, vec![1; 31])), "short");
    assert!(is_invalid_key(ec(Curve::P256, vec![1; 33])), "long");
    assert!(
        is_invalid_key(ec(Curve::P384, vec![1; 32])),
        "P-256 width on P-384"
    );
    assert!(
        is_invalid_key(ec(Curve::P521, vec![1; 65])),
        "P-521 needs 66 bytes"
    );
    assert!(
        is_invalid_key(ec(Curve::Ed25519, vec![1; 32])),
        "Ed25519 is not an EC curve"
    );
    let mut one = vec![0; 32];
    one[31] = 1;
    assert!(ec(Curve::P256, one).is_ok(), "d == 1 is valid");
}

#[test]
fn ec_public_point_validation() {
    let key = generate_from_seed(KeySpec::P256, &[1; 32])
        .unwrap()
        .public_key();
    let PublicKeyMaterial::Ec { curve, x, y } = key.to_material() else {
        panic!()
    };
    let ec =
        |x: Vec<u8>, y: Vec<u8>| PublicKey::from_material(&PublicKeyMaterial::Ec { curve, x, y });
    assert!(ec(x.clone(), y.clone()).is_ok());
    assert!(is_invalid_key(ec(x.clone(), flip(&y, 31))), "not on curve");
    assert!(
        is_invalid_key(ec(vec![0; 32], vec![0; 32])),
        "identity / (0,0)"
    );
    assert!(is_invalid_key(ec(x[1..].to_vec(), y.clone())), "short x");
    assert!(
        is_invalid_key(ec(x.clone(), [y.clone(), vec![0]].concat())),
        "long y"
    );
    let wrong_curve = PublicKey::from_material(&PublicKeyMaterial::Ec {
        curve: Curve::P384,
        x,
        y,
    });
    assert!(is_invalid_key(wrong_curve), "P-256 coordinates on P-384");
}

#[test]
fn ed25519_length_validation() {
    for len in [0, 31, 33, 64] {
        assert!(
            is_invalid_key(PrivateKey::from_material(&PrivateKeyMaterial::Ed25519 {
                d: vec![1; len]
            })),
            "{len}"
        );
        assert!(
            is_invalid_key(PublicKey::from_material(&PublicKeyMaterial::Ed25519 {
                x: vec![1; len]
            })),
            "{len}"
        );
    }
}

#[test]
fn rsa_validation() {
    let PrivateKeyMaterial::Rsa(good) = rfc7515_rsa_key().to_material() else {
        panic!()
    };
    // Inconsistent d.
    let mut bad = good.clone();
    bad.d = flip(&bad.d, 10);
    assert!(is_invalid_key(PrivateKey::from_material(
        &PrivateKeyMaterial::Rsa(bad)
    )));
    // Wrong prime.
    let mut bad = good.clone();
    bad.p = bad.p.map(|p| flip(&p, 5));
    assert!(is_invalid_key(PrivateKey::from_material(
        &PrivateKeyMaterial::Rsa(bad)
    )));
    // n, e, d only, but d belongs to another modulus.
    let bad = RsaPrivateMaterial {
        d: flip(&good.d, 0),
        p: None,
        q: None,
        dp: None,
        dq: None,
        qi: None,
        ..good.clone()
    };
    assert!(is_invalid_key(PrivateKey::from_material(
        &PrivateKeyMaterial::Rsa(bad)
    )));
    // Public exponent 1 and empty modulus.
    let pk = |n: Vec<u8>, e: Vec<u8>| PublicKey::from_material(&PublicKeyMaterial::Rsa { n, e });
    assert!(is_invalid_key(pk(good.n.clone(), vec![1])));
    assert!(is_invalid_key(pk(vec![], vec![1, 0, 1])));
    assert!(is_invalid_key(pk(good.n.clone(), vec![])));
}

#[test]
fn ml_dsa_material_validation() {
    let params = MlDsaParams::MlDsa44;
    let key = generate_from_seed(KeySpec::MlDsa(params), &[5; 32]).unwrap();
    let PrivateKeyMaterial::MlDsa {
        seed: Some(seed),
        expanded: Some(expanded),
        ..
    } = key.to_material()
    else {
        panic!()
    };
    let ml = |seed: Option<Vec<u8>>, expanded: Option<Vec<u8>>| {
        PrivateKey::from_material(&PrivateKeyMaterial::MlDsa {
            params,
            seed,
            expanded,
        })
    };

    // Seed only, expanded only, both consistent.
    assert_eq!(
        ml(Some(seed.clone()), None).unwrap().public_key(),
        key.public_key()
    );
    let expanded_only = ml(None, Some(expanded.clone())).unwrap();
    assert_eq!(expanded_only.public_key(), key.public_key());
    assert_eq!(
        expanded_only.to_material(),
        PrivateKeyMaterial::MlDsa {
            params,
            seed: None,
            expanded: Some(expanded.clone())
        }
    );
    assert!(ml(Some(seed.clone()), Some(expanded.clone())).is_ok());

    // Neither, wrong lengths, disagreeing seed and expanded key.
    assert!(is_invalid_key(ml(None, None)));
    assert!(is_invalid_key(ml(Some(vec![5; 31]), None)));
    assert!(is_invalid_key(ml(Some(vec![5; 33]), None)));
    assert!(is_invalid_key(ml(None, Some(expanded[1..].to_vec()))));
    assert!(is_invalid_key(ml(
        Some(vec![6; 32]),
        Some(expanded.clone())
    )));

    // Expanded key of a different parameter set.
    let other = PrivateKeyMaterial::MlDsa {
        params: MlDsaParams::MlDsa65,
        seed: None,
        expanded: Some(expanded),
    };
    assert!(is_invalid_key(PrivateKey::from_material(&other)));

    // Public key lengths.
    let PublicKeyMaterial::MlDsa { public, .. } = key.public_key().to_material() else {
        panic!()
    };
    let pk = |params, public: Vec<u8>| {
        PublicKey::from_material(&PublicKeyMaterial::MlDsa { params, public })
    };
    assert!(pk(params, public.clone()).is_ok());
    assert!(is_invalid_key(pk(params, public[1..].to_vec())));
    assert!(is_invalid_key(pk(MlDsaParams::MlDsa65, public)));
}
