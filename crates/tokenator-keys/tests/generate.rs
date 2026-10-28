//! Key generation through tokenator-crypto: seeded (reproducible) and
//! random, roles, and seed validation.

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
    HashAlg, KeySpec, MlDsaParams, PublicKeyMaterial, digest, generate_from_seed,
};
use tokenator_keys::{Key, KeyError, Role, WELL_KNOWN_TEST_SEED, generate};

const FAST_SPECS: [KeySpec; 7] = [
    KeySpec::P256,
    KeySpec::P384,
    KeySpec::P521,
    KeySpec::Ed25519,
    KeySpec::MlDsa(MlDsaParams::MlDsa44),
    KeySpec::MlDsa(MlDsaParams::MlDsa65),
    KeySpec::MlDsa(MlDsaParams::MlDsa87),
];

#[test]
fn seeded_generation_is_reproducible_and_ignores_rng() {
    let seed = [0x42u8; 32];
    for spec in FAST_SPECS {
        let a = generate(spec, None, Some(&seed), &mut rng(1)).unwrap();
        let b = generate(spec, None, Some(&seed), &mut rng(2)).unwrap();
        assert_eq!(a, b, "{spec:?}");
        // Same as tokenator-crypto's own seeded generation.
        let direct = Key::from_private(generate_from_seed(spec, &seed).unwrap());
        assert_same_material(&a, &direct, &format!("{spec:?}"));
    }
}

#[test]
fn different_seeds_give_different_keys() {
    for spec in FAST_SPECS {
        let a = generate(spec, None, Some(&[1; 32]), &mut rng(0)).unwrap();
        let b = generate(spec, None, Some(&[2; 32]), &mut rng(0)).unwrap();
        assert!(!a.same_material(&b), "{spec:?}");
    }
}

#[test]
fn random_generation_uses_the_rng() {
    for spec in FAST_SPECS {
        let a = generate(spec, None, None, &mut rng(7)).unwrap();
        let b = generate(spec, None, None, &mut rng(7)).unwrap();
        let c = generate(spec, None, None, &mut rng(8)).unwrap();
        assert!(a.same_material(&b), "{spec:?}: same RNG stream, same key");
        assert!(!a.same_material(&c), "{spec:?}");
    }
}

#[test]
fn generated_keys_carry_only_the_role() {
    for (i, role) in [
        None,
        Some(Role::Issuer),
        Some(Role::Holder),
        Some(Role::Verifier),
    ]
    .into_iter()
    .enumerate()
    {
        let key = generate(KeySpec::P256, role, None, &mut rng(i as u8)).unwrap();
        assert!(key.is_private());
        assert_eq!(key.role, role);
        assert_eq!(key.kid, None);
        assert_eq!(key.alg, None);
        assert_eq!(key.key_use, None);
        assert_eq!(key.key_ops, None);
        assert!(key.extras.is_empty());
        assert!(!key.derived);
    }
}

#[test]
fn seeds_of_other_lengths_are_hashed_first() {
    for len in [0usize, 1, 16, 31, 33, 64] {
        let seed = vec![9u8; len];
        let hashed: [u8; 32] = digest(HashAlg::Sha256, &seed).try_into().unwrap();
        for spec in [
            KeySpec::Ed25519,
            KeySpec::P256,
            KeySpec::MlDsa(MlDsaParams::MlDsa44),
        ] {
            let a = generate(spec, None, Some(&seed), &mut rng(0)).unwrap();
            let b = generate(spec, None, Some(&hashed), &mut rng(1)).unwrap();
            assert_eq!(a, b, "len {len} {spec:?}");
        }
    }
}

#[test]
fn well_known_test_seed_reproduces_rfc9964() {
    assert_eq!(WELL_KNOWN_TEST_SEED, [0; 32]);
    let key = generate(
        KeySpec::MlDsa(MlDsaParams::MlDsa44),
        None,
        Some(&WELL_KNOWN_TEST_SEED),
        &mut rng(0),
    )
    .unwrap();
    let rfc = import_fixture("rfc9964/ml-dsa-44-private.jwk.json");
    assert_same_material(&key, &rfc, "RFC 9964 A.1");
}

#[test]
fn unsupported_rsa_size_is_an_error() {
    let err = generate(
        KeySpec::Rsa { bits: 1024 },
        None,
        Some(&[0; 32]),
        &mut rng(0),
    )
    .unwrap_err();
    assert!(matches!(err, KeyError::Crypto(_)), "{err:?}");
}

#[test]
fn ed25519_seed_is_the_rfc8037_secret() {
    let rfc = import_fixture("rfc8037/ed25519-private.json");
    let d =
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
    let key = generate(KeySpec::Ed25519, None, Some(&d), &mut rng(0)).unwrap();
    assert_same_material(&key, &rfc, "RFC 8037 A.1");
}

#[test]
fn ml_dsa_zero_seed_is_the_rfc9964_key() {
    for (p, set) in [
        ("44", MlDsaParams::MlDsa44),
        ("65", MlDsaParams::MlDsa65),
        ("87", MlDsaParams::MlDsa87),
    ] {
        let key = generate(
            KeySpec::MlDsa(set),
            Some(Role::Issuer),
            Some(&[0; 32]),
            &mut rng(0),
        )
        .unwrap();
        let kat = testdata_json(&format!("rfc9964/ml-dsa-{p}-jose.json"));
        assert_eq!(
            key.public_key().to_material(),
            PublicKeyMaterial::MlDsa {
                params: set,
                public: hexv(&kat["raw_public_key"]),
            }
        );
        let rfc = import_fixture(&format!("rfc9964/ml-dsa-{p}-private.jwk.json"));
        assert_same_material(&key, &rfc, p);
    }
}

#[test]
fn ml_dsa_counting_seed_is_the_rfc9881_key() {
    let seed: Vec<u8> = (0u8..32).collect();
    for (p, set) in [
        ("44", MlDsaParams::MlDsa44),
        ("65", MlDsaParams::MlDsa65),
        ("87", MlDsaParams::MlDsa87),
    ] {
        let key = generate(KeySpec::MlDsa(set), None, Some(&seed), &mut rng(0)).unwrap();
        let rfc = import_fixture(&format!("rfc9881/ml-dsa-{p}-seed.pem"));
        assert_eq!(key, rfc, "ML-DSA-{p}");
    }
}

#[test]
fn seeded_rsa_2048_is_reproducible() {
    let spec = KeySpec::Rsa { bits: 2048 };
    let a = generate(spec, None, Some(&[5; 32]), &mut rng(0)).unwrap();
    let b = generate(spec, None, Some(&[5; 32]), &mut rng(1)).unwrap();
    assert_eq!(a, b);
    assert_eq!(tokenator_keys::params(&a).rsa_bits, Some(2048));
}

#[test]
#[ignore = "slow in debug builds"]
fn seeded_rsa_3072_and_4096_are_reproducible() {
    for bits in [3072, 4096] {
        let spec = KeySpec::Rsa { bits };
        let a = generate(spec, None, Some(&[6; 32]), &mut rng(0)).unwrap();
        let b = generate(spec, None, Some(&[6; 32]), &mut rng(1)).unwrap();
        assert_eq!(a, b);
        assert_eq!(tokenator_keys::params(&a).rsa_bits, Some(bits));
    }
}
