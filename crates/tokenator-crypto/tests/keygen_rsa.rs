//! RSA key generation (slow in debug builds, so kept in its own test binary;
//! 3072/4096 are `#[ignore]`d — run with `cargo test -- --ignored`).

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use rand_core::SeedableRng;
use tokenator_crypto::{
    Alg, CryptoError, KeyParams, KeySpec, PrivateKeyMaterial, PublicKeyMaterial, generate,
    generate_from_seed, sign, verify,
};

fn check_generated(bits: u32) {
    let key = generate(KeySpec::Rsa { bits }, &mut rng(1)).unwrap();
    assert_eq!(key.params(), KeyParams::rsa(bits));
    let PublicKeyMaterial::Rsa { n, e } = key.public_key().to_material() else {
        panic!()
    };
    assert_eq!(n.len() * 8, bits as usize);
    assert!(n[0] & 0x80 != 0, "modulus has exactly {bits} bits");
    assert_eq!(e, vec![1, 0, 1], "e = 65537");
    let PrivateKeyMaterial::Rsa(m) = key.to_material() else {
        panic!()
    };
    assert!(m.p.is_some() && m.q.is_some() && m.dp.is_some() && m.dq.is_some() && m.qi.is_some());
    let sig = sign(Alg::PS256, &key, b"msg", &mut rng(2)).unwrap();
    assert_eq!(sig.len(), bits as usize / 8);
    verify(Alg::PS256, &key.public_key(), b"msg", &sig).unwrap();
}

#[test]
fn generate_rsa_2048() {
    check_generated(2048);
}

#[test]
#[ignore = "slow in debug builds"]
fn generate_rsa_3072() {
    check_generated(3072);
}

#[test]
#[ignore = "slow in debug builds"]
fn generate_rsa_4096() {
    check_generated(4096);
}

#[test]
fn unsupported_rsa_sizes_are_rejected() {
    for bits in [0, 512, 1024, 2047, 2049, 2056, 5000, 8192] {
        let r = generate(KeySpec::Rsa { bits }, &mut rng(1));
        assert!(
            matches!(r, Err(CryptoError::UnsupportedKeySpec(_))),
            "{bits}"
        );
        let r = generate_from_seed(KeySpec::Rsa { bits }, &[1; 32]);
        assert!(
            matches!(r, Err(CryptoError::UnsupportedKeySpec(_))),
            "{bits}"
        );
    }
}

#[test]
fn rsa_seed_is_reproducible_and_keys_a_chacha20_rng() {
    let spec = KeySpec::Rsa { bits: 2048 };
    let seed = [0x11; 32];
    let a = generate_from_seed(spec, &seed).unwrap();
    let b = generate_from_seed(spec, &seed).unwrap();
    assert_eq!(a.to_material(), b.to_material());
    let via_rng = generate(spec, &mut rand_chacha::ChaCha20Rng::from_seed(seed)).unwrap();
    assert_eq!(a.to_material(), via_rng.to_material());
}
