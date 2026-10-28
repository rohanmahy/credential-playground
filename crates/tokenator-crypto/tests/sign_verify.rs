//! sign / sign_deterministic / verify round trips and failure modes for every Alg.

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
    Alg, CryptoError, KeySpec, MlDsaParams, PublicKeyMaterial, check_key, generate_from_seed, sign,
    sign_deterministic, verify,
};

const MSG: &[u8] = b"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0b2tlbmF0b3IifQ";

const RSA_ALGS: [Alg; 6] = [
    Alg::RS256,
    Alg::RS384,
    Alg::RS512,
    Alg::PS256,
    Alg::PS384,
    Alg::PS512,
];

/// Algorithms whose signatures depend on randomness.
fn is_randomized(alg: Alg) -> bool {
    matches!(
        alg,
        Alg::ES256
            | Alg::ES384
            | Alg::ES512
            | Alg::PS256
            | Alg::PS384
            | Alg::PS512
            | Alg::MlDsa44
            | Alg::MlDsa65
            | Alg::MlDsa87
    )
}

fn expected_len(alg: Alg) -> usize {
    // The RSA test key is 2048 bits.
    alg.fixed_signature_len().unwrap_or(256)
}

#[test]
fn round_trip_every_alg() {
    for alg in Alg::ALL {
        let key = key_for(alg);
        let sig = sign(alg, &key, MSG, &mut rng(1)).unwrap();
        assert_eq!(sig.len(), expected_len(alg), "{alg:?}");
        verify(alg, &key.public_key(), MSG, &sig).unwrap_or_else(|e| panic!("{alg:?}: {e}"));
    }
}

#[test]
fn deterministic_round_trip_every_alg_except_pss() {
    for alg in Alg::ALL {
        let key = key_for(alg);
        let r = sign_deterministic(alg, &key, MSG);
        if matches!(alg, Alg::PS256 | Alg::PS384 | Alg::PS512) {
            assert_eq!(r, Err(CryptoError::RandomnessRequired(alg)));
            continue;
        }
        let sig = r.unwrap();
        assert_eq!(sig.len(), expected_len(alg), "{alg:?}");
        assert_eq!(
            sign_deterministic(alg, &key, MSG).unwrap(),
            sig,
            "{alg:?} is reproducible"
        );
        verify(alg, &key.public_key(), MSG, &sig).unwrap_or_else(|e| panic!("{alg:?}: {e}"));
    }
}

#[test]
fn round_trip_with_freshly_generated_keys() {
    for alg in Alg::ALL {
        if RSA_ALGS.contains(&alg) {
            continue; // RSA keygen is covered in keygen_rsa.rs
        }
        let key = tokenator_crypto::generate(KeySpec::for_alg(alg), &mut rng(77)).unwrap();
        let sig = sign(alg, &key, MSG, &mut rng(78)).unwrap();
        verify(alg, &key.public_key(), MSG, &sig).unwrap();
    }
}

#[test]
fn round_trip_message_sizes() {
    let big = vec![0x5au8; 1 << 20];
    for alg in Alg::ALL {
        let key = key_for(alg);
        for msg in [&b""[..], &b"x"[..], &big[..]] {
            let sig = sign(alg, &key, msg, &mut rng(3)).unwrap();
            verify(alg, &key.public_key(), msg, &sig)
                .unwrap_or_else(|e| panic!("{alg:?} len {}: {e}", msg.len()));
        }
    }
}

#[test]
fn same_rng_seed_gives_same_signature() {
    for alg in Alg::ALL {
        let key = key_for(alg);
        let a = sign(alg, &key, MSG, &mut rng(5)).unwrap();
        let b = sign(alg, &key, MSG, &mut rng(5)).unwrap();
        assert_eq!(a, b, "{alg:?}");
    }
}

#[test]
fn randomized_algs_use_the_rng() {
    for alg in Alg::ALL.into_iter().filter(|a| is_randomized(*a)) {
        let key = key_for(alg);
        let a = sign(alg, &key, MSG, &mut rng(5)).unwrap();
        let b = sign(alg, &key, MSG, &mut rng(6)).unwrap();
        assert_ne!(a, b, "{alg:?}");
        if let Ok(det) = sign_deterministic(alg, &key, MSG) {
            // ECDSA is hedged (RFC 6979 + entropy) and ML-DSA is hedged, so
            // sign() differs from the purely deterministic variant.
            assert_ne!(a, det, "{alg:?}");
        }
    }
}

#[test]
fn deterministic_algs_ignore_the_rng() {
    for alg in Alg::ALL.into_iter().filter(|a| !is_randomized(*a)) {
        let key = key_for(alg);
        let det = sign_deterministic(alg, &key, MSG).unwrap();
        assert_eq!(sign(alg, &key, MSG, &mut rng(5)).unwrap(), det, "{alg:?}");
        assert_eq!(sign(alg, &key, MSG, &mut rng(6)).unwrap(), det, "{alg:?}");
    }
}

#[test]
fn eddsa_and_ed25519_produce_identical_interchangeable_signatures() {
    let key = key_for(Alg::Ed25519);
    let a = sign(Alg::EdDSA, &key, MSG, &mut rng(1)).unwrap();
    let b = sign(Alg::Ed25519, &key, MSG, &mut rng(1)).unwrap();
    assert_eq!(a, b);
    verify(Alg::Ed25519, &key.public_key(), MSG, &a).unwrap();
    verify(Alg::EdDSA, &key.public_key(), MSG, &b).unwrap();
}

#[test]
fn tampered_message_fails() {
    for alg in Alg::ALL {
        let key = key_for(alg);
        let sig = sign(alg, &key, MSG, &mut rng(1)).unwrap();
        for i in [0, MSG.len() / 2, MSG.len() - 1] {
            assert_eq!(
                verify(alg, &key.public_key(), &flip(MSG, i), &sig),
                Err(CryptoError::InvalidSignature),
                "{alg:?}"
            );
        }
        assert_eq!(
            verify(alg, &key.public_key(), &MSG[..MSG.len() - 1], &sig),
            Err(CryptoError::InvalidSignature)
        );
        assert_eq!(
            verify(alg, &key.public_key(), &[MSG, b"x"].concat(), &sig),
            Err(CryptoError::InvalidSignature)
        );
    }
}

#[test]
fn tampered_signature_fails() {
    for alg in Alg::ALL {
        let key = key_for(alg);
        let public = key.public_key();
        let sig = sign(alg, &key, MSG, &mut rng(1)).unwrap();
        for i in [0, 1, sig.len() / 2, sig.len() - 1] {
            assert_eq!(
                verify(alg, &public, MSG, &flip(&sig, i)),
                Err(CryptoError::InvalidSignature),
                "{alg:?} byte {i}"
            );
        }
    }
}

#[test]
fn wrong_length_signatures_fail() {
    for alg in Alg::ALL {
        let key = key_for(alg);
        let public = key.public_key();
        let sig = sign(alg, &key, MSG, &mut rng(1)).unwrap();
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            sig[..sig.len() - 1].to_vec(),
            [&sig[..], &[0]].concat(),
            [&[0], &sig[..]].concat(),
            sig[..sig.len() / 2].to_vec(),
            [&sig[..], &sig[..]].concat(),
            vec![0; sig.len()],
        ];
        for bad in cases {
            assert_eq!(
                verify(alg, &public, MSG, &bad),
                Err(CryptoError::InvalidSignature),
                "{alg:?} len {}",
                bad.len()
            );
        }
    }
}

/// DER-encode a raw `r || s` ECDSA signature.
fn to_der(raw: &[u8]) -> Vec<u8> {
    fn int(v: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = v.iter().copied().skip_while(|b| *b == 0).collect();
        if v.first().is_none_or(|b| b & 0x80 != 0) {
            v.insert(0, 0);
        }
        let mut out = vec![0x02, v.len() as u8];
        out.extend(v);
        out
    }
    let (r, s) = raw.split_at(raw.len() / 2);
    let body = [int(r), int(s)].concat();
    let mut out = vec![0x30];
    if body.len() >= 0x80 {
        out.push(0x81);
    }
    out.push(body.len() as u8);
    out.extend(body);
    out
}

#[test]
fn ecdsa_signatures_are_raw_r_s_not_der() {
    for alg in [Alg::ES256, Alg::ES384, Alg::ES512] {
        let key = key_for(alg);
        let sig = sign(alg, &key, MSG, &mut rng(1)).unwrap();
        assert_ne!(sig[0], 0x30, "{alg:?} looks like DER");
        let der = to_der(&sig);
        assert_eq!(
            verify(alg, &key.public_key(), MSG, &der),
            Err(CryptoError::InvalidSignature),
            "{alg:?}"
        );
    }
}

#[test]
fn ecdsa_r_and_s_halves_are_fixed_width() {
    // Even when r or s has leading zero bytes, the halves stay field-sized.
    for alg in [Alg::ES256, Alg::ES384, Alg::ES512] {
        let key = key_for(alg);
        let width = alg.fixed_signature_len().unwrap() / 2;
        for i in 0..64u32 {
            let msg = i.to_be_bytes();
            let sig = sign_deterministic(alg, &key, &msg).unwrap();
            assert_eq!(sig.len(), 2 * width, "{alg:?}");
        }
    }
}

#[test]
fn wrong_public_key_of_same_type_fails() {
    for alg in Alg::ALL {
        let key = key_for(alg);
        let other = match KeySpec::for_alg(alg) {
            KeySpec::Rsa { .. } => {
                // A different RSA public key: the Wycheproof 2048-bit key.
                let v = load_json("wycheproof/rsa_signature_2048_sha256_test.json");
                let g = &v["testGroups"][0];
                tokenator_crypto::PublicKey::from_material(&PublicKeyMaterial::Rsa {
                    n: hex(&g["publicKey"]["modulus"]),
                    e: hex(&g["publicKey"]["publicExponent"]),
                })
                .unwrap()
            }
            spec => generate_from_seed(spec, &[0x99; 32]).unwrap().public_key(),
        };
        let sig = sign(alg, &key, MSG, &mut rng(1)).unwrap();
        assert_eq!(
            verify(alg, &other, MSG, &sig),
            Err(CryptoError::InvalidSignature),
            "{alg:?}"
        );
    }
}

#[test]
fn wrong_alg_with_same_key_fails() {
    let rsa = key_for(Alg::RS256);
    for signed in RSA_ALGS {
        let sig = sign(signed, &rsa, MSG, &mut rng(1)).unwrap();
        for checked in RSA_ALGS.into_iter().filter(|a| *a != signed) {
            assert_eq!(
                verify(checked, &rsa.public_key(), MSG, &sig),
                Err(CryptoError::InvalidSignature),
                "signed {signed:?}, verified as {checked:?}"
            );
        }
    }
}

#[test]
fn unsuitable_key_is_rejected_for_sign_and_verify() {
    for alg in Alg::ALL {
        let wrong = wrong_key_for(alg);
        let expected = CryptoError::KeyNotSuitable {
            alg,
            mismatches: check_key(alg, &wrong.params()),
        };
        assert!(!check_key(alg, &wrong.params()).is_empty(), "{alg:?}");
        assert_eq!(
            sign(alg, &wrong, MSG, &mut rng(1)),
            Err(expected.clone()),
            "{alg:?} sign"
        );
        if !matches!(alg, Alg::PS256 | Alg::PS384 | Alg::PS512) {
            assert_eq!(
                sign_deterministic(alg, &wrong, MSG),
                Err(expected.clone()),
                "{alg:?} sign_deterministic"
            );
        }
        let fake_sig = vec![0u8; expected_len(alg)];
        assert_eq!(
            verify(alg, &wrong.public_key(), MSG, &fake_sig),
            Err(expected),
            "{alg:?} verify"
        );
    }
}

#[test]
fn ml_dsa_signature_from_one_param_set_does_not_verify_under_another() {
    let k44 = generate_from_seed(KeySpec::MlDsa(MlDsaParams::MlDsa44), &[1; 32]).unwrap();
    let k65 = generate_from_seed(KeySpec::MlDsa(MlDsaParams::MlDsa65), &[1; 32]).unwrap();
    let sig65 = sign(Alg::MlDsa65, &k65, MSG, &mut rng(1)).unwrap();
    // ML-DSA-65 key used with ML-DSA-44 alg: unsuitable key, not a bad signature.
    assert!(matches!(
        verify(Alg::MlDsa44, &k65.public_key(), MSG, &sig65),
        Err(CryptoError::KeyNotSuitable {
            alg: Alg::MlDsa44,
            ..
        })
    ));
    assert!(matches!(
        verify(Alg::MlDsa44, &k44.public_key(), MSG, &sig65),
        Err(CryptoError::InvalidSignature)
    ));
}

#[test]
fn verify_does_not_panic_on_garbage() {
    let junk: Vec<Vec<u8>> = vec![
        vec![],
        vec![0xff; 1],
        vec![0xff; 64],
        vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
        vec![0xab; 5000],
    ];
    for alg in Alg::ALL {
        let public = key_for(alg).public_key();
        for sig in &junk {
            assert!(verify(alg, &public, MSG, sig).is_err(), "{alg:?}");
        }
    }
}
