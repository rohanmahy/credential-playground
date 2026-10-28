//! Known-answer tests from RFC 7515, RFC 8037, RFC 8032, RFC 6979, RFC 9964.
//! Vectors live in `testdata/rfc*/` (see TEST-PLAN.md for provenance).

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
    Alg, CryptoError, Curve, KeySpec, MlDsaParams, PrivateKey, PrivateKeyMaterial, PublicKey,
    PublicKeyMaterial, alg_from_jose, generate_from_seed, sign, sign_deterministic, verify,
};

// ---------------------------------------------------------------- RFC 7515

#[test]
fn rfc7515_appendix_a_verify() {
    let v = load_json("rfc/rfc7515-jws.json");
    for t in v["vectors"].as_array().unwrap() {
        let alg = alg_from_jose(t["alg"].as_str().unwrap()).unwrap();
        let mut jwk = t["jwk"].clone();
        let private = PrivateKey::from_material(&private_material_from_jwk(&jwk)).unwrap();
        jwk.as_object_mut().unwrap().remove("d");
        let public = if alg == Alg::RS256 {
            private.public_key()
        } else {
            PublicKey::from_material(&public_material_from_jwk(&jwk)).unwrap()
        };
        let input = t["signing_input"].as_str().unwrap().as_bytes();
        let sig = b64(&t["signature"]);
        verify(alg, &public, input, &sig)
            .unwrap_or_else(|e| panic!("{} {alg:?}: {e}", t["section"]));
        assert_eq!(
            verify(alg, &public, input, &flip(&sig, 3)),
            Err(CryptoError::InvalidSignature)
        );
    }
}

#[test]
fn rfc7515_a2_rs256_sign_is_exact() {
    // PKCS#1 v1.5 is deterministic, so signing reproduces the RFC's bytes.
    let v = load_json("rfc/rfc7515-jws.json");
    let t = &v["vectors"][0];
    assert_eq!(t["alg"], "RS256");
    let key = PrivateKey::from_material(&private_material_from_jwk(&t["jwk"])).unwrap();
    let input = t["signing_input"].as_str().unwrap().as_bytes();
    let expected = b64(&t["signature"]);
    assert_eq!(
        sign_deterministic(Alg::RS256, &key, input).unwrap(),
        expected
    );
    assert_eq!(
        sign(Alg::RS256, &key, input, &mut rng(1)).unwrap(),
        expected
    );
}

#[test]
fn rfc7515_a3_a4_ecdsa_signature_widths() {
    let v = load_json("rfc/rfc7515-jws.json");
    assert_eq!(b64(&v["vectors"][1]["signature"]).len(), 64);
    assert_eq!(b64(&v["vectors"][2]["signature"]).len(), 132);
}

// ---------------------------------------------------------------- RFC 8037

#[test]
fn rfc8037_a4_ed25519_sign_and_verify() {
    let v = load_json("rfc/rfc8037-ed25519.json");
    let key = PrivateKey::from_material(&private_material_from_jwk(&v["jwk"])).unwrap();
    let input = v["signing_input"].as_str().unwrap().as_bytes();
    let expected = b64(&v["signature"]);
    assert_eq!(hex::encode(&expected), v["signature_hex"].as_str().unwrap());
    // The RFC uses alg "EdDSA"; Ed25519 (RFC 9864) is the same signature.
    for alg in [Alg::EdDSA, Alg::Ed25519] {
        assert_eq!(
            sign_deterministic(alg, &key, input).unwrap(),
            expected,
            "{alg:?}"
        );
        assert_eq!(
            sign(alg, &key, input, &mut rng(1)).unwrap(),
            expected,
            "{alg:?}"
        );
        let public = PublicKey::from_material(&public_material_from_jwk(&serde_json::json!({
            "kty": "OKP", "crv": "Ed25519", "x": v["jwk"]["x"]
        })))
        .unwrap();
        verify(alg, &public, input, &expected).unwrap();
    }
}

// ---------------------------------------------------------------- RFC 8032

#[test]
fn rfc8032_section_7_1_ed25519() {
    let v = load_json("rfc/rfc8032-ed25519.json");
    let vectors = v["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 5);
    for t in vectors {
        let name = t["name"].as_str().unwrap();
        let key = PrivateKey::from_material(&PrivateKeyMaterial::Ed25519 {
            d: hex(&t["secret"]),
        })
        .unwrap();
        assert_eq!(
            key.public_key().to_material(),
            PublicKeyMaterial::Ed25519 {
                x: hex(&t["public"])
            },
            "{name}"
        );
        let msg = hex(&t["msg"]);
        let sig = hex(&t["sig"]);
        assert_eq!(
            sign_deterministic(Alg::Ed25519, &key, &msg).unwrap(),
            sig,
            "TEST {name}"
        );
        let public = PublicKey::from_material(&PublicKeyMaterial::Ed25519 {
            x: hex(&t["public"]),
        })
        .unwrap();
        verify(Alg::Ed25519, &public, &msg, &sig).unwrap();
        verify(Alg::EdDSA, &public, &msg, &sig).unwrap();
        assert_eq!(
            verify(Alg::Ed25519, &public, &msg, &flip(&sig, 63)),
            Err(CryptoError::InvalidSignature)
        );
    }
}

// ---------------------------------------------------------------- RFC 6979

#[test]
fn rfc6979_deterministic_ecdsa() {
    let v = load_json("rfc/rfc6979-ecdsa.json");
    let vectors = v["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 6);
    for t in vectors {
        let alg = alg_from_jose(t["alg"].as_str().unwrap()).unwrap();
        let curve = Curve::from_jwk_name(t["curve"].as_str().unwrap()).unwrap();
        let key = PrivateKey::from_material(&PrivateKeyMaterial::Ec {
            curve,
            d: hex(&t["d"]),
        })
        .unwrap();
        assert_eq!(
            key.public_key().to_material(),
            PublicKeyMaterial::Ec {
                curve,
                x: hex(&t["x"]),
                y: hex(&t["y"])
            },
            "{alg:?} public key"
        );
        let msg = t["msg"].as_str().unwrap().as_bytes();
        let expected = [hex(&t["r"]), hex(&t["s"])].concat();
        assert_eq!(
            sign_deterministic(alg, &key, msg).unwrap(),
            expected,
            "{alg:?} {:?}",
            t["msg"]
        );
        verify(alg, &key.public_key(), msg, &expected).unwrap();
    }
}

// ---------------------------------------------------------------- RFC 9964 (ML-DSA)

fn ml_dsa(p: u32) -> (Alg, MlDsaParams) {
    match p {
        44 => (Alg::MlDsa44, MlDsaParams::MlDsa44),
        65 => (Alg::MlDsa65, MlDsaParams::MlDsa65),
        _ => (Alg::MlDsa87, MlDsaParams::MlDsa87),
    }
}

#[test]
fn rfc9964_appendix_a_examples() {
    for p in [44, 65, 87] {
        for family in ["jose", "cose"] {
            let v = load_json(&format!("rfc9964/ml-dsa-{p}-{family}.json"));
            let (alg, params) = ml_dsa(p);
            let seed: [u8; 32] = hex(&v["priv"]).try_into().unwrap();
            let tbs = hex(&v["raw_to_be_signed"]);
            let sig = hex(&v["raw_signature"]);
            assert_eq!(sig.len(), params.signature_len());

            let public = PublicKey::from_material(&PublicKeyMaterial::MlDsa {
                params,
                public: hex(&v["raw_public_key"]),
            })
            .unwrap();
            verify(alg, &public, &tbs, &sig).unwrap_or_else(|e| panic!("ML-DSA-{p} {family}: {e}"));
            assert_eq!(
                verify(alg, &public, &tbs, &flip(&sig, 100)),
                Err(CryptoError::InvalidSignature)
            );
            assert_eq!(
                verify(alg, &public, &flip(&tbs, 0), &sig),
                Err(CryptoError::InvalidSignature)
            );

            // The examples were produced with deterministic ML-DSA from seed 0^32.
            let key = generate_from_seed(KeySpec::MlDsa(params), &seed).unwrap();
            assert_eq!(key.public_key(), public);
            assert_eq!(
                sign_deterministic(alg, &key, &tbs).unwrap(),
                sig,
                "ML-DSA-{p} {family}"
            );
        }
    }
}

#[test]
fn rfc9964_jws_signing_input_matches_raw_to_be_signed() {
    // Guards the extraction script: raw_to_be_signed is the hex of the JWS signing input.
    for p in [44, 65, 87] {
        let v = load_json(&format!("rfc9964/ml-dsa-{p}-jose.json"));
        let jws = v["jws"].as_str().unwrap();
        let signing_input = &jws[..jws.rfind('.').unwrap()];
        assert_eq!(
            signing_input.as_bytes(),
            hex(&v["raw_to_be_signed"]).as_slice()
        );
        assert_eq!(
            b64(&serde_json::Value::from(
                &jws[jws.rfind('.').unwrap() + 1..]
            )),
            hex(&v["raw_signature"])
        );
    }
}
