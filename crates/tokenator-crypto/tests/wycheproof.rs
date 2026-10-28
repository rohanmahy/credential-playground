//! Wycheproof verification vectors (curated subset in `testdata/wycheproof/`).
//!
//! "valid" must verify, "invalid" must fail (a public key that fails to parse
//! counts as a failure), "acceptable" may go either way.

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use serde_json::Value;
use tokenator_crypto::{
    Alg, Curve, MlDsaParams, PrivateKey, PrivateKeyMaterial, PublicKey, PublicKeyMaterial, sign,
    sign_deterministic, verify,
};

#[derive(Default)]
struct Tally {
    passed: usize,
    failures: Vec<String>,
}

impl Tally {
    fn check(&mut self, file: &str, t: &Value, verified: bool) {
        let ok = match t["result"].as_str().unwrap() {
            "valid" => verified,
            "invalid" => !verified,
            "acceptable" => true,
            other => panic!("unknown result {other}"),
        };
        if ok {
            self.passed += 1;
        } else {
            self.failures.push(format!(
                "{file} tcId {} ({}; flags {}): expected {}, verify returned {}",
                t["tcId"], t["comment"], t["flags"], t["result"], verified
            ));
        }
    }

    fn finish(self, file: &str, expected_count: u64) {
        assert!(
            self.failures.is_empty(),
            "{} of {} vectors failed:\n{}",
            self.failures.len(),
            self.passed + self.failures.len(),
            self.failures.join("\n")
        );
        assert_eq!(
            self.passed as u64, expected_count,
            "{file}: every vector ran"
        );
    }
}

fn run(file: &str, alg: Alg, key_of: impl Fn(&Value) -> PublicKeyMaterial) {
    let v = load_json(&format!("wycheproof/{file}"));
    let mut tally = Tally::default();
    for g in v["testGroups"].as_array().unwrap() {
        let key = PublicKey::from_material(&key_of(g));
        for t in g["tests"].as_array().unwrap() {
            let verified = match &key {
                Ok(k) => verify(alg, k, &hex(&t["msg"]), &hex(&t["sig"])).is_ok(),
                Err(_) => false,
            };
            tally.check(file, t, verified);
        }
    }
    tally.finish(file, v["numberOfTests"].as_u64().unwrap());
}

fn ec_key(curve: Curve) -> impl Fn(&Value) -> PublicKeyMaterial {
    move |g| PublicKeyMaterial::Ec {
        curve,
        x: fixed_width(hex(&g["publicKey"]["wx"]), curve.field_len()),
        y: fixed_width(hex(&g["publicKey"]["wy"]), curve.field_len()),
    }
}

fn rsa_key(g: &Value) -> PublicKeyMaterial {
    PublicKeyMaterial::Rsa {
        n: hex(&g["publicKey"]["modulus"]),
        e: hex(&g["publicKey"]["publicExponent"]),
    }
}

fn ml_dsa_key(params: MlDsaParams) -> impl Fn(&Value) -> PublicKeyMaterial {
    move |g| PublicKeyMaterial::MlDsa {
        params,
        public: hex(&g["publicKey"]),
    }
}

#[test]
fn ecdsa_p256_sha256_p1363() {
    run(
        "ecdsa_secp256r1_sha256_p1363_test.json",
        Alg::ES256,
        ec_key(Curve::P256),
    );
}

#[test]
fn ecdsa_p384_sha384_p1363() {
    run(
        "ecdsa_secp384r1_sha384_p1363_test.json",
        Alg::ES384,
        ec_key(Curve::P384),
    );
}

#[test]
fn ecdsa_p521_sha512_p1363() {
    run(
        "ecdsa_secp521r1_sha512_p1363_test.json",
        Alg::ES512,
        ec_key(Curve::P521),
    );
}

#[test]
fn ed25519() {
    for alg in [Alg::Ed25519, Alg::EdDSA] {
        run("ed25519_test.json", alg, |g| PublicKeyMaterial::Ed25519 {
            x: hex(&g["publicKey"]["pk"]),
        });
    }
}

#[test]
fn rsa_pkcs1_2048_sha256() {
    run("rsa_signature_2048_sha256_test.json", Alg::RS256, rsa_key);
}

#[test]
fn rsa_pkcs1_3072_sha384() {
    run("rsa_signature_3072_sha384_test.json", Alg::RS384, rsa_key);
}

#[test]
fn rsa_pkcs1_4096_sha512() {
    run("rsa_signature_4096_sha512_test.json", Alg::RS512, rsa_key);
}

#[test]
fn rsa_pss_2048_sha256_salt32() {
    run("rsa_pss_2048_sha256_mgf1_32_test.json", Alg::PS256, rsa_key);
}

#[test]
fn rsa_pss_2048_sha384_salt48() {
    run("rsa_pss_2048_sha384_mgf1_48_test.json", Alg::PS384, rsa_key);
}

#[test]
fn rsa_pss_4096_sha512_salt64() {
    run("rsa_pss_4096_sha512_mgf1_64_test.json", Alg::PS512, rsa_key);
}

#[test]
fn ml_dsa_44_verify() {
    run(
        "mldsa_44_verify_test.json",
        Alg::MlDsa44,
        ml_dsa_key(MlDsaParams::MlDsa44),
    );
}

#[test]
fn ml_dsa_65_verify() {
    run(
        "mldsa_65_verify_test.json",
        Alg::MlDsa65,
        ml_dsa_key(MlDsaParams::MlDsa65),
    );
}

#[test]
fn ml_dsa_87_verify() {
    run(
        "mldsa_87_verify_test.json",
        Alg::MlDsa87,
        ml_dsa_key(MlDsaParams::MlDsa87),
    );
}

/// Seeded keygen + deterministic signing must reproduce the vector exactly;
/// the "Randomized" vector checks that `sign` uses the next 32 RNG bytes as
/// the FIPS 204 `rnd`.
fn run_sign_seed(file: &str, alg: Alg, params: MlDsaParams) {
    let v = load_json(&format!("wycheproof/{file}"));
    let mut ran = 0u64;
    for g in v["testGroups"].as_array().unwrap() {
        let key = PrivateKey::from_material(&PrivateKeyMaterial::MlDsa {
            params,
            seed: Some(hex(&g["privateSeed"])),
            expanded: None,
        });
        for t in g["tests"].as_array().unwrap() {
            ran += 1;
            let id = &t["tcId"];
            if t["result"] == "invalid" {
                assert!(key.is_err(), "{file} tcId {id}: invalid seed accepted");
                continue;
            }
            let key = key
                .as_ref()
                .unwrap_or_else(|e| panic!("{file} tcId {id}: {e}"));
            assert_eq!(
                key.public_key().to_material(),
                PublicKeyMaterial::MlDsa {
                    params,
                    public: hex(&g["publicKey"])
                },
                "{file} tcId {id}"
            );
            let msg = hex(&t["msg"]);
            let expected = hex(&t["sig"]);
            let got = match t.get("rnd") {
                None => sign_deterministic(alg, key, &msg).unwrap(),
                Some(rnd) => {
                    let mut fixed = FixedRng::new(hex(rnd));
                    let sig = sign(alg, key, &msg, &mut fixed).unwrap();
                    assert_eq!(fixed.consumed(), 32, "{file} tcId {id}: rnd is 32 bytes");
                    sig
                }
            };
            assert_eq!(
                hex::encode(&got),
                hex::encode(&expected),
                "{file} tcId {id} ({})",
                t["comment"]
            );
            verify(alg, &key.public_key(), &msg, &expected).unwrap();
        }
    }
    assert_eq!(ran, v["numberOfTests"].as_u64().unwrap());
}

#[test]
fn ml_dsa_44_sign_from_seed() {
    run_sign_seed(
        "mldsa_44_sign_seed_test.json",
        Alg::MlDsa44,
        MlDsaParams::MlDsa44,
    );
}

#[test]
fn ml_dsa_65_sign_from_seed() {
    run_sign_seed(
        "mldsa_65_sign_seed_test.json",
        Alg::MlDsa65,
        MlDsaParams::MlDsa65,
    );
}

#[test]
fn ml_dsa_87_sign_from_seed() {
    run_sign_seed(
        "mldsa_87_sign_seed_test.json",
        Alg::MlDsa87,
        MlDsaParams::MlDsa87,
    );
}
