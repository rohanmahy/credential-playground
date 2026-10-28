//! Shared helpers for the tokenator-crypto integration tests.
#![allow(dead_code)]

use std::convert::Infallible;
use std::path::PathBuf;

use base64ct::{Base64UrlUnpadded, Encoding};
use rand_chacha::ChaCha20Rng;
use rand_core::{SeedableRng, TryCryptoRng, TryRng};
use serde_json::Value;
use tokenator_crypto::{
    Alg, Curve, KeySpec, MlDsaParams, PrivateKey, PrivateKeyMaterial, PublicKeyMaterial,
    RsaPrivateMaterial, generate_from_seed,
};

/// `testdata/` at the repository root.
pub fn testdata(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(rel)
}

pub fn load_json(rel: &str) -> Value {
    let path = testdata(rel);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap()
}

pub fn hex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

pub fn b64(v: &Value) -> Vec<u8> {
    Base64UrlUnpadded::decode_vec(v.as_str().unwrap()).unwrap()
}

pub fn b64_opt(v: &Value) -> Option<Vec<u8>> {
    v.as_str()
        .map(|s| Base64UrlUnpadded::decode_vec(s).unwrap())
}

/// Strip leading zeros and left-pad to `len` (Wycheproof sometimes adds a
/// sign byte to EC coordinates).
pub fn fixed_width(mut bytes: Vec<u8>, len: usize) -> Vec<u8> {
    while bytes.len() > len && bytes.first() == Some(&0) {
        bytes.remove(0);
    }
    let mut out = vec![0u8; len.saturating_sub(bytes.len())];
    out.extend(bytes);
    out
}

/// A deterministic CSPRNG for tests.
pub fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

/// An "RNG" that replays fixed bytes, then panics. Lets tests pin exactly
/// which random bytes an operation consumes (e.g. ML-DSA `rnd`).
pub struct FixedRng {
    bytes: Vec<u8>,
    pos: usize,
}

impl FixedRng {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, pos: 0 }
    }

    pub fn consumed(&self) -> usize {
        self.pos
    }
}

impl TryRng for FixedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let end = self.pos + dst.len();
        assert!(end <= self.bytes.len(), "FixedRng exhausted");
        dst.copy_from_slice(&self.bytes[self.pos..end]);
        self.pos = end;
        Ok(())
    }
}

impl TryCryptoRng for FixedRng {}

/// Private key material from a JWK-shaped JSON object (EC, OKP, RSA).
pub fn private_material_from_jwk(jwk: &Value) -> PrivateKeyMaterial {
    match jwk["kty"].as_str().unwrap() {
        "EC" => PrivateKeyMaterial::Ec {
            curve: Curve::from_jwk_name(jwk["crv"].as_str().unwrap()).unwrap(),
            d: b64(&jwk["d"]),
        },
        "OKP" => PrivateKeyMaterial::Ed25519 { d: b64(&jwk["d"]) },
        "RSA" => PrivateKeyMaterial::Rsa(RsaPrivateMaterial {
            n: b64(&jwk["n"]),
            e: b64(&jwk["e"]),
            d: b64(&jwk["d"]),
            p: b64_opt(&jwk["p"]),
            q: b64_opt(&jwk["q"]),
            dp: b64_opt(&jwk["dp"]),
            dq: b64_opt(&jwk["dq"]),
            qi: b64_opt(&jwk["qi"]),
        }),
        other => panic!("unsupported kty {other}"),
    }
}

/// Public key material from a JWK-shaped JSON object (EC, OKP, RSA).
pub fn public_material_from_jwk(jwk: &Value) -> PublicKeyMaterial {
    match jwk["kty"].as_str().unwrap() {
        "EC" => PublicKeyMaterial::Ec {
            curve: Curve::from_jwk_name(jwk["crv"].as_str().unwrap()).unwrap(),
            x: b64(&jwk["x"]),
            y: b64(&jwk["y"]),
        },
        "OKP" => PublicKeyMaterial::Ed25519 { x: b64(&jwk["x"]) },
        "RSA" => PublicKeyMaterial::Rsa {
            n: b64(&jwk["n"]),
            e: b64(&jwk["e"]),
        },
        other => panic!("unsupported kty {other}"),
    }
}

/// The 2048-bit RSA key of RFC 7515 Appendix A.2 (avoids slow RSA keygen).
pub fn rfc7515_rsa_key() -> PrivateKey {
    let v = load_json("rfc/rfc7515-jws.json");
    let jwk = &v["vectors"][0]["jwk"];
    PrivateKey::from_material(&private_material_from_jwk(jwk)).unwrap()
}

/// A private key usable with `alg`: seeded for EC/OKP/ML-DSA, the RFC 7515
/// key for RSA.
pub fn key_for(alg: Alg) -> PrivateKey {
    match KeySpec::for_alg(alg) {
        KeySpec::Rsa { .. } => rfc7515_rsa_key(),
        spec => generate_from_seed(spec, &[0x42; 32]).unwrap(),
    }
}

/// A key of a different type/curve/parameter set than `alg` requires.
pub fn wrong_key_for(alg: Alg) -> PrivateKey {
    let spec = match alg {
        Alg::ES256 => KeySpec::P384,
        Alg::ES384 => KeySpec::P521,
        Alg::ES512 => KeySpec::P256,
        Alg::EdDSA | Alg::Ed25519 => KeySpec::P256,
        Alg::RS256 | Alg::RS384 | Alg::RS512 | Alg::PS256 | Alg::PS384 | Alg::PS512 => {
            KeySpec::Ed25519
        }
        Alg::MlDsa44 => KeySpec::MlDsa(MlDsaParams::MlDsa65),
        Alg::MlDsa65 => KeySpec::MlDsa(MlDsaParams::MlDsa87),
        Alg::MlDsa87 => KeySpec::MlDsa(MlDsaParams::MlDsa44),
    };
    generate_from_seed(spec, &[0x24; 32]).unwrap()
}

/// Flip one bit of `bytes[index]`.
pub fn flip(bytes: &[u8], index: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[index] ^= 0x01;
    out
}
