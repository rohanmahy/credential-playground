//! Shared helpers for the tokenator-keys integration tests.
#![allow(dead_code)]

use std::path::PathBuf;

use base64ct::{Base64UrlUnpadded, Encoding};
use rand_chacha::ChaCha20Rng;
use serde_json::Value;
use tokenator_crypto::rand_core::SeedableRng;
use tokenator_crypto::{
    Curve, KeySpec, MlDsaParams, PrivateKey, PrivateKeyMaterial, PublicKey, PublicKeyMaterial,
    RsaPrivateMaterial, generate_from_seed,
};
use tokenator_keys::{Key, KeyFormat, Visibility, import};

/// `testdata/` at the repository root.
pub fn testdata(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(rel)
}

/// Bytes of `testdata/keys/<rel>`.
pub fn fixture(rel: &str) -> Vec<u8> {
    let path = testdata("keys").join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// Text of `testdata/keys/<rel>`.
pub fn fixture_str(rel: &str) -> String {
    String::from_utf8(fixture(rel)).unwrap()
}

/// `testdata/keys/<rel>` parsed with serde_json (member order NOT kept).
pub fn fixture_json(rel: &str) -> Value {
    serde_json::from_slice(&fixture(rel)).unwrap()
}

/// `testdata/<rel>` parsed with serde_json.
pub fn testdata_json(rel: &str) -> Value {
    let path = testdata(rel);
    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
}

pub fn hexv(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

pub fn b64u(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

pub fn unb64u(s: &str) -> Vec<u8> {
    Base64UrlUnpadded::decode_vec(s).unwrap()
}

/// A deterministic CSPRNG for tests.
pub fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

/// Imports exactly one key.
pub fn import_one(input: &[u8], hint: Option<KeyFormat>) -> Key {
    let mut keys = import(input, hint).unwrap_or_else(|e| panic!("import failed: {e:?}"));
    assert_eq!(keys.len(), 1, "expected one key");
    keys.remove(0)
}

/// Imports exactly one key from `testdata/keys/<rel>`, detecting the format.
pub fn import_fixture(rel: &str) -> Key {
    import_one(&fixture(rel), None)
}

/// Member names of a JSON object, in order (via tokenator-json).
pub fn json_member_names(json: &[u8]) -> Vec<String> {
    let node = tokenator_json::parse(json).unwrap();
    node.members()
        .unwrap()
        .iter()
        .map(|m| m.key().to_string())
        .collect()
}

/// The labels of a CBOR map, in order, as i64 (panics on non-int labels).
pub fn cbor_int_labels(cbor: &[u8]) -> Vec<i64> {
    let item = tokenator_cbor::decode(cbor).unwrap();
    match item.value {
        tokenator_cbor::Value::Map(entries) => entries.iter().map(|(k, _)| int(&k.value)).collect(),
        other => panic!("not a map: {other:?}"),
    }
}

pub fn int(v: &tokenator_cbor::Value) -> i64 {
    match v {
        tokenator_cbor::Value::Uint(n) => i64::try_from(*n).unwrap(),
        tokenator_cbor::Value::Nint(n) => -1 - i64::try_from(*n).unwrap(),
        other => panic!("not an int: {other:?}"),
    }
}

/// The value at integer label `label` of a CBOR map.
pub fn cbor_get(cbor: &[u8], label: i64) -> Option<tokenator_cbor::Item<'static>> {
    let item = tokenator_cbor::decode(cbor).unwrap().into_owned();
    match item.value {
        tokenator_cbor::Value::Map(entries) => entries
            .into_iter()
            .find(|(k, _)| {
                matches!(
                    &k.value,
                    tokenator_cbor::Value::Uint(_) | tokenator_cbor::Value::Nint(_)
                ) && int(&k.value) == label
            })
            .map(|(_, v)| v),
        other => panic!("not a map: {other:?}"),
    }
}

pub fn cbor_bytes(item: &tokenator_cbor::Item<'_>) -> Vec<u8> {
    match &item.value {
        tokenator_cbor::Value::Bytes(b) => b.to_vec(),
        other => panic!("not a bstr: {other:?}"),
    }
}

/// Every supported key type, for cross-product tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    P256,
    P384,
    P521,
    Ed25519,
    Rsa2048,
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

pub const ALL_KINDS: [Kind; 8] = [
    Kind::P256,
    Kind::P384,
    Kind::P521,
    Kind::Ed25519,
    Kind::Rsa2048,
    Kind::MlDsa44,
    Kind::MlDsa65,
    Kind::MlDsa87,
];

impl Kind {
    /// The OpenSSL fixture stem (`testdata/keys/openssl/<stem>.json`).
    pub fn stem(self) -> &'static str {
        match self {
            Kind::P256 => "p256",
            Kind::P384 => "p384",
            Kind::P521 => "p521",
            Kind::Ed25519 => "ed25519",
            Kind::Rsa2048 => "rsa2048",
            Kind::MlDsa44 => "mldsa44",
            Kind::MlDsa65 => "mldsa65",
            Kind::MlDsa87 => "mldsa87",
        }
    }

    pub fn is_ec(self) -> bool {
        matches!(self, Kind::P256 | Kind::P384 | Kind::P521)
    }

    pub fn is_rsa(self) -> bool {
        self == Kind::Rsa2048
    }

    pub fn is_ml_dsa(self) -> bool {
        matches!(self, Kind::MlDsa44 | Kind::MlDsa65 | Kind::MlDsa87)
    }

    pub fn ml_dsa(self) -> Option<MlDsaParams> {
        match self {
            Kind::MlDsa44 => Some(MlDsaParams::MlDsa44),
            Kind::MlDsa65 => Some(MlDsaParams::MlDsa65),
            Kind::MlDsa87 => Some(MlDsaParams::MlDsa87),
            _ => None,
        }
    }
}

/// The expected private material of an OpenSSL fixture key.
pub fn fixture_private_material(kind: Kind) -> PrivateKeyMaterial {
    let j = fixture_json(&format!("openssl/{}.json", kind.stem()));
    match kind {
        Kind::P256 | Kind::P384 | Kind::P521 => PrivateKeyMaterial::Ec {
            curve: Curve::from_jwk_name(j["crv"].as_str().unwrap()).unwrap(),
            d: hexv(&j["d"]),
        },
        Kind::Ed25519 => PrivateKeyMaterial::Ed25519 { d: hexv(&j["d"]) },
        Kind::Rsa2048 => PrivateKeyMaterial::Rsa(RsaPrivateMaterial {
            n: hexv(&j["n"]),
            e: hexv(&j["e"]),
            d: hexv(&j["d"]),
            p: Some(hexv(&j["p"])),
            q: Some(hexv(&j["q"])),
            dp: Some(hexv(&j["dp"])),
            dq: Some(hexv(&j["dq"])),
            qi: Some(hexv(&j["qi"])),
        }),
        Kind::MlDsa44 | Kind::MlDsa65 | Kind::MlDsa87 => PrivateKeyMaterial::MlDsa {
            params: kind.ml_dsa().unwrap(),
            seed: Some(hexv(&j["seed"])),
            expanded: Some(hexv(&j["expanded"])),
        },
    }
}

/// The expected public material of an OpenSSL fixture key.
pub fn fixture_public_material(kind: Kind) -> PublicKeyMaterial {
    let j = fixture_json(&format!("openssl/{}.json", kind.stem()));
    match kind {
        Kind::P256 | Kind::P384 | Kind::P521 => PublicKeyMaterial::Ec {
            curve: Curve::from_jwk_name(j["crv"].as_str().unwrap()).unwrap(),
            x: hexv(&j["x"]),
            y: hexv(&j["y"]),
        },
        Kind::Ed25519 => PublicKeyMaterial::Ed25519 { x: hexv(&j["x"]) },
        Kind::Rsa2048 => PublicKeyMaterial::Rsa {
            n: hexv(&j["n"]),
            e: hexv(&j["e"]),
        },
        Kind::MlDsa44 | Kind::MlDsa65 | Kind::MlDsa87 => PublicKeyMaterial::MlDsa {
            params: kind.ml_dsa().unwrap(),
            public: hexv(&j["pub"]),
        },
    }
}

/// The OpenSSL fixture key of `kind` as a private [`Key`], built from the
/// JSON components (not from PEM), with no metadata.
pub fn fixture_key(kind: Kind) -> Key {
    let pk = PrivateKey::from_material(&fixture_private_material(kind)).unwrap();
    Key::from_private(pk)
}

/// The public half of [`fixture_key`], built from the JSON components.
pub fn fixture_public_key(kind: Kind) -> Key {
    Key::from_public(PublicKey::from_material(&fixture_public_material(kind)).unwrap())
}

/// A fast key of `kind`: seeded generation for EC/OKP/ML-DSA (via
/// tokenator-crypto directly) and the OpenSSL fixture for RSA.
pub fn sample_key(kind: Kind) -> Key {
    let spec = match kind {
        Kind::P256 => KeySpec::P256,
        Kind::P384 => KeySpec::P384,
        Kind::P521 => KeySpec::P521,
        Kind::Ed25519 => KeySpec::Ed25519,
        Kind::Rsa2048 => return fixture_key(kind),
        Kind::MlDsa44 | Kind::MlDsa65 | Kind::MlDsa87 => KeySpec::MlDsa(kind.ml_dsa().unwrap()),
    };
    Key::from_private(generate_from_seed(spec, &[0x5a; 32]).unwrap())
}

/// Every (format, visibility) pair that `kind` supports for export, with
/// the PEM encodings that apply.
pub fn formats_for(kind: Kind, visibility: Visibility) -> Vec<KeyFormat> {
    use tokenator_keys::{MlDsaPrivateForm, PemEncoding};
    let mut f = vec![
        KeyFormat::Jwk,
        KeyFormat::JwkSet,
        KeyFormat::CoseKey,
        KeyFormat::CoseKeySet,
        KeyFormat::Pem(PemEncoding::Auto),
    ];
    match visibility {
        Visibility::Public => {
            f.push(KeyFormat::Pem(PemEncoding::Spki));
            if kind.is_rsa() {
                f.push(KeyFormat::Pem(PemEncoding::Pkcs1));
            }
        }
        Visibility::Private => {
            f.push(KeyFormat::Pem(PemEncoding::Pkcs8));
            if kind.is_ec() {
                f.push(KeyFormat::Pem(PemEncoding::Sec1));
            }
            if kind.is_rsa() {
                f.push(KeyFormat::Pem(PemEncoding::Pkcs1));
            }
            if kind.is_ml_dsa() {
                f.push(KeyFormat::Pem(PemEncoding::Pkcs8MlDsa(
                    MlDsaPrivateForm::Seed,
                )));
                f.push(KeyFormat::Pem(PemEncoding::Pkcs8MlDsa(
                    MlDsaPrivateForm::Expanded,
                )));
                f.push(KeyFormat::Pem(PemEncoding::Pkcs8MlDsa(
                    MlDsaPrivateForm::Both,
                )));
            }
        }
    }
    f
}

/// Asserts that `a` and `b` hold the same key material, with a readable
/// failure message.
pub fn assert_same_material(a: &Key, b: &Key, context: &str) {
    assert!(
        a.same_material(b),
        "{context}: material differs\n  left public: {:?}\n right public: {:?}\n private: {} vs {}",
        a.public_key().to_material(),
        b.public_key().to_material(),
        a.is_private(),
        b.is_private()
    );
}
