//! Shared helpers for the tokenator-jose integration tests. Oracles here
//! (base64url, hashing, JSON comparison) are independent of the crate.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use base64ct::{Base64UrlUnpadded, Encoding};
use rand_chacha::ChaCha20Rng;
use tokenator_crypto::rand_core::SeedableRng;
use tokenator_crypto::{Alg, HashAlg, KeySpec, digest};
use tokenator_json::{Node, PrintStyle, Value};
use tokenator_keys::{Jwk, Key, Kid, Role, from_jwk, generate, import};

pub const RFC9901_ISSUER_JWK: &str = r#"{"kty":"EC","crv":"P-256","x":"b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ","y":"Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"}"#;
/// The holder key in the `cnf` of the RFC 9901 examples (public only).
pub const RFC9901_HOLDER_JWK: &str = r#"{"kty": "EC", "crv": "P-256", "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc", "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"}"#;
/// `iat` of every KB-JWT in RFC 9901.
pub const RFC9901_KB_IAT: i64 = 1748537244;
pub const RFC9901_AUD: &str = "https://verifier.example.org";
pub const RFC9901_NONCE: &str = "1234567890";

pub fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

/// A fixture from `testdata/tokens/`, exactly as stored.
pub fn raw(name: &str) -> String {
    std::fs::read_to_string(testdata().join("tokens").join(name))
        .unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// A token fixture without its trailing newline.
pub fn token(name: &str) -> String {
    raw(name).trim_end().to_owned()
}

pub fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

pub fn b64d(s: &str) -> Vec<u8> {
    Base64UrlUnpadded::decode_vec(s).unwrap_or_else(|e| panic!("{s}: {e}"))
}

pub fn b64e(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

/// Base64url digest of the ASCII text (the RFC 9901 digest rule).
pub fn digest_b64(h: HashAlg, s: &str) -> String {
    b64e(&digest(h, s.as_bytes()))
}

pub fn sha256_b64(s: &str) -> String {
    digest_b64(HashAlg::Sha256, s)
}

pub fn json(s: &str) -> Node<'_> {
    tokenator_json::parse(s.as_bytes()).unwrap_or_else(|e| panic!("{e}: {s}"))
}

pub fn compact(n: &Node<'_>) -> String {
    tokenator_json::print(n, PrintStyle::Compact)
}

/// Structural equality that also requires the same member order (number
/// lexemes compared verbatim, strings decoded).
pub fn same_json(a: &Node<'_>, b: &Node<'_>) -> bool {
    match (a.value(), b.value()) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Number(x), Value::Number(y)) => x == y,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same_json(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .zip(y)
                    .all(|(p, q)| p.key() == q.key() && same_json(p.value(), q.value()))
        }
        _ => false,
    }
}

#[track_caller]
pub fn assert_json_eq(actual: &Node<'_>, expected: &Node<'_>) {
    assert!(
        same_json(actual, expected),
        "JSON differs\n  actual:   {}\n  expected: {}",
        compact(actual),
        compact(expected)
    );
}

#[track_caller]
pub fn assert_json_text(actual: &Node<'_>, expected: &str) {
    assert_json_eq(actual, &json(expected));
}

pub fn str_of<'n>(n: &'n Node<'_>, pointer: &str) -> &'n str {
    match n.pointer(pointer).map(Node::value) {
        Some(Value::String(s)) => s,
        other => panic!("{pointer}: {other:?}"),
    }
}

pub fn jwk_key(json: &str) -> Key {
    from_jwk(&Jwk::parse(json.as_bytes()).unwrap()).unwrap()
}

pub fn rfc9901_issuer() -> Key {
    jwk_key(RFC9901_ISSUER_JWK)
}

pub fn rfc9901_holder() -> Key {
    jwk_key(RFC9901_HOLDER_JWK)
}

/// One entry of `testdata/rfc/rfc7515-jws.json`.
pub struct Rfc7515Vector {
    pub alg: String,
    pub key: Key,
    pub signing_input: String,
    pub signature: String,
}

pub fn rfc7515_vector(section: &str) -> Rfc7515Vector {
    let text = std::fs::read_to_string(testdata().join("rfc/rfc7515-jws.json")).unwrap();
    let root = json(&text);
    let v = root
        .get("vectors")
        .and_then(Node::elements)
        .unwrap()
        .iter()
        .find(|v| str_of(v, "/section") == section)
        .unwrap_or_else(|| panic!("no vector {section}"));
    Rfc7515Vector {
        alg: str_of(v, "/alg").to_owned(),
        key: from_jwk(&Jwk::from_node(v.get("jwk").unwrap()).unwrap()).unwrap(),
        signing_input: str_of(v, "/signing_input").to_owned(),
        signature: str_of(v, "/signature").to_owned(),
    }
}

fn pem_key(name: &str) -> Key {
    let pem = std::fs::read(testdata().join("keys/openssl").join(name)).unwrap();
    import(&pem, None).unwrap().remove(0)
}

/// A private issuer key for `alg`: seeded generation, except RSA (slow to
/// generate in debug builds), which comes from the OpenSSL fixtures.
pub fn issuer_key(alg: Alg) -> Key {
    key_with_seed(alg, 1, "rsa2048-pkcs8.pem", Role::Issuer)
}

/// A private holder key for `alg`, different from [`issuer_key`].
pub fn holder_key(alg: Alg) -> Key {
    key_with_seed(alg, 2, "rsa3072-pkcs8.pem", Role::Holder)
}

fn key_with_seed(alg: Alg, seed: u8, rsa: &str, role: Role) -> Key {
    let spec = KeySpec::for_alg(alg);
    let mut key = match spec {
        KeySpec::Rsa { .. } => pem_key(rsa),
        _ => generate(spec, Some(role), Some(&[seed; 32]), &mut rng(0)).unwrap(),
    };
    key.role = Some(role);
    key
}

pub fn with_kid(mut key: Key, kid: &str) -> Key {
    key.kid = Some(Kid::Text(kid.to_owned()));
    key
}

/// The public JWK text of a key.
pub fn public_jwk(key: &Key) -> Jwk {
    tokenator_keys::to_jwk(key, tokenator_keys::Visibility::Public).unwrap()
}

/// `(section, claim label, digest, disclosure)` rows of
/// `rfc9901-disclosures.json`.
pub fn rfc9901_disclosures() -> Vec<(String, String, String, String)> {
    let text = raw("rfc9901-disclosures.json");
    let root = json(&text);
    root.elements()
        .unwrap()
        .iter()
        .map(|e| {
            (
                str_of(e, "/section").to_owned(),
                str_of(e, "/claim").to_owned(),
                str_of(e, "/digest").to_owned(),
                str_of(e, "/disclosure").to_owned(),
            )
        })
        .collect()
}

/// The disclosure texts of one section, in RFC order.
pub fn section_disclosures(section: &str) -> Vec<String> {
    rfc9901_disclosures()
        .into_iter()
        .filter(|r| r.0 == section)
        .map(|r| r.3)
        .collect()
}

/// Splits a compact SD-JWT with plain string operations (an oracle):
/// `(issuer JWT, disclosures, KB-JWT or "")`.
pub fn split_sd(t: &str) -> (&str, Vec<&str>, &str) {
    let parts: Vec<&str> = t.split('~').collect();
    let (jwt, rest) = parts.split_first().unwrap();
    let (kb, discs) = rest.split_last().unwrap();
    (jwt, discs.to_vec(), kb)
}

/// The three segments of a compact JWS.
pub fn segments(jwt: &str) -> [&str; 3] {
    let v: Vec<&str> = jwt.split('.').collect();
    [v[0], v[1], v[2]]
}

/// Decoded JSON of a base64url segment, as owned text.
pub fn segment_json(seg: &str) -> String {
    String::from_utf8(b64d(seg)).unwrap()
}
