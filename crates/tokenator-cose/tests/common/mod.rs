//! Shared helpers for the tokenator-cose integration tests.
//!
//! Fixture inspection here uses `tokenator-cbor` directly, never the crate
//! under test, so expectations do not depend on the implementation.
#![allow(dead_code)]

use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::OnceLock;

use rand_chacha::ChaCha20Rng;
use tokenator_cbor::{EncodeMode, Item, Value, decode, encode};
use tokenator_cose::{Alg, CborBackend};
use tokenator_crypto::KeySpec;
use tokenator_crypto::rand_core::SeedableRng;
use tokenator_keys::{Key, Kid, Visibility, generate, import, to_cwk, to_public};

pub const B: CborBackend = CborBackend;

// ---------------------------------------------------------------- files

pub fn testdata(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(rel)
}

fn read(rel: &str) -> Vec<u8> {
    let p = testdata(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
}

/// Bytes of `testdata/tokens/<name>`.
pub fn token(name: &str) -> Vec<u8> {
    read(&format!("tokens/{name}"))
}

/// Bytes of `testdata/keys/<name>`.
pub fn key_file(name: &str) -> Vec<u8> {
    read(&format!("keys/{name}"))
}

/// `testdata/rfc9964/ml-dsa-NN-cose.json`.
pub fn rfc9964(n: u32) -> serde_json::Value {
    serde_json::from_slice(&read(&format!("rfc9964/ml-dsa-{n}-cose.json"))).unwrap()
}

pub fn h(s: &str) -> Vec<u8> {
    hex::decode(s.split_whitespace().collect::<String>()).unwrap()
}

pub fn hexs(v: &serde_json::Value) -> Vec<u8> {
    h(v.as_str().unwrap())
}

// Fixture names.
pub const RFC8392_A1: &str = "rfc8392-a1-claims.cbor";
pub const RFC8392_A3: &str = "rfc8392-a3-signed-cwt.cbor";
pub const RFC8392_A3_UNTAGGED: &str = "derived-rfc8392-a3-untagged.cbor";
pub const RFC8392_A3_TAG61: &str = "derived-rfc8392-a3-tag61.cbor";
pub const RFC8392_A4: &str = "rfc8392-a4-maced-cwt-tag61.cbor";
pub const RFC8392_A5: &str = "rfc8392-a5-encrypted-cwt.cbor";
pub const RFC8392_A7: &str = "rfc8392-a7-maced-cwt-float.cbor";
pub const RFC9052_C21: &str = "rfc9052-c2.1-sign1.cbor";
pub const SD_ISSUER: &str = "sd-cwt-08-issuer-sd-cwt.cbor";
pub const SD_KBT: &str = "sd-cwt-08-sd-kbt.cbor";
pub const SD_NESTED_ISSUER: &str = "sd-cwt-08-nested-issuer-sd-cwt.cbor";
pub const SD_NESTED_KBT: &str = "sd-cwt-08-nested-sd-kbt.cbor";
pub const SD_DECOY: &str = "sd-cwt-08-decoy-sd-cwt.cbor";

/// Every COSE_Sign1 fixture.
pub const SIGN1_FIXTURES: [&str; 9] = [
    RFC8392_A3,
    RFC8392_A3_UNTAGGED,
    RFC8392_A3_TAG61,
    RFC9052_C21,
    SD_ISSUER,
    SD_KBT,
    SD_NESTED_ISSUER,
    SD_NESTED_KBT,
    SD_DECOY,
];

/// A clock at which every sd-cwt-08 example is valid (KBT iat 1725244237,
/// SD-CWT exp 1725330600).
pub const SD_NOW: i64 = 1_725_244_240;
pub const SD_AUD: &str = "https://verifier.example/app";
pub const SD_CNONCE: &str = "8c0f5f523b95bea44a9a48c649240803";
pub const SD_KBT_IAT: i64 = 1_725_244_237;
/// The kid in the sd-cwt-08 issuer protected header.
pub const SD_ISSUER_KID: &[u8] = b"https://issuer.example/cose-key3";

// ---------------------------------------------------------------- keys

fn one_key(bytes: &[u8]) -> Key {
    let mut keys = import(bytes, None).unwrap();
    assert_eq!(keys.len(), 1);
    keys.remove(0)
}

/// RFC 8392 A.2.3 (P-256, private).
pub fn rfc8392_key() -> Key {
    one_key(&key_file("rfc8392-a2.3-ec-p256.cosekey.cbor"))
}

/// RFC 9052 C.7.1 key `11` (P-256, public).
pub fn rfc9052_key_11() -> Key {
    import(&key_file("rfc8152/c7-1-public-keyset.cbor"), None)
        .unwrap()
        .into_iter()
        .find(|k| k.kid == Some(Kid::Bytes(b"11".to_vec())))
        .unwrap()
}

/// RFC 9964 A.2 ML-DSA-NN private key (all-zero seed).
pub fn rfc9964_key(n: u32) -> Key {
    one_key(&key_file(&format!("rfc9964/ml-dsa-{n}-private.cbor")))
}

/// sd-cwt-08 C.1 holder key (P-256, private).
pub fn sd_holder() -> Key {
    one_key(&key_file("sd-cwt-08-c1-holder-private.cosekey.cbor"))
}

/// sd-cwt-08 C.2 issuer key (P-384, private, declares alg -51).
pub fn sd_issuer() -> Key {
    one_key(&key_file("sd-cwt-08-c2-issuer-private.cosekey.cbor"))
}

pub fn public(k: &Key) -> Key {
    to_public(k)
}

pub fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

/// A seeded private key for `alg`. RSA keys are generated once per test
/// binary (two of them: issuer and holder), because RSA keygen is slow.
pub fn key_for(alg: Alg, seed: u8) -> Key {
    let spec = KeySpec::for_alg(alg);
    if matches!(spec, KeySpec::Rsa { .. }) {
        static RSA: OnceLock<(Key, Key)> = OnceLock::new();
        let (a, b) = RSA.get_or_init(|| {
            let mut r = rng(0);
            (
                generate(spec, None, Some(&[1u8; 32]), &mut r).unwrap(),
                generate(spec, None, Some(&[2u8; 32]), &mut r).unwrap(),
            )
        });
        return if seed % 2 == 1 { a.clone() } else { b.clone() };
    }
    generate(spec, None, Some(&[seed; 32]), &mut rng(seed)).unwrap()
}

// ---------------------------------------------------------------- CBOR

pub fn int<'a>(n: i64) -> Item<'a> {
    Item::int(n)
}
pub fn text<'a>(s: &'a str) -> Item<'a> {
    Item::text(s)
}
pub fn bs<'a>(b: &[u8]) -> Item<'a> {
    Item::bytes(Cow::Owned(b.to_vec()))
}
pub fn arr<'a>(items: Vec<Item<'a>>) -> Item<'a> {
    Item::array(items)
}
pub fn map<'a>(entries: Vec<(Item<'a>, Item<'a>)>) -> Item<'a> {
    Item::map(entries)
}
pub fn tag<'a>(n: u64, item: Item<'a>) -> Item<'a> {
    Item::tag(n, item)
}
pub fn simple<'a>(n: u8) -> Item<'a> {
    Item::simple(n)
}
pub fn tbr<'a>(item: Item<'a>) -> Item<'a> {
    tag(58, item)
}
pub fn decoy<'a>(n: u64) -> Item<'a> {
    tag(62, Item::new(Value::Uint(n)))
}
pub fn null<'a>() -> Item<'a> {
    Item::new(Value::Null)
}
pub fn tru<'a>() -> Item<'a> {
    Item::new(Value::Bool(true))
}

pub fn enc(item: &Item) -> Vec<u8> {
    encode(item, EncodeMode::Preserve).unwrap()
}

/// Encodes a byte string head + contents (preferred head).
pub fn bstr_item(contents: &[u8]) -> Vec<u8> {
    enc(&bs(contents))
}

/// Strips tags; returns (tags, the four array elements).
pub fn elements(token: &[u8]) -> (Vec<u64>, Vec<Item<'_>>) {
    let mut item = decode(token).unwrap();
    let mut tags = Vec::new();
    loop {
        match item.value {
            Value::Tag(t, inner) => {
                tags.push(t);
                item = *inner;
            }
            Value::Array(a) => return (tags, a),
            other => panic!("not a COSE_Sign1: {other:?}"),
        }
    }
}

pub fn bstr_of<'a>(item: &Item<'a>) -> Vec<u8> {
    match &item.value {
        Value::Bytes(b) => b.to_vec(),
        other => panic!("not bytes: {other:?}"),
    }
}

/// Protected header contents of a COSE_Sign1.
pub fn protected_of(token: &[u8]) -> Vec<u8> {
    bstr_of(&elements(token).1[0])
}

/// Payload contents of a COSE_Sign1.
pub fn payload_of(token: &[u8]) -> Vec<u8> {
    bstr_of(&elements(token).1[2])
}

/// Signature of a COSE_Sign1.
pub fn signature_of(token: &[u8]) -> Vec<u8> {
    bstr_of(&elements(token).1[3])
}

/// Encoded unprotected header of a COSE_Sign1.
pub fn unprotected_of(token: &[u8]) -> Vec<u8> {
    enc(&elements(token).1[1])
}

fn map_get<'i, 'a>(m: &'i Item<'a>, key: i64) -> Option<&'i Item<'a>> {
    let Value::Map(entries) = &m.value else {
        return None;
    };
    entries
        .iter()
        .find(|(k, _)| enc(k) == enc(&Item::int(key)))
        .map(|(_, v)| v)
}

/// The `kcwt` COSE_Sign1 inside an SD-KBT, encoded (tag 18 included).
pub fn kcwt_of(kbt: &[u8]) -> Vec<u8> {
    let prot = protected_of(kbt);
    let hdr = decode(&prot).unwrap();
    enc(map_get(&hdr, 13).expect("kcwt"))
}

/// The `sd_claims` bstr contents of an SD-CWT, in order.
pub fn disclosures_of(sd_cwt: &[u8]) -> Vec<Vec<u8>> {
    let (_, els) = elements(sd_cwt);
    match map_get(&els[1], 17) {
        None => Vec::new(),
        Some(Item {
            value: Value::Array(a),
            ..
        }) => a.iter().map(bstr_of).collect(),
        Some(other) => panic!("sd_claims not an array: {other:?}"),
    }
}

/// The salt (first element) of each disclosure, in order.
pub fn salts_of(sd_cwt: &[u8]) -> Vec<Vec<u8>> {
    disclosures_of(sd_cwt)
        .iter()
        .map(|d| match decode(d).unwrap().value {
            Value::Array(a) => bstr_of(&a[0]),
            other => panic!("disclosure not an array: {other:?}"),
        })
        .collect()
}

pub fn sha256(b: &[u8]) -> Vec<u8> {
    tokenator_crypto::digest(tokenator_crypto::HashAlg::Sha256, b)
}

// ---------------------------------------------------------------- sd-cwt-08 claims

pub const HOLDER_X: &str = "8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d";
pub const HOLDER_Y: &str = "4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343";

/// `{1: {1: 2, -1: 1, -2: x, -3: y}}`, the cnf of every sd-cwt-08 example.
pub fn holder_cnf<'a>() -> Item<'a> {
    map(vec![(
        int(1),
        map(vec![
            (int(1), int(2)),
            (int(-1), int(1)),
            (int(-2), bs(&h(HOLDER_X))),
            (int(-3), bs(&h(HOLDER_Y))),
        ]),
    )])
}

/// `{8: {1: COSE_Key(public key)}}` as a cnf value for `key`.
pub fn cnf_for<'a>(key: &Key) -> Item<'a> {
    let cwk = to_cwk(key, Visibility::Public).unwrap();
    map(vec![(int(1), cwk.item().clone())])
}

/// iss, sub, exp, nbf, iat, cnf of the sd-cwt-08 examples.
pub fn sd_standard_claims<'a>() -> Vec<(Item<'a>, Item<'a>)> {
    vec![
        (int(1), text("https://issuer.example")),
        (int(2), text("https://holder.example")),
        (int(4), int(1_725_330_600)),
        (int(5), int(1_725_243_900)),
        (int(6), int(1_725_244_200)),
        (int(8), holder_cnf()),
    ]
}

/// The pre-issuance claims behind `sd-cwt-08-issuer-sd-cwt.cbor` (Figure 4
/// with the redaction requests of Figure 21 and the region/postal code).
///
/// ```text
/// { 1: "https://issuer.example", 2: ..., 4: ..., 5: ..., 6: ..., 8: {...},
///   500: true,
///   58(501): "ABCD-123456",
///   502: [58(1549560720), 58(1612560720), 1674004740],
///   503: {"country": "us", 58("region"): "ca", 58("postal_code"): "94188"} }
/// ```
pub fn issuer_preissuance<'a>() -> Item<'a> {
    let mut m = sd_standard_claims();
    m.push((int(500), tru()));
    m.push((tbr(int(501)), text("ABCD-123456")));
    m.push((
        int(502),
        arr(vec![
            tbr(int(1_549_560_720)),
            tbr(int(1_612_560_720)),
            int(1_674_004_740),
        ]),
    ));
    m.push((
        int(503),
        map(vec![
            (text("country"), text("us")),
            (tbr(text("region")), text("ca")),
            (tbr(text("postal_code")), text("94188")),
        ]),
    ));
    map(m)
}

fn nested_record<'a>(date: i64, license: &'a str, region: &'a str, postcode: &'a str) -> Item<'a> {
    map(vec![
        (int(500), tru()),
        (int(502), int(date)),
        (tbr(int(501)), text(license)),
        (
            tbr(int(503)),
            map(vec![
                (int(1), text("us")),
                (tbr(int(2)), text(region)),
                (tbr(int(3)), text(postcode)),
            ]),
        ),
    ])
}

/// The pre-issuance claims behind `sd-cwt-08-nested-issuer-sd-cwt.cbor`
/// (Figure 27 with every record, license, location, region, and postcode
/// marked to be redacted).
pub fn nested_preissuance<'a>() -> Item<'a> {
    let mut m = sd_standard_claims();
    m.push((
        int(504),
        arr(vec![
            tbr(nested_record(1_549_560_720, "DCBA-101777", "co", "80302")),
            tbr(nested_record(1_612_560_720, "EFGH-789012", "nv", "89155")),
            tbr(nested_record(1_674_004_740, "ABCD-123456", "ca", "94188")),
        ]),
    ));
    map(m)
}

/// The pre-issuance claims behind `sd-cwt-08-decoy-sd-cwt.cbor` (Figure 22
/// style): `98: [58("fr"), 62(1)], 58(500): true, 62(2): null`.
pub fn decoy_preissuance<'a>() -> Item<'a> {
    let mut m = sd_standard_claims();
    m.push((int(98), arr(vec![tbr(text("fr")), decoy(1)])));
    m.push((tbr(int(500)), tru()));
    m.push((decoy(2), null()));
    map(m)
}

/// The fully disclosed claims of the issuer example, in the reconstruction
/// order of TEST-PLAN decision 3.
pub fn issuer_processed<'a>() -> Item<'a> {
    let mut m = sd_standard_claims();
    m.push((int(500), tru()));
    m.push((
        int(502),
        arr(vec![
            int(1_549_560_720),
            int(1_612_560_720),
            int(1_674_004_740),
        ]),
    ));
    m.push((
        int(503),
        map(vec![
            (text("country"), text("us")),
            (text("region"), text("ca")),
            (text("postal_code"), text("94188")),
        ]),
    ));
    m.push((int(501), text("ABCD-123456")));
    map(m)
}
