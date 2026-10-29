//! Shared helpers for the tokenator-core integration tests.
//!
//! Expectations are computed from fixtures with tokenator-cbor,
//! tokenator-edn, tokenator-json, and serde_json, never with core itself.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use tokenator_core::{
    Bytes, Candidate, CheckItem, DocRef, Document, Engine, KeyGenRequest, KeyInfo, KeyRef, KeySeed,
    KeySpec, Kind, Node, NodeId, RawView, Status, TextRange, ValidateRequest, ValidationReport,
    ViewOptions,
};

// ---------------------------------------------------------------- constants

/// RFC 8392 A.1: iat/nbf 1443944944, exp 1444064944.
pub const RFC8392_NOW: i64 = 1_444_000_000;
/// RFC 7515 / RFC 7519 examples: exp 1300819380.
pub const RFC7515_NOW: i64 = 1_300_819_000;
/// RFC 9901: issuer iat 1683000000, exp 1883000000; KB-JWT iat 1748537244.
pub const RFC9901_NOW: i64 = 1_748_537_250;
pub const RFC9901_KB_IAT: i64 = 1_748_537_244;
pub const RFC9901_AUD: &str = "https://verifier.example.org";
pub const RFC9901_NONCE: &str = "1234567890";
/// RFC 9901 A.5 issuer key.
pub const RFC9901_ISSUER_JWK: &str = r#"{"kty":"EC","crv":"P-256","x":"b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ","y":"Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"}"#;
/// sd-cwt-08: a clock at which every example is valid.
pub const SD_NOW: i64 = 1_725_244_240;
pub const SD_AUD: &str = "https://verifier.example/app";
pub const SD_CNONCE_HEX: &str = "8c0f5f523b95bea44a9a48c649240803";
pub const SD_KBT_IAT: i64 = 1_725_244_237;
/// Far in the future, for freshly issued tokens without exp.
pub const LATER: i64 = 1_800_000_000;

pub const SD_ISSUER: &str = "sd-cwt-08-issuer-sd-cwt.cbor";
pub const SD_KBT: &str = "sd-cwt-08-sd-kbt.cbor";
pub const SD_NESTED_ISSUER: &str = "sd-cwt-08-nested-issuer-sd-cwt.cbor";
pub const SD_NESTED_KBT: &str = "sd-cwt-08-nested-sd-kbt.cbor";
pub const SD_DECOY: &str = "sd-cwt-08-decoy-sd-cwt.cbor";
pub const CWT_TAGGED: &str = "rfc8392-a3-signed-cwt.cbor";
pub const CWT_UNTAGGED: &str = "derived-rfc8392-a3-untagged.cbor";
pub const CWT_TAG61: &str = "derived-rfc8392-a3-tag61.cbor";

/// Every COSE_Sign1 fixture that opens as a credential.
pub const COSE_FIXTURES: [&str; 9] = [
    CWT_TAGGED,
    CWT_UNTAGGED,
    CWT_TAG61,
    "rfc9052-c2.1-sign1.cbor",
    SD_ISSUER,
    SD_KBT,
    SD_NESTED_ISSUER,
    SD_NESTED_KBT,
    SD_DECOY,
];

/// Every JOSE token fixture.
pub const JOSE_FIXTURES: [&str; 21] = [
    "rfc7515-a1-jws-hs256.txt",
    "rfc7515-a2-jws-rs256.txt",
    "rfc7515-a3-jws-es256.txt",
    "rfc7515-a4-jws-es512-nonjson-payload.txt",
    "rfc7515-a5-unsecured-jws.txt",
    "rfc7515-a6-jws-json-general.json",
    "rfc7515-a7-jws-json-flattened.json",
    "rfc7519-s3.1-jwt-hs256.txt",
    "rfc7519-s6.1-unsecured-jwt.txt",
    "rfc9901-a1-presentation.txt",
    "rfc9901-a2-presentation.txt",
    "rfc9901-a3-sd-jwt-kb.txt",
    "rfc9901-a3-sd-jwt.txt",
    "rfc9901-a4-sd-jwt-kb.txt",
    "rfc9901-a4-sd-jwt.txt",
    "rfc9901-s5.1-issuer-signed-jwt.txt",
    "rfc9901-s5.1-sd-jwt.txt",
    "rfc9901-s5.2-sd-jwt-kb.txt",
    "rfc9901-s8.2-sd-jwt-json-flattened.json",
    "rfc9901-s8.2-sd-jwt-kb-json-flattened.json",
    "rfc9901-s8.3-sd-jwt-kb-json-general.json",
];

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

/// Text of `testdata/tokens/<name>`, trimmed.
pub fn token_text(name: &str) -> String {
    String::from_utf8(token(name)).unwrap().trim().to_owned()
}

/// Bytes of `testdata/keys/<name>`.
pub fn key_file(name: &str) -> Vec<u8> {
    read(&format!("keys/{name}"))
}

/// A [`KeyRef`] for a key fixture.
pub fn key_ref(name: &str) -> KeyRef {
    let mut k = KeyRef::new(key_file(name));
    k.label = Some(name.to_owned());
    k
}

/// A [`KeyRef`] for a JWK text.
pub fn jwk_ref(json: &str) -> KeyRef {
    KeyRef::new(json.as_bytes().to_vec())
}

/// The JWK of an RFC 7515 Appendix A vector (`testdata/rfc/rfc7515-jws.json`).
pub fn rfc7515_key(section: &str) -> KeyRef {
    let text = std::fs::read_to_string(testdata("rfc/rfc7515-jws.json")).unwrap();
    let root: serde_json::Value = serde_json::from_str(&text).unwrap();
    let v = root["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["section"] == section)
        .unwrap_or_else(|| panic!("no vector {section}"));
    let mut k = jwk_ref(&v["jwk"].to_string());
    k.label = Some(format!("RFC 7515 {section}"));
    k
}

pub fn rfc9901_issuer() -> KeyRef {
    let mut k = jwk_ref(RFC9901_ISSUER_JWK);
    k.label = Some("RFC 9901 A.5".into());
    k
}

pub fn rfc8392_key() -> KeyRef {
    key_ref("rfc8392-a2.3-ec-p256.cosekey.cbor")
}

pub fn sd_issuer_key() -> KeyRef {
    key_ref("sd-cwt-08-c2-issuer-private.cosekey.cbor")
}

pub fn sd_holder_key() -> KeyRef {
    key_ref("sd-cwt-08-c1-holder-private.cosekey.cbor")
}

pub fn hexd(s: &str) -> Vec<u8> {
    hex::decode(s.split_whitespace().collect::<String>()).unwrap()
}

/// CBOR bytes of an EDN text (via tokenator-edn, preserving indicators).
pub fn edn(text: &str) -> Vec<u8> {
    let item = tokenator_edn::parse(text).unwrap();
    tokenator_cbor::encode(&item, tokenator_cbor::EncodeMode::Preserve).unwrap()
}

/// A 32-byte randomness seed.
pub fn seed(n: u8) -> Bytes {
    Bytes(vec![n; 32])
}

// ---------------------------------------------------------------- engine

pub fn engine() -> Engine {
    Engine::new().unwrap()
}

pub fn view() -> ViewOptions {
    ViewOptions::default()
}

/// The top candidate of `input`.
pub fn top(e: &Engine, input: &[u8]) -> Candidate {
    e.detect(input)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("nothing detected in {:?}", String::from_utf8_lossy(input)))
}

/// paste → detect → open (top candidate, default view).
pub fn open(e: &Engine, input: &[u8]) -> Document {
    let c = top(e, input);
    e.open(input, &c, &view()).unwrap()
}

/// Opens a token fixture.
pub fn open_token(e: &Engine, name: &str) -> Document {
    open(e, &token(name))
}

/// Opens the first candidate whose kind satisfies `pred`.
pub fn open_as(e: &Engine, input: &[u8], pred: impl Fn(&Kind) -> bool) -> Document {
    let cands = e.detect(input);
    let c = cands
        .iter()
        .find(|c| pred(&c.kind))
        .unwrap_or_else(|| panic!("no matching candidate in {cands:?}"));
    e.open(input, c, &view()).unwrap()
}

/// Renders `kind`/`bytes` with default options.
pub fn render(e: &Engine, kind: Kind, bytes: &[u8]) -> Document {
    e.render(&tokenator_core::RenderRequest {
        doc: DocRef::new(kind, bytes.to_vec()),
        layers: Vec::new(),
        view: view(),
    })
    .unwrap()
}

pub fn validate(e: &Engine, doc: &Document, keys: Vec<KeyRef>, now: i64) -> ValidationReport {
    let mut req = ValidateRequest::new(DocRef::from(doc), now);
    req.keys = keys;
    e.validate(&req).unwrap()
}

/// A seeded key.
pub fn gen_key(e: &Engine, spec: KeySpec, n: u8) -> KeyInfo {
    e.key_generate(&KeyGenRequest {
        spec,
        role: None,
        seed: KeySeed::Seed { bytes: seed(n) },
        kid: None,
    })
    .unwrap()
}

// ---------------------------------------------------------------- reports

pub fn ids_of(report: &ValidationReport) -> Vec<(&str, Status)> {
    report
        .items
        .iter()
        .map(|i| (i.id.as_str(), i.status))
        .collect()
}

/// The first item with `id`.
pub fn item<'r>(report: &'r ValidationReport, id: &str) -> &'r CheckItem {
    report
        .items
        .iter()
        .find(|i| i.id == id)
        .unwrap_or_else(|| panic!("no item {id} in {:?}", ids_of(report)))
}

/// All items with `id`.
pub fn items<'r>(report: &'r ValidationReport, id: &str) -> Vec<&'r CheckItem> {
    report.items.iter().filter(|i| i.id == id).collect()
}

pub fn status(report: &ValidationReport, id: &str) -> Status {
    item(report, id).status
}

pub fn has(report: &ValidationReport, id: &str) -> bool {
    report.items.iter().any(|i| i.id == id)
}

pub fn assert_status(report: &ValidationReport, id: &str, expected: Status) {
    let got = status(report, id);
    assert_eq!(
        got,
        expected,
        "{id}: {:?} (all: {:?})",
        item(report, id).message,
        ids_of(report)
    );
}

/// No item fails.
pub fn assert_no_fail(report: &ValidationReport) {
    let fails: Vec<_> = report
        .items
        .iter()
        .filter(|i| i.status == Status::Fail)
        .map(|i| (&i.id, &i.message))
        .collect();
    assert!(fails.is_empty(), "failing items: {fails:?}");
}

// ---------------------------------------------------------------- trees

/// Every node in pre-order, key nodes right before their value node.
pub fn walk(root: &Node) -> Vec<&Node> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if let Some(k) = &n.key {
            out.push(k.as_ref());
        }
        out.push(n);
        for c in n.children.iter().rev() {
            stack.push(c);
        }
    }
    out
}

/// All node ids in pre-order.
pub fn ids(doc: &Document) -> Vec<String> {
    walk(&doc.tree).iter().map(|n| n.id.0.clone()).collect()
}

/// The node with `id`.
pub fn find<'d>(doc: &'d Document, id: &str) -> &'d Node {
    walk(&doc.tree)
        .into_iter()
        .find(|n| n.id.as_str() == id)
        .unwrap_or_else(|| panic!("no node {id:?}; ids: {:?}", ids(doc)))
}

pub fn has_node(doc: &Document, id: &str) -> bool {
    walk(&doc.tree).iter().any(|n| n.id.as_str() == id)
}

pub fn node_id(s: &str) -> NodeId {
    NodeId(s.to_owned())
}

/// `text` at a UTF-16 range.
pub fn slice16(text: &str, r: TextRange) -> String {
    let units: Vec<u16> = text.encode_utf16().collect();
    String::from_utf16(&units[r.start as usize..r.end as usize]).unwrap()
}

/// The main pane text of a node.
pub fn main_text(doc: &Document, id: &str) -> String {
    let n = find(doc, id);
    slice16(
        &doc.main.text,
        n.main.unwrap_or_else(|| panic!("{id} has no main range")),
    )
}

/// The raw buffer a document's hex rows index.
pub fn hex_bytes(doc: &Document) -> &[u8] {
    match &doc.raw {
        RawView::Hex { bytes, .. } => bytes,
        other => panic!("not a hex view: {other:?}"),
    }
}

/// The raw bytes of a node in a hex view.
pub fn raw_bytes<'d>(doc: &'d Document, id: &str) -> &'d [u8] {
    let n = find(doc, id);
    let r = n.raw.unwrap_or_else(|| panic!("{id} has no raw range"));
    &hex_bytes(doc)[r.start as usize..r.end as usize]
}

/// Serialized JSON of any DTO.
pub fn json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap()
}

/// The main pane text with node `id`'s main range replaced by `new`.
pub fn replace_node(doc: &Document, id: &str, new: &str) -> String {
    let r = find(doc, id)
        .main
        .unwrap_or_else(|| panic!("{id} has no main range"));
    let units: Vec<u16> = doc.main.text.encode_utf16().collect();
    let before = String::from_utf16(&units[..r.start as usize]).unwrap();
    let after = String::from_utf16(&units[r.end as usize..]).unwrap();
    format!("{before}{new}{after}")
}

/// `parse_edit` of `text` against `doc`.
pub fn edit(e: &Engine, doc: &Document, text: String) -> tokenator_core::EditResult {
    e.parse_edit(&tokenator_core::EditRequest {
        kind: doc.kind.clone(),
        base: doc.bytes.clone(),
        text,
        view: view(),
    })
}

/// The JOSE segment texts of a document.
pub fn segment_texts(doc: &Document) -> Vec<String> {
    match &doc.raw {
        RawView::Segments { segments } => segments.iter().map(|s| s.text.clone()).collect(),
        other => panic!("not a segment view: {other:?}"),
    }
}
