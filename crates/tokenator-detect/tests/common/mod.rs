//! Shared helpers for the tokenator-detect integration tests.
//!
//! The encoders here are deliberately independent of the crate under test,
//! so expectations never depend on `rewrap`.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use tokenator_cbor::{EncodeMode, Item, Value, encode};
use tokenator_detect::{Candidate, Kind, Layer, MAX_LAYERS, detect, unwrap_layers};

// ------------------------------------------------------------------ fixtures

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

/// Raw bytes of `testdata/tokens/<name>`.
pub fn token(name: &str) -> Vec<u8> {
    let p = testdata().join("tokens").join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// Raw bytes of `testdata/keys/<name>`.
pub fn key(name: &str) -> Vec<u8> {
    let p = testdata().join("keys").join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// A text fixture with its final newline removed.
pub fn token_text(name: &str) -> String {
    let s = String::from_utf8(token(name)).unwrap();
    s.strip_suffix('\n').unwrap_or(&s).to_owned()
}

/// A text key fixture with its final newline removed.
pub fn key_text(name: &str) -> String {
    let s = String::from_utf8(key(name)).unwrap();
    s.strip_suffix('\n').unwrap_or(&s).to_owned()
}

/// Compact JWS/JWT fixtures (one token per file).
pub const JWT: &str = "rfc7519-s3.1-jwt-hs256.txt";
pub const SD_JWT: &str = "rfc9901-s5.1-sd-jwt.txt";
pub const SD_JWT_KB: &str = "rfc9901-s5.2-sd-jwt-kb.txt";
pub const CWT_TAG18: &str = "rfc8392-a3-signed-cwt.cbor";
pub const SD_CWT: &str = "sd-cwt-08-issuer-sd-cwt.cbor";
pub const SD_KBT: &str = "sd-cwt-08-sd-kbt.cbor";

// ------------------------------------------------------------------ encoders

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64(data: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.len();
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let v = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= n {
                out.push(alphabet[(v >> (18 - 6 * i) & 63) as usize] as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// Classic base64 with padding.
pub fn b64std(data: &[u8]) -> String {
    b64(data, STD, true)
}

/// Classic base64 without padding.
pub fn b64std_nopad(data: &[u8]) -> String {
    b64(data, STD, false)
}

/// base64url without padding.
pub fn b64url(data: &[u8]) -> String {
    b64(data, URL, false)
}

/// base64url with padding.
pub fn b64url_pad(data: &[u8]) -> String {
    b64(data, URL, true)
}

/// Splits `s` into `\n`-joined lines of `width` characters.
pub fn wrap(s: &str, width: usize) -> String {
    s.as_bytes()
        .chunks(width)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Upper-case hex.
pub fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Hex with `sep` between bytes and `per_line` bytes per `\n`-separated line.
pub fn hex_layout(bytes: &[u8], upper: bool, sep: Option<char>, per_line: Option<usize>) -> String {
    let byte = |b: &u8| {
        if upper {
            format!("{b:02X}")
        } else {
            format!("{b:02x}")
        }
    };
    let line = |c: &[u8]| {
        c.iter()
            .map(byte)
            .collect::<Vec<_>>()
            .join(&sep.map(String::from).unwrap_or_default())
    };
    match per_line {
        Some(n) => bytes.chunks(n).map(line).collect::<Vec<_>>().join("\n"),
        None => line(bytes),
    }
}

/// Parses hex, ignoring whitespace.
pub fn h(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(digits.len().is_multiple_of(2), "odd hex length: {s:?}");
    digits
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

/// Percent-encodes every byte outside the RFC 3986 unreserved set,
/// upper-case hex (the canonical form `rewrap` produces).
pub fn pct(data: &[u8]) -> String {
    let mut out = String::new();
    for &b in data {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Percent-encodes every byte, unreserved or not.
pub fn pct_all(data: &[u8]) -> String {
    data.iter().map(|b| format!("%{b:02X}")).collect()
}

// ------------------------------------------------------------------ CBOR

pub fn cbor(item: &Item) -> Vec<u8> {
    encode(item, EncodeMode::Preserve).unwrap()
}

pub fn int(n: i64) -> Item<'static> {
    Item::int(n)
}

pub fn bstr(b: &[u8]) -> Item<'static> {
    Item::bytes(b.to_vec())
}

pub fn tstr(s: &str) -> Item<'static> {
    Item::text(s.to_owned())
}

pub fn null() -> Item<'static> {
    Item::new(Value::Null)
}

pub fn map(entries: Vec<(Item<'static>, Item<'static>)>) -> Item<'static> {
    Item::map(entries)
}

pub fn arr(items: Vec<Item<'static>>) -> Item<'static> {
    Item::array(items)
}

/// A bstr-wrapped, encoded map (a COSE protected header or CWT payload).
pub fn wrapped(entries: Vec<(Item<'static>, Item<'static>)>) -> Item<'static> {
    if entries.is_empty() {
        return bstr(&[]);
    }
    bstr(&cbor(&map(entries)))
}

/// A simple RFC 8392-style claims map.
pub fn claims() -> Vec<(Item<'static>, Item<'static>)> {
    vec![
        (int(1), tstr("https://issuer.example")),
        (int(2), tstr("https://holder.example")),
        (int(6), int(1_725_244_200)),
    ]
}

/// An untagged COSE_Sign1 `[protected, unprotected, payload, signature]`.
pub fn sign1(
    protected: Vec<(Item<'static>, Item<'static>)>,
    unprotected: Vec<(Item<'static>, Item<'static>)>,
    payload: Item<'static>,
) -> Item<'static> {
    arr(vec![
        wrapped(protected),
        map(unprotected),
        payload,
        bstr(&[0x5a; 64]),
    ])
}

/// `18(sign1)` encoded.
pub fn sign1_tagged(item: Item<'static>) -> Vec<u8> {
    cbor(&Item::tag(18, item))
}

/// The untagged COSE_Sign1 inside the RFC 8392 A.3 example.
pub fn cwt_untagged() -> Vec<u8> {
    token("derived-rfc8392-a3-untagged.cbor")
}

// ------------------------------------------------------------------ lookups

/// Runs `detect`, checks the invariants, and returns the candidates.
pub fn run(input: &[u8]) -> Vec<Candidate> {
    let cands = detect(input);
    check_invariants(input, &cands);
    cands
}

/// The top candidate, failing if there is none.
pub fn top(input: &[u8]) -> Candidate {
    let cands = run(input);
    assert!(
        !cands.is_empty(),
        "no candidates for {:?}",
        String::from_utf8_lossy(&input[..input.len().min(80)])
    );
    cands[0].clone()
}

/// The first (highest ranked) candidate of `kind`.
pub fn find<'a>(cands: &'a [Candidate], kind: &Kind) -> Option<&'a Candidate> {
    cands.iter().find(|c| &c.kind == kind)
}

/// The first candidate of `kind` whose layers equal `layers`.
pub fn find_with<'a>(
    cands: &'a [Candidate],
    kind: &Kind,
    layers: &[Layer],
) -> Option<&'a Candidate> {
    cands.iter().find(|c| &c.kind == kind && c.layers == layers)
}

/// Asserts that a candidate of `kind` exists and returns it.
pub fn expect_kind<'a>(cands: &'a [Candidate], kind: &Kind) -> &'a Candidate {
    find(cands, kind).unwrap_or_else(|| panic!("no {kind:?} candidate in {}", summary(cands)))
}

/// Index of the first candidate of `kind`.
pub fn rank(cands: &[Candidate], kind: &Kind) -> Option<usize> {
    cands.iter().position(|c| &c.kind == kind)
}

/// Asserts the first candidate of `a` ranks strictly above every candidate of
/// `b` (with strictly higher confidence), if any candidate of `b` exists.
pub fn assert_outranks(cands: &[Candidate], a: &Kind, b: &Kind) {
    let ca = expect_kind(cands, a);
    for cb in cands.iter().filter(|c| &c.kind == b) {
        assert!(
            ca.confidence > cb.confidence,
            "{a:?} ({}) should outrank {b:?} ({}) in {}",
            ca.confidence,
            cb.confidence,
            summary(cands)
        );
    }
}

/// Every kind present, in rank order.
pub fn kinds(cands: &[Candidate]) -> Vec<Kind> {
    cands.iter().map(|c| c.kind.clone()).collect()
}

/// A one-line description of candidates for assertion messages.
pub fn summary(cands: &[Candidate]) -> String {
    cands
        .iter()
        .map(|c| format!("{:?}@{} {:?}", c.kind, c.confidence, c.layers))
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Layers that only select a sub-slice of their input.
pub fn is_positional(layer: &Layer) -> bool {
    matches!(
        layer,
        Layer::Trim { .. }
            | Layer::Quotes { .. }
            | Layer::AuthorizationHeader { .. }
            | Layer::BearerPrefix { .. }
            | Layer::JsonField { .. }
            | Layer::CborTag(_)
    )
}

/// The invariants every `detect` result must satisfy.
pub fn check_invariants(input: &[u8], cands: &[Candidate]) {
    for w in cands.windows(2) {
        assert!(
            w[0].confidence >= w[1].confidence,
            "not sorted by confidence: {}",
            summary(cands)
        );
    }
    for c in cands {
        assert!(c.confidence <= 100, "confidence > 100: {c:?}");
        assert!(c.layers.len() <= MAX_LAYERS, "too many layers: {c:?}");
        assert!(
            c.payload_range.start <= c.payload_range.end && c.payload_range.end <= input.len(),
            "payload_range {:?} outside input of {} bytes",
            c.payload_range,
            input.len()
        );
        let payload = unwrap_layers(input, &c.layers)
            .unwrap_or_else(|e| panic!("unwrap_layers failed for {c:?}: {e}"));
        let escaped_json = c
            .layers
            .iter()
            .any(|l| matches!(l, Layer::JsonField { .. }))
            && input[c.payload_range.clone()].contains(&b'\\');
        if c.layers.iter().all(is_positional) && !escaped_json {
            assert_eq!(
                payload,
                &input[c.payload_range.clone()],
                "positional layers but payload != input[payload_range] for {c:?}"
            );
        }
    }
    assert_eq!(
        cands,
        detect(input).as_slice(),
        "detect is not deterministic"
    );
}

/// The range of `needle` within `haystack` (first occurrence).
pub fn range_of(haystack: &[u8], needle: &[u8]) -> std::ops::Range<usize> {
    let start = haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap_or_else(|| panic!("needle not found"));
    start..start + needle.len()
}

/// `Layer::Trim` shorthand.
pub fn trim(leading: &str, trailing: &str) -> Layer {
    Layer::Trim {
        leading: leading.to_owned(),
        trailing: trailing.to_owned(),
    }
}

/// `Layer::JsonField` with object keys only.
pub fn field(keys: &[&str]) -> Layer {
    Layer::JsonField {
        path: keys
            .iter()
            .map(|k| tokenator_detect::PathSegment::Key((*k).to_owned()))
            .collect(),
    }
}
