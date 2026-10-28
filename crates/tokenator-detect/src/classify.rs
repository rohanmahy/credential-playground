//! Shallow, structural classification of one payload. Nothing here verifies
//! signatures or validates claims; it only checks that the shape parses.

use tokenator_cbor::{Item, Value as Cbor};
use tokenator_json::{Node, Value as Json};
use tokenator_registry::Registry;

use crate::Kind;
use crate::codec::{self, Alphabet};

/// Base confidences. Only the order matters; layers subtract a little (see
/// `detect::penalty`).
pub(crate) mod conf {
    pub(crate) const PEM: u8 = 95;
    pub(crate) const SD_JWT: u8 = 95;
    pub(crate) const SD_KBT: u8 = 96;
    pub(crate) const SD_CWT: u8 = 94;
    pub(crate) const SD_JWT_JSON: u8 = 93;
    pub(crate) const CWT: u8 = 92;
    pub(crate) const JWT: u8 = 90;
    pub(crate) const JWS_JSON: u8 = 90;
    pub(crate) const JWK: u8 = 90;
    pub(crate) const COSE_KEY: u8 = 88;
    pub(crate) const COSE_SIGN1: u8 = 85;
    pub(crate) const JWS_COMPACT: u8 = 85;
    /// Subtracted when a JOSE header lacks `alg` or a key's type is unknown.
    pub(crate) const DOUBTFUL: u8 = 20;
    pub(crate) const JSON_CLAIMS: u8 = 60;
    pub(crate) const CBOR_CLAIMS: u8 = 55;
    /// A COSE_Key reading with a text or unregistered `kty`: below the
    /// claims catch-all, since a CWT `iss` (label 1) is also text.
    pub(crate) const COSE_KEY_WEAK: u8 = 50;
    pub(crate) const EDN: u8 = 40;
}

// ------------------------------------------------------------------ JOSE compact

/// Classifies compact JWS / JWT / SD-JWT text.
pub(crate) fn jose_compact(text: &[u8]) -> Option<(Kind, u8)> {
    if !text.contains(&b'.')
        || !text
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.~".contains(c))
    {
        return None;
    }
    if !text.contains(&b'~') {
        return jws_compact(text);
    }
    let mut parts: Vec<&[u8]> = text.split(|&c| c == b'~').collect();
    let last = parts.pop()?;
    let (first, disclosures) = parts.split_first()?;
    let (jws_kind, _) = jws_compact(first)?;
    if jws_kind != Kind::Jwt {
        return None;
    }
    if !disclosures
        .iter()
        .all(|d| !d.is_empty() && codec::base64_decode(d, Some(Alphabet::Url)).is_some())
    {
        return None;
    }
    let kb = !last.is_empty();
    if kb && jws_compact(last).is_none() {
        return None;
    }
    Some((Kind::SdJwt { kb }, conf::SD_JWT))
}

/// Classifies one `header.payload.signature` JWS.
fn jws_compact(text: &[u8]) -> Option<(Kind, u8)> {
    let mut segs = text.split(|&c| c == b'.');
    let (h, p, s) = (segs.next()?, segs.next()?, segs.next()?);
    if segs.next().is_some() || h.is_empty() || h.contains(&b'~') {
        return None;
    }
    let b64 = |seg: &[u8]| {
        codec::base64_decode(seg, Some(Alphabet::Url)).filter(|_| !seg.contains(&b'='))
    };
    let header = b64(h)?;
    let header = tokenator_json::parse(&header.bytes).ok()?;
    if !matches!(header.value(), Json::Object(_)) {
        return None;
    }
    b64(s)?;
    let payload = b64(p)?;
    let has_alg = matches!(header.get("alg").map(Node::value), Some(Json::String(_)));
    let json_payload = !p.is_empty()
        && tokenator_json::parse(&payload.bytes)
            .is_ok_and(|n| matches!(n.value(), Json::Object(_)));
    let (kind, c) = if json_payload {
        (Kind::Jwt, conf::JWT)
    } else {
        (Kind::JwsCompact, conf::JWS_COMPACT)
    };
    Some((kind, if has_alg { c } else { c - conf::DOUBTFUL }))
}

// ------------------------------------------------------------------ JSON

/// Classifies a parsed JSON value. Returns the kinds and whether the
/// document is a recognized structure whose fields should not be searched
/// for tokens.
pub(crate) fn json(root: &Node<'_>) -> (Vec<(Kind, u8)>, bool) {
    let mut kinds = Vec::new();
    if !matches!(root.value(), Json::Object(_)) {
        return (kinds, false);
    }
    if let Some(k) = jws_json(root) {
        kinds.push(k);
    }
    if let Some(Json::Array(keys)) = root.get("keys").map(Node::value)
        && keys.iter().all(|k| jwk_kty(k).is_some())
    {
        let known = keys.iter().all(|k| jwk_kty(k) == Some(true));
        kinds.push((Kind::JwkSet, doubt(conf::JWK, known)));
    }
    if let Some(known) = jwk_kty(root) {
        kinds.push((Kind::Jwk, doubt(conf::JWK, known)));
    }
    let structured = !kinds.is_empty();
    kinds.push((Kind::JsonClaims, conf::JSON_CLAIMS));
    (kinds, structured)
}

fn doubt(c: u8, sure: bool) -> u8 {
    if sure { c } else { c - conf::DOUBTFUL }
}

/// `Some(registered)` if `node` is an object with a string `kty`.
fn jwk_kty(node: &Node<'_>) -> Option<bool> {
    match node.get("kty")?.value() {
        Json::String(kty) => Some(registry().is_none_or(|r| r.jwk_kty(kty).is_some())),
        _ => None,
    }
}

fn is_string(node: Option<&Node<'_>>) -> bool {
    matches!(node.map(Node::value), Some(Json::String(_)))
}

/// JWS JSON Serialization (RFC 7515 §7.2), and SD-JWT in it (RFC 9901 §8).
fn jws_json(root: &Node<'_>) -> Option<(Kind, u8)> {
    if !is_string(root.get("payload")) {
        return None;
    }
    // (disclosures present, kb_jwt present) in an unprotected header
    let sd = |sig: &Node<'_>| {
        let header = sig.get("header")?;
        matches!(header.get("disclosures")?.value(), Json::Array(_))
            .then(|| header.get("kb_jwt").is_some())
    };
    let (general, sd) = if is_string(root.get("signature")) {
        (false, sd(root))
    } else {
        let sigs = root.get("signatures")?.elements()?;
        if sigs.is_empty() || !sigs.iter().all(|s| is_string(s.get("signature"))) {
            return None;
        }
        (true, sigs.iter().find_map(sd))
    };
    Some(match sd {
        Some(kb) => (Kind::SdJwtJson { general, kb }, conf::SD_JWT_JSON),
        None => (Kind::JwsJson { general }, conf::JWS_JSON),
    })
}

// ------------------------------------------------------------------ CBOR

/// COSE header and claim labels used for classification
/// (draft-ietf-spice-sd-cwt-08).
mod label {
    pub(super) const KTY: u64 = 1;
    pub(super) const KCWT: u64 = 13;
    pub(super) const SD_CLAIMS: u64 = 17;
    pub(super) const SD_ALG: u64 = 170;
    /// `simple(59)`: a redacted claim key.
    pub(super) const REDACTED_KEY: u8 = 59;
}

/// Tags under which a 4-array may be a COSE_Sign1.
const SIGN1_TAGS: [u64; 3] = [18, 61, 55799];

/// Classifies an untagged CBOR item. `tag` is the tag directly around it,
/// if it was peeled.
pub(crate) fn cbor(item: &Item<'_>, tag: Option<u64>) -> Vec<(Kind, u8)> {
    let mut kinds = Vec::new();
    match &item.value {
        Cbor::Map(entries) => {
            if let Some(known) = cose_key(entries) {
                kinds.push((
                    Kind::CoseKey,
                    if known {
                        conf::COSE_KEY
                    } else {
                        conf::COSE_KEY_WEAK
                    },
                ));
            }
            kinds.push((Kind::CborClaims, conf::CBOR_CLAIMS));
        }
        Cbor::Array(items) => {
            if tag.is_none_or(|t| SIGN1_TAGS.contains(&t)) {
                kinds.extend(sign1(items));
            }
            if !items.is_empty() {
                let keys: Option<Vec<bool>> = items
                    .iter()
                    .map(|i| match &i.value {
                        Cbor::Map(e) => cose_key(e),
                        _ => None,
                    })
                    .collect();
                if let Some(keys) = keys {
                    let known = keys.iter().all(|k| *k);
                    kinds.push((
                        Kind::CoseKeySet,
                        if known {
                            conf::COSE_KEY
                        } else {
                            conf::COSE_KEY_WEAK
                        },
                    ));
                }
            }
        }
        _ => {}
    }
    kinds
}

fn registry() -> Option<&'static Registry> {
    Registry::shared().ok()
}

fn get<'m, 'a>(entries: &'m [(Item<'a>, Item<'a>)], key: u64) -> Option<&'m Item<'a>> {
    entries
        .iter()
        .find(|(k, _)| k.value == Cbor::Uint(key))
        .map(|(_, v)| v)
}

/// `Some(registered)` if the map has a `kty` (label 1) that is an integer or
/// text. `registered` is true for an integer `kty` in the IANA registry.
fn cose_key(entries: &[(Item<'_>, Item<'_>)]) -> Option<bool> {
    let kty = match get(entries, label::KTY)?.value {
        Cbor::Uint(n) => i64::try_from(n).ok(),
        Cbor::Nint(n) => i64::try_from(n).ok().map(|n| -1 - n),
        Cbor::Text(_) => None,
        _ => return None,
    };
    Some(kty.is_some_and(|v| registry().is_none_or(|r| r.cose_kty(v).is_some())))
}

/// Classifies `[protected, unprotected, payload, signature]`.
fn sign1(items: &[Item<'_>]) -> Option<(Kind, u8)> {
    let [protected, unprotected, payload, signature] = items else {
        return None;
    };
    let protected = match &protected.value {
        Cbor::Bytes(b) if b.is_empty() => Vec::new(),
        Cbor::Bytes(b) => match tokenator_cbor::decode(b).ok()?.value {
            Cbor::Map(m) => m,
            _ => return None,
        },
        _ => return None,
    };
    let (Cbor::Map(unprotected), Cbor::Bytes(_)) = (&unprotected.value, &signature.value) else {
        return None;
    };
    let claims = match &payload.value {
        Cbor::Bytes(b) => match tokenator_cbor::decode(b).map(|i| i.value) {
            Ok(Cbor::Map(m)) => Some(m),
            _ => None,
        },
        Cbor::Null => None,
        _ => return None,
    };
    let has = |m: &[(Item<'_>, Item<'_>)], k| get(m, k).is_some();
    Some(if has(&protected, label::KCWT) {
        (Kind::SdKbt, conf::SD_KBT)
    } else if has(&protected, label::SD_ALG)
        || has(unprotected, label::SD_CLAIMS)
        || has(&protected, label::SD_CLAIMS)
        || claims.as_deref().is_some_and(|c| has_redacted_key(c, 0))
    {
        (Kind::SdCwt, conf::SD_CWT)
    } else if claims.is_some() {
        (Kind::Cwt, conf::CWT)
    } else {
        (Kind::CoseSign1, conf::COSE_SIGN1)
    })
}

/// Whether a `simple(59)` key appears in `entries` or a map nested in it.
fn has_redacted_key(entries: &[(Item<'_>, Item<'_>)], depth: usize) -> bool {
    const MAX_DEPTH: usize = 16;
    depth < MAX_DEPTH
        && entries.iter().any(|(k, v)| {
            k.value == Cbor::Simple(label::REDACTED_KEY)
                || match &v.value {
                    Cbor::Map(m) => has_redacted_key(m, depth + 1),
                    _ => false,
                }
        })
}

// ------------------------------------------------------------------ PEM

/// The labels of one or more PEM blocks (RFC 7468) separated by whitespace.
pub(crate) fn pem(text: &str) -> Option<Vec<String>> {
    const BEGIN: &str = "-----BEGIN ";
    const DASHES: &str = "-----";
    let mut rest = text;
    let mut labels = Vec::new();
    while !rest.is_empty() {
        let after = rest.strip_prefix(BEGIN)?;
        let (label, after) = after.split_once(DASHES)?;
        if label.is_empty() || label.contains(['\n', '\r']) {
            return None;
        }
        let end = format!("{DASHES}END {label}{DASHES}");
        let body_len = after.find(DASHES)?;
        let after = after.get(body_len..)?.strip_prefix(end.as_str())?;
        labels.push(label.to_owned());
        rest = after.trim_start();
    }
    (!labels.is_empty()).then_some(labels)
}

// ------------------------------------------------------------------ EDN

/// Whether `text` looks like CBOR diagnostic notation: one container, tagged
/// item, or prefixed string, with balanced brackets and only EDN punctuation
/// outside strings and comments. Not a parser.
pub(crate) fn looks_like_edn(text: &[u8]) -> bool {
    let start = skip_ignorable(text, 0);
    let Some(rest) = text.get(start..) else {
        return false;
    };
    // The first token: an opener, a tag number with `(`, or a prefixed string.
    let lead = rest
        .iter()
        .take_while(|c| c.is_ascii_alphanumeric())
        .count();
    let first_ok = match (rest.first(), rest.get(lead)) {
        (Some(b'{' | b'['), _) => true,
        (Some(b'<'), _) => rest.get(1) == Some(&b'<'),
        (Some(c), Some(b'(')) if c.is_ascii_digit() => {
            rest.iter().take(lead).all(u8::is_ascii_digit)
        }
        (Some(c), Some(b'\'')) if c.is_ascii_alphabetic() => true,
        _ => false,
    };
    first_ok && balanced(text, start)
}

fn skip_ignorable(text: &[u8], mut i: usize) -> usize {
    loop {
        match text.get(i) {
            Some(c) if c.is_ascii_whitespace() => i += 1,
            Some(b'/') => match text
                .get(i + 1..)
                .and_then(|r| r.iter().position(|&c| c == b'/'))
            {
                Some(n) => i += n + 2,
                None => return text.len() + 1,
            },
            Some(b'#') => match text
                .get(i..)
                .and_then(|r| r.iter().position(|&c| c == b'\n'))
            {
                Some(n) => i += n + 1,
                None => return text.len(),
            },
            _ => return i,
        }
    }
}

fn balanced(text: &[u8], mut i: usize) -> bool {
    let mut stack: Vec<u8> = Vec::new();
    let mut seen_value = false;
    while let Some(&c) = text.get(i) {
        if stack.is_empty() && seen_value {
            // One item only: what follows must be ignorable.
            return skip_ignorable(text, i) == text.len();
        }
        match c {
            b'/' | b'#' => {
                let j = skip_ignorable(text, i);
                if j > text.len() {
                    return false;
                }
                i = j;
                continue;
            }
            b'"' | b'\'' => {
                let mut j = i + 1;
                loop {
                    match text.get(j) {
                        None => return false,
                        Some(b'\\') => j += 2,
                        Some(&q) if q == c => break,
                        Some(_) => j += 1,
                    }
                }
                i = j + 1;
                seen_value |= stack.is_empty();
                continue;
            }
            b'{' | b'[' | b'(' => stack.push(c),
            b'<' if text.get(i + 1) == Some(&b'<') => {
                stack.push(b'<');
                i += 1;
            }
            b'}' | b']' | b')' | b'>' => {
                let open = match c {
                    b'}' => b'{',
                    b']' => b'[',
                    b')' => b'(',
                    _ => b'<',
                };
                if stack.pop() != Some(open) || (c == b'>' && text.get(i + 1) != Some(&b'>')) {
                    return false;
                }
                if c == b'>' {
                    i += 1;
                }
                seen_value |= stack.is_empty();
            }
            c if c.is_ascii_alphanumeric()
                || c.is_ascii_whitespace()
                || b",:_-+.*".contains(&c) => {}
            _ => return false,
        }
        i += 1;
    }
    stack.is_empty() && seen_value
}
