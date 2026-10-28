//! Applying ([`unwrap_layers`]) and re-creating ([`rewrap`]) single layers.

use std::borrow::Cow;

use tokenator_json::{Node, Value as Json};

use crate::codec::{self, Alphabet};
use crate::{Layer, PathSegment, UnwrapError};

/// Peels one layer off `data`. Positional layers return a sub-slice.
pub(crate) fn unwrap_one<'a>(
    data: Cow<'a, [u8]>,
    layer: &Layer,
) -> Result<Cow<'a, [u8]>, &'static str> {
    let range = match layer {
        Layer::Trim { leading, trailing } => {
            let (l, t) = (leading.as_bytes(), trailing.as_bytes());
            if data.len() < l.len() + t.len() || !data.starts_with(l) || !data.ends_with(t) {
                return Err("surrounding whitespace does not match");
            }
            l.len()..data.len() - t.len()
        }
        Layer::Quotes { quote } => {
            let mut buf = [0; 4];
            let q = quote.encode_utf8(&mut buf).as_bytes();
            if data.len() < 2 * q.len() || !data.starts_with(q) || !data.ends_with(q) {
                return Err("not quoted");
            }
            q.len()..data.len() - q.len()
        }
        Layer::AuthorizationHeader { prefix } | Layer::BearerPrefix { prefix } => {
            let p = prefix.as_bytes();
            match data.get(..p.len()) {
                Some(head) if head.eq_ignore_ascii_case(p) => p.len()..data.len(),
                _ => return Err("prefix does not match"),
            }
        }
        Layer::UrlEncoded => {
            let (bytes, _) = codec::percent_decode(&data).ok_or("invalid percent-encoding")?;
            return Ok(Cow::Owned(bytes));
        }
        Layer::JsonField { path } => {
            return json_field(&data, path).map(|s| Cow::Owned(s.into_bytes()));
        }
        Layer::Base64Url { .. } | Layer::Base64Std { .. } => {
            let alphabet = match layer {
                Layer::Base64Url { .. } => Alphabet::Url,
                _ => Alphabet::Std,
            };
            let b = codec::base64_decode(&data, Some(alphabet)).ok_or("not base64")?;
            return Ok(Cow::Owned(b.bytes));
        }
        Layer::Hex { .. } => {
            return Ok(Cow::Owned(codec::hex_decode(&data).ok_or("not hex")?.bytes));
        }
        Layer::CborTag(tag) => {
            let item = tokenator_cbor::decode(&data).map_err(|_| "not a single CBOR item")?;
            match item.value {
                tokenator_cbor::Value::Tag(t, inner) if t == *tag => {
                    inner.span.start..inner.span.end
                }
                _ => return Err("not the expected CBOR tag"),
            }
        }
    };
    Ok(match data {
        Cow::Borrowed(b) => Cow::Borrowed(b.get(range).ok_or("out of range")?),
        Cow::Owned(v) => Cow::Owned(v.get(range).ok_or("out of range")?.to_vec()),
    })
}

/// The string at `path` in the JSON document `data`. Object keys match the
/// first member with that name.
fn json_field(data: &[u8], path: &[PathSegment]) -> Result<String, &'static str> {
    let root = tokenator_json::parse(data).map_err(|_| "not JSON")?;
    let node = follow(&root, path).ok_or("JSON path not found")?;
    match node.value() {
        Json::String(s) => Ok(s.to_string()),
        _ => Err("JSON value is not a string"),
    }
}

fn follow<'n, 'a>(mut node: &'n Node<'a>, path: &[PathSegment]) -> Option<&'n Node<'a>> {
    for seg in path {
        node = match seg {
            PathSegment::Key(k) => node.get(k)?,
            PathSegment::Index(i) => node.index(*i)?,
        };
    }
    Some(node)
}

/// Applies `layers` outermost first.
pub(crate) fn unwrap_all(input: &[u8], layers: &[Layer]) -> Result<Vec<u8>, UnwrapError> {
    let mut data = Cow::Borrowed(input);
    for (i, layer) in layers.iter().enumerate() {
        data = unwrap_one(data, layer).map_err(|reason| UnwrapError { layer: i, reason })?;
    }
    Ok(data.into_owned())
}

/// Wraps `payload` in one layer.
pub(crate) fn wrap_one(payload: Vec<u8>, layer: &Layer) -> Vec<u8> {
    match layer {
        Layer::Trim { leading, trailing } => {
            [leading.as_bytes(), &payload, trailing.as_bytes()].concat()
        }
        Layer::Quotes { quote } => {
            let mut buf = [0; 4];
            let q = quote.encode_utf8(&mut buf).as_bytes();
            [q, &payload, q].concat()
        }
        Layer::AuthorizationHeader { prefix } | Layer::BearerPrefix { prefix } => {
            [prefix.as_bytes(), &payload].concat()
        }
        Layer::UrlEncoded => codec::percent_encode(&payload),
        Layer::JsonField { path } => {
            let mut out = Vec::with_capacity(payload.len() + 16 * path.len() + 2);
            json_document(&mut out, path, &String::from_utf8_lossy(&payload));
            out
        }
        Layer::Base64Url { padded, wrap } => {
            codec::base64_encode(&payload, Alphabet::Url, *padded, *wrap)
        }
        Layer::Base64Std { padded, wrap } => {
            codec::base64_encode(&payload, Alphabet::Std, *padded, *wrap)
        }
        Layer::Hex {
            upper,
            separator,
            wrap,
        } => codec::hex_encode(&payload, *upper, *separator, *wrap),
        Layer::CborTag(tag) => {
            let mut out = codec::tag_head(*tag);
            out.extend_from_slice(&payload);
            out
        }
    }
}

/// Writes a compact JSON document holding only `path`, ending in `value`.
/// Skipped array slots are `null`.
fn json_document(out: &mut Vec<u8>, path: &[PathSegment], value: &str) {
    match path.split_first() {
        None => codec::json_string(out, value),
        Some((PathSegment::Key(k), rest)) => {
            out.push(b'{');
            codec::json_string(out, k);
            out.push(b':');
            json_document(out, rest, value);
            out.push(b'}');
        }
        Some((PathSegment::Index(i), rest)) => {
            out.push(b'[');
            for _ in 0..*i {
                out.extend_from_slice(b"null,");
            }
            json_document(out, rest, value);
            out.push(b']');
        }
    }
}
