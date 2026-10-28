//! The unwrapping search behind [`crate::detect`].
//!
//! Each node is a candidate payload: the input itself, or what is left after
//! peeling some layers. A node is classified, then every layer that applies
//! to it is peeled and the result explored, depth first, up to
//! [`MAX_LAYERS`]. Text cleanup (trim, quotes, prefixes) is exclusive: when
//! it applies, only the cleaned text is explored. Every other layer adds a
//! branch, so ambiguous text (hex that is also base64) is read both ways.
//! A node budget and a byte budget bound the work on adversarial input.

use std::borrow::Cow;
use std::collections::HashSet;
use std::ops::Range;

use tokenator_json::{Node, Value as Json};

use crate::classify::{self, conf};
use crate::codec;
use crate::{Candidate, Kind, Layer, MAX_LAYERS, PathSegment};

/// The most nodes explored for one input.
const MAX_NODES: usize = 512;
/// The most candidates returned.
pub(crate) const MAX_CANDIDATES: usize = 64;

/// Where a node's bytes are in the input.
#[derive(Clone, Debug)]
enum Origin {
    /// Only positional layers so far: the node is `input[offset..][..len]`.
    At(usize),
    /// A decoding layer was applied: its input was this range.
    Frozen(Range<usize>),
}

impl Origin {
    fn range(&self, len: usize) -> Range<usize> {
        match self {
            Origin::At(o) => *o..o + len,
            Origin::Frozen(r) => r.clone(),
        }
    }

    /// A positional child at `sub` within a node.
    fn sub(&self, sub: &Range<usize>) -> Origin {
        match self {
            Origin::At(o) => Origin::At(o + sub.start),
            Origin::Frozen(r) => Origin::Frozen(r.clone()),
        }
    }

    /// A decoded child of a node whose (encoded) part is `sub`.
    fn decoded(&self, sub: &Range<usize>) -> Origin {
        match self {
            Origin::At(o) => Origin::Frozen(o + sub.start..o + sub.end),
            Origin::Frozen(r) => Origin::Frozen(r.clone()),
        }
    }
}

struct Explorer {
    nodes_left: usize,
    bytes_left: usize,
    layers: Vec<Layer>,
    found: Vec<Candidate>,
}

/// See [`crate::detect`].
pub(crate) fn detect(input: &[u8]) -> Vec<Candidate> {
    let mut ex = Explorer {
        nodes_left: MAX_NODES,
        bytes_left: input.len().saturating_mul(8).max(1 << 20),
        layers: Vec::new(),
        found: Vec::new(),
    };
    ex.explore(input, Origin::At(0));
    let mut found = ex.found;
    // Stable: ties keep discovery order (input order for JSON fields).
    found.sort_by_key(|c| std::cmp::Reverse(c.confidence));
    let mut seen = HashSet::new();
    found.retain(|c| seen.insert((c.kind.clone(), c.layers.clone())));
    found.truncate(MAX_CANDIDATES);
    found
}

/// What the layers cost in confidence: each decoding step is a little less
/// likely to be the intended reading, and base64 more so than hex (hex text
/// is also valid base64, never the reverse).
fn penalty(layers: &[Layer]) -> u8 {
    layers
        .iter()
        .map(|l| match l {
            Layer::Hex { .. } | Layer::UrlEncoded => 1u8,
            Layer::Base64Url { .. } | Layer::Base64Std { .. } => 2,
            _ => 0,
        })
        .fold(0, u8::saturating_add)
}

fn is_cleanup(layer: &Layer) -> bool {
    matches!(
        layer,
        Layer::Trim { .. }
            | Layer::Quotes { .. }
            | Layer::AuthorizationHeader { .. }
            | Layer::BearerPrefix { .. }
    )
}

/// The length of `prefix` (case-insensitive) plus following spaces and tabs
/// at the start of `data`, requiring at least `min_space` of them.
fn prefix_len(data: &[u8], prefix: &[u8], min_space: usize) -> Option<usize> {
    let head = data.get(..prefix.len())?;
    if !head.eq_ignore_ascii_case(prefix) {
        return None;
    }
    let rest = data.get(prefix.len()..)?;
    let spaces = rest
        .iter()
        .take_while(|c| matches!(c, b' ' | b'\t'))
        .count();
    (spaces >= min_space && spaces < rest.len()).then_some(prefix.len() + spaces)
}

impl Explorer {
    fn push(&mut self, kind: Kind, base: u8, data_len: usize, origin: &Origin) {
        self.found.push(Candidate {
            layers: self.layers.clone(),
            kind,
            confidence: base.saturating_sub(penalty(&self.layers)).min(100),
            payload_range: origin.range(data_len),
        });
    }

    /// Explores `child` under one more `layer`, if the depth allows.
    fn descend(&mut self, layer: Layer, child: &[u8], origin: Origin) {
        if self.layers.len() >= MAX_LAYERS {
            return;
        }
        self.layers.push(layer);
        self.explore(child, origin);
        self.layers.pop();
    }

    fn explore(&mut self, data: &[u8], origin: Origin) {
        if data.is_empty() || self.nodes_left == 0 || data.len() > self.bytes_left {
            return;
        }
        self.nodes_left -= 1;
        self.bytes_left -= data.len();

        // Binary: one CBOR item. Tags are peeled; the rest is classified.
        if let Ok(item) = tokenator_cbor::decode(data) {
            use tokenator_cbor::Value as Cbor;
            let tag = match self.layers.last() {
                Some(Layer::CborTag(t)) => Some(*t),
                _ => None,
            };
            for (kind, c) in classify::cbor(&item, tag) {
                self.push(kind, c, data.len(), &origin);
            }
            if let Cbor::Tag(t, inner) = &item.value {
                let r = inner.span.start..inner.span.end;
                if let Some(child) = data.get(r.clone()) {
                    self.descend(Layer::CborTag(*t), child, origin.sub(&r));
                }
            }
            if matches!(item.value, Cbor::Array(_) | Cbor::Map(_) | Cbor::Tag(..)) {
                // Never trimmed or read as text (a COSE_Key may end in 0x0a).
                return;
            }
        }
        let Ok(text) = std::str::from_utf8(data) else {
            return;
        };

        if self.clean_up(data, &origin) {
            return;
        }

        if let Some((kind, c)) = classify::jose_compact(data) {
            self.push(kind, c, data.len(), &origin);
        }
        if let Some(labels) = classify::pem(text) {
            self.push(Kind::Pem { labels }, conf::PEM, data.len(), &origin);
        }
        let json = match data.trim_ascii_start().first() {
            Some(b'{' | b'[') => tokenator_json::parse(data).ok(),
            _ => None,
        };
        match &json {
            Some(root) => {
                let (kinds, structured) = classify::json(root);
                for (kind, c) in kinds {
                    self.push(kind, c, data.len(), &origin);
                }
                if !structured {
                    self.fields(data, &origin, root, &mut Vec::new());
                }
            }
            None => {
                if self.layers.iter().all(|l| matches!(l, Layer::Trim { .. }))
                    && classify::looks_like_edn(data)
                {
                    self.push(Kind::EdnText, conf::EDN, data.len(), &origin);
                }
                // Percent-decoding a JSON document would break its strings;
                // fields are percent-decoded on their own instead.
                if data.contains(&b'%')
                    && let Some((bytes, true)) = codec::percent_decode(data)
                {
                    self.descend(Layer::UrlEncoded, &bytes, origin.decoded(&(0..data.len())));
                }
            }
        }
        if let Some(hex) = codec::hex_decode(data).filter(|h| !h.bytes.is_empty()) {
            self.descend(hex.layer, &hex.bytes, origin.decoded(&(0..data.len())));
        }
        if let Some(b64) = codec::base64_decode(data, None).filter(|b| !b.bytes.is_empty()) {
            let layer = b64.layer();
            self.descend(layer, &b64.bytes, origin.decoded(&(0..data.len())));
        }
    }

    /// Peels one text-cleanup layer, if one applies, and explores the rest.
    /// Cleanup only happens before any other layer, and each kind once.
    fn clean_up(&mut self, data: &[u8], origin: &Origin) -> bool {
        if !self.layers.iter().all(is_cleanup) {
            return false;
        }
        let has = |f: fn(&Layer) -> bool| self.layers.iter().any(f);
        let peeled = if self.layers.is_empty() {
            let lead = data.iter().take_while(|c| c.is_ascii_whitespace()).count();
            let trail = data
                .iter()
                .rev()
                .take_while(|c| c.is_ascii_whitespace())
                .count();
            if lead + trail == 0 {
                None
            } else if lead == data.len() {
                return true; // whitespace only
            } else {
                let r = lead..data.len() - trail;
                let text = |r: Range<usize>| {
                    String::from_utf8_lossy(data.get(r).unwrap_or_default()).into_owned()
                };
                let layer = Layer::Trim {
                    leading: text(0..lead),
                    trailing: text(data.len() - trail..data.len()),
                };
                Some((layer, r))
            }
        } else {
            None
        };
        let peeled = peeled.or_else(|| {
            let (&first, &last) = (data.first()?, data.last()?);
            if matches!(first, b'"' | b'\'' | b'`')
                && first == last
                && data.len() > 2
                && !has(|l| matches!(l, Layer::Quotes { .. }))
            {
                return Some((
                    Layer::Quotes {
                        quote: char::from(first),
                    },
                    1..data.len() - 1,
                ));
            }
            let bearer = has(|l| matches!(l, Layer::BearerPrefix { .. }));
            let prefixed = |n: usize, make: fn(String) -> Layer| {
                let p = String::from_utf8_lossy(data.get(..n).unwrap_or_default()).into_owned();
                Some((make(p), n..data.len()))
            };
            if bearer {
                return None;
            }
            if !has(|l| matches!(l, Layer::AuthorizationHeader { .. }))
                && let Some(n) = prefix_len(data, b"authorization:", 0)
            {
                return prefixed(n, |prefix| Layer::AuthorizationHeader { prefix });
            }
            let n = prefix_len(data, b"bearer", 1)?;
            prefixed(n, |prefix| Layer::BearerPrefix { prefix })
        });
        match peeled {
            Some((layer, r)) => {
                if let Some(child) = data.get(r.clone()) {
                    self.descend(layer, child, origin.sub(&r));
                }
                true
            }
            None => false,
        }
    }

    /// Explores every string in a JSON document under a `JsonField` layer,
    /// in document order. Within an object only the first member of each
    /// name is used, since that is the one a path resolves to.
    fn fields(
        &mut self,
        data: &[u8],
        origin: &Origin,
        node: &Node<'_>,
        path: &mut Vec<PathSegment>,
    ) {
        if self.nodes_left == 0 {
            return;
        }
        match node.value() {
            Json::String(s) if !path.is_empty() && !s.is_empty() => {
                let Some(span) = node.span() else { return };
                let content = span.start + 1..span.end.saturating_sub(1);
                let layer = Layer::JsonField { path: path.clone() };
                match s {
                    Cow::Borrowed(_) => {
                        if let Some(child) = data.get(content.clone()) {
                            self.descend(layer, child, origin.sub(&content));
                        }
                    }
                    Cow::Owned(owned) => {
                        self.descend(layer, owned.as_bytes(), origin.decoded(&content))
                    }
                }
            }
            Json::Array(elements) => {
                for (i, e) in elements.iter().enumerate() {
                    path.push(PathSegment::Index(i));
                    self.fields(data, origin, e, path);
                    path.pop();
                }
            }
            Json::Object(members) => {
                let mut names = HashSet::new();
                for m in members {
                    if !names.insert(m.key().as_ref()) {
                        continue;
                    }
                    path.push(PathSegment::Key(m.key().to_string()));
                    self.fields(data, origin, m.value(), path);
                    path.pop();
                }
            }
            _ => {}
        }
    }
}
