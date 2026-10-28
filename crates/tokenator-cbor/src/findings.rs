//! Checks for non-preferred and non-deterministic encodings.

use crate::encode::{Mode, effective_width, encode_mode, write_head};
use crate::item::len_u64;
use crate::{EncodeMode, FloatWidth, Item, Span, Value, Width, encode, float};

/// One place where the encoding is not preferred (or not deterministic).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodingFinding {
    /// The exact input bytes that `preferred_bytes` would replace.
    ///
    /// - `NonPreferredArgument`: only the head of the item (for a string,
    ///   array, map, or tag the content is not included).
    /// - `NonPreferredFloat`: the whole float item.
    /// - `IndefiniteLength` and `MapKeyOrder`: the whole item, including
    ///   content and break byte.
    pub span: Span,
    /// What is wrong.
    pub kind: FindingKind,
    /// Replacement bytes for `span`.
    ///
    /// For `NonPreferredArgument` and `NonPreferredFloat` only the head
    /// changes. For `IndefiniteLength` it is the whole item in preferred
    /// serialization; for `MapKeyOrder` the whole map in deterministic
    /// encoding. Nested problems are still reported separately, so findings
    /// may overlap.
    pub preferred_bytes: Vec<u8>,
}

/// Kinds of [`EncodingFinding`]. The declaration order is the tie-break
/// order for findings that start at the same offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingKind {
    /// An integer, length, or tag number with a longer argument than needed.
    /// Also reported for the chunks of an indefinite-length string.
    NonPreferredArgument,
    /// A float that a shorter width represents exactly (NaN payload
    /// included).
    NonPreferredFloat,
    /// An indefinite-length string, array, or map.
    IndefiniteLength,
    /// A map whose keys are not in RFC 8949 §4.2.1 order (bytewise
    /// lexicographic order of the deterministically encoded keys). Equal
    /// (duplicate) keys are not an order violation. Only reported by
    /// [`deterministic_findings`].
    MapKeyOrder,
}

/// Every non-preferred encoding (RFC 8949 §4.1) in `item`, sorted by
/// `span.start` and then by [`FindingKind`] declaration order.
pub fn preferred_findings(item: &Item) -> Vec<EncodingFinding> {
    collect(item, false)
}

/// [`preferred_findings`] plus map key order violations (RFC 8949 §4.2.1),
/// sorted the same way.
pub fn deterministic_findings(item: &Item) -> Vec<EncodingFinding> {
    collect(item, true)
}

fn collect(item: &Item, key_order: bool) -> Vec<EncodingFinding> {
    let mut findings = Vec::new();
    walk(item, key_order, &mut findings);
    // Stable: findings with equal start and kind stay in document order.
    findings.sort_by_key(|f| (f.span.start, f.kind));
    findings
}

/// The span of an item's head only.
fn head_span(item: &Item) -> Span {
    Span {
        start: item.span.start,
        end: item.span.start + item.span.head_len,
        head_len: item.span.head_len,
    }
}

/// Reports a head whose argument is longer than needed.
fn check_argument(item: &Item, major: u8, arg: u64, out: &mut Vec<EncodingFinding>) {
    let used = effective_width(item.width, arg, Mode::Preserve);
    let preferred = Width::preferred_for(arg);
    if used != preferred {
        let mut bytes = Vec::with_capacity(1);
        write_head(&mut bytes, major, arg, preferred);
        out.push(EncodingFinding {
            span: head_span(item),
            kind: FindingKind::NonPreferredArgument,
            preferred_bytes: bytes,
        });
    }
}

fn walk(item: &Item, key_order: bool, out: &mut Vec<EncodingFinding>) {
    let indefinite = item.width == Width::Indefinite;
    if indefinite
        && matches!(
            item.value,
            Value::Bytes(_) | Value::Text(_) | Value::Array(_) | Value::Map(_)
        )
    {
        out.push(EncodingFinding {
            span: item.span,
            kind: FindingKind::IndefiniteLength,
            preferred_bytes: encode_mode(item, Mode::Preferred),
        });
    }
    match &item.value {
        Value::Uint(n) => check_argument(item, 0, *n, out),
        Value::Nint(n) => check_argument(item, 1, *n, out),
        Value::Bytes(_) | Value::Text(_) if indefinite => {
            for chunk in &item.chunks {
                walk(chunk, key_order, out);
            }
        }
        Value::Bytes(b) => check_argument(item, 2, len_u64(b.len()), out),
        Value::Text(t) => check_argument(item, 3, len_u64(t.len()), out),
        Value::Array(items) => {
            if !indefinite {
                check_argument(item, 4, len_u64(items.len()), out);
            }
            for i in items {
                walk(i, key_order, out);
            }
        }
        Value::Map(entries) => {
            if !indefinite {
                check_argument(item, 5, len_u64(entries.len()), out);
            }
            if key_order && !keys_sorted(entries) {
                out.push(EncodingFinding {
                    span: item.span,
                    kind: FindingKind::MapKeyOrder,
                    preferred_bytes: encode(item, EncodeMode::Deterministic),
                });
            }
            for (k, v) in entries {
                walk(k, key_order, out);
                walk(v, key_order, out);
            }
        }
        Value::Tag(tag, inner) => {
            check_argument(item, 6, *tag, out);
            walk(inner, key_order, out);
        }
        Value::Float(f, width) => {
            if float::effective_width(*f, *width) != float::shortest_width(*f) {
                let mut bytes = Vec::with_capacity(3);
                float::write(&mut bytes, *f, FloatWidth::F16);
                out.push(EncodingFinding {
                    span: item.span,
                    kind: FindingKind::NonPreferredFloat,
                    preferred_bytes: bytes,
                });
            }
        }
        Value::Bool(_) | Value::Null | Value::Undefined | Value::Simple(_) => {}
    }
}

/// Whether the deterministic encodings of the keys are in non-decreasing
/// bytewise order (equal keys are not a violation).
fn keys_sorted(entries: &[(Item, Item)]) -> bool {
    let mut prev: Option<Vec<u8>> = None;
    for (k, _) in entries {
        let key = encode_mode(k, Mode::Deterministic);
        if prev.as_ref().is_some_and(|p| *p > key) {
            return false;
        }
        prev = Some(key);
    }
    true
}
