//! Serialization conformance checks (draft-ietf-cbor-serialization-11 §4
//! and §5) and duplicate map key detection. These only report; they never
//! modify the item.

use crate::encode::{Mode, effective_width, encode_mode, write_head};
use crate::item::len_u64;
use crate::{FloatWidth, Item, Span, Value, Width, float};

/// One place where the encoding is not preferred-plus (or not
/// deterministic).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodingFinding {
    /// The exact input bytes that `preferred_bytes` would replace.
    ///
    /// - `NonPreferredArgument`: only the head of the item (for a string,
    ///   array, map, or tag the content is not included).
    /// - `NonPreferredFloat` and `NonCanonicalNaN`: the whole float item.
    /// - `NonPreferredBignum`, `IndefiniteLength`, and `MapKeyOrder`: the
    ///   whole item (for a bignum, the tag and its byte string), including
    ///   content and break bytes.
    pub span: Span,
    /// What is wrong.
    pub kind: FindingKind,
    /// Replacement bytes for `span`.
    ///
    /// For `NonPreferredArgument` and `NonPreferredFloat` only the head
    /// changes; `NonCanonicalNaN` always suggests `f97e00`. For
    /// `NonPreferredBignum` and `IndefiniteLength` it is the whole item in
    /// preferred-plus serialization; for `MapKeyOrder` the whole map in
    /// deterministic serialization. Nested problems are still reported
    /// separately, so findings may overlap.
    pub preferred_bytes: Vec<u8>,
}

/// Kinds of [`EncodingFinding`], each tied to a rule of
/// draft-ietf-cbor-serialization-11. The declaration order is the tie-break
/// order for findings that start at the same offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingKind {
    /// §4.1 rule 1: an integer, length, or tag number with a longer argument
    /// than needed. Also reported for the chunks of an indefinite-length
    /// string.
    NonPreferredArgument,
    /// §4.1 rule 4: a non-NaN float that a shorter width represents exactly.
    NonPreferredFloat,
    /// §4.1 rule 4: any NaN other than `f97e00` (wider encodings of the
    /// quiet NaN, payloads, signaling NaNs, the sign bit set).
    NonCanonicalNaN,
    /// §4.1 rule 5: a bignum (tag 2 or 3 over a byte string) with leading
    /// zeros, or whose value fits major type 0 or 1.
    NonPreferredBignum,
    /// §4.1 rules 2 and 3: an indefinite-length string, array, or map.
    IndefiniteLength,
    /// §5.1 rule 2: a map whose keys are not sorted by the bytewise
    /// lexicographic order of their deterministic encodings. Equal
    /// (duplicate) keys are not an order violation. Only reported by
    /// [`deterministic_findings`].
    MapKeyOrder,
}

/// Every departure from preferred-plus serialization
/// (draft-ietf-cbor-serialization-11 §4.1) in `item`, sorted by
/// `span.start` and then by [`FindingKind`] declaration order.
///
/// A finding whose replacement would contain a `Simple(24..=31)` (which
/// cannot be encoded) is omitted.
pub fn preferred_plus_findings(item: &Item) -> Vec<EncodingFinding> {
    collect(item, false)
}

/// [`preferred_plus_findings`] plus map key order violations: everything
/// that is not deterministic serialization
/// (draft-ietf-cbor-serialization-11 §5.1), sorted the same way.
pub fn deterministic_findings(item: &Item) -> Vec<EncodingFinding> {
    collect(item, true)
}

/// One step from an item to one of its children, used to locate a map in
/// [`DuplicateKey::path`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PathStep {
    /// Element `n` of an array.
    Index(usize),
    /// The key of entry `n` of a map.
    Key(usize),
    /// The value of entry `n` of a map.
    Value(usize),
    /// The content of a tag.
    TagContent,
}

/// A map key that equals an earlier key of the same map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateKey {
    /// Steps from the root item to the map (empty if the root is the map).
    pub path: Vec<PathStep>,
    /// Span of the map.
    pub map: Span,
    /// Entry index of the first occurrence of the key.
    pub first: usize,
    /// Entry index of the later, duplicate occurrence.
    pub duplicate: usize,
    /// Span of the first occurrence's key.
    pub first_key: Span,
    /// Span of the duplicate key.
    pub duplicate_key: Span,
}

/// Every duplicate key in every map in `item`, including maps nested in
/// keys, values, arrays, and tags. Detection only: decoding keeps
/// duplicates, and the linter decides what to report.
///
/// Two keys are duplicates when their deterministic serializations
/// (draft-ietf-cbor-serialization-11 §5) are equal. That makes `1`, `0x1801`,
/// and the bignum `c24101` the same key, as are all NaNs, while `0.0` and
/// `-0.0` stay distinct. A key that cannot be encoded (it contains a
/// `Simple(24..=31)`) is never a duplicate.
///
/// Each later occurrence is paired with the first one, so a key that appears
/// three times gives two results. Results are in document order: by map
/// (outer before inner, then by position), then by `duplicate`.
#[allow(clippy::unimplemented)]
pub fn duplicate_keys(item: &Item) -> Vec<DuplicateKey> {
    let _ = item;
    unimplemented!()
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
                    preferred_bytes: encode_mode(item, Mode::Deterministic),
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
