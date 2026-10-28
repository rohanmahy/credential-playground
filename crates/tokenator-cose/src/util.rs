//! Small helpers shared by the modules: labels, map lookup, tree walks,
//! heads, and byte splicing.

use std::borrow::Cow;

use tokenator_cbor::{EncodeMode, Item, Span, Value, Width, encode};

use crate::CoseError;
use tokenator_crypto::{DeclaredAlg, alg_from_cose};
use tokenator_keys::Label;

/// An integer item as `i64`.
pub(crate) fn int_of(item: &Item<'_>) -> Option<i64> {
    match item.value {
        Value::Uint(n) => i64::try_from(n).ok(),
        // -1 - n == !n
        Value::Nint(n) => i64::try_from(n).ok().map(|n| !n),
        _ => None,
    }
}

/// An int or text item as a [`Label`].
pub(crate) fn label_of(item: &Item<'_>) -> Option<Label> {
    match &item.value {
        Value::Text(t) => Some(Label::Text(t.to_string())),
        _ => int_of(item).map(Label::Int),
    }
}

/// Whether an item is the int or text `label`, compared by value.
pub(crate) fn label_eq(item: &Item<'_>, label: &Label) -> bool {
    match (&item.value, label) {
        (Value::Text(t), Label::Text(l)) => t == l,
        (_, Label::Int(l)) => int_of(item) == Some(*l),
        _ => false,
    }
}

/// The entries of a map item.
pub(crate) fn entries<'i, 'a>(item: &'i Item<'a>) -> Option<&'i [(Item<'a>, Item<'a>)]> {
    match &item.value {
        Value::Map(m) => Some(m),
        _ => None,
    }
}

/// The first entry with integer key `label`.
pub(crate) fn map_get<'i, 'a>(map: &'i Item<'a>, label: i64) -> Option<&'i Item<'a>> {
    entries(map)?
        .iter()
        .find(|(k, _)| int_of(k) == Some(label))
        .map(|(_, v)| v)
}

/// Byte string contents.
pub(crate) fn bytes_of<'i>(item: &'i Item<'_>) -> Option<&'i [u8]> {
    match &item.value {
        Value::Bytes(b) => Some(b),
        _ => None,
    }
}

/// An `alg` value: an integer label or (JOSE-style) a text name.
pub(crate) fn declared_alg(item: &Item<'_>) -> Option<DeclaredAlg> {
    match &item.value {
        Value::Text(t) => Some(DeclaredAlg::UnknownJose(t.to_string())),
        _ => {
            let label = int_of(item)?;
            Some(match alg_from_cose(label) {
                Some(alg) => DeclaredAlg::Known(alg),
                None => DeclaredAlg::UnknownCose(label),
            })
        }
    }
}

/// Visits every item in document order (keys before their values) with an
/// explicit stack, so deep nesting costs heap rather than call stack.
pub(crate) fn walk<'i, 'a>(root: &'i Item<'a>, mut f: impl FnMut(&'i Item<'a>)) {
    let mut stack = vec![root];
    while let Some(item) = stack.pop() {
        f(item);
        match &item.value {
            Value::Array(a) => stack.extend(a.iter().rev()),
            Value::Map(m) => {
                for (k, v) in m.iter().rev() {
                    stack.push(v);
                    stack.push(k);
                }
            }
            Value::Tag(_, inner) => stack.push(inner),
            _ => {}
        }
    }
}

/// Whether any item in the tree has indefinite length.
pub(crate) fn has_indefinite(root: &Item<'_>) -> bool {
    let mut found = false;
    walk(root, |i| found |= i.width == Width::Indefinite);
    found
}

/// `usize` to `u64` (lossless on every supported target).
pub(crate) fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// A preferred head for major type `major` and argument `arg`.
pub(crate) fn head(major: u8, arg: u64) -> Vec<u8> {
    let m = major << 5;
    if let Ok(b) = u8::try_from(arg) {
        if b < 24 {
            return vec![m | b];
        }
        return vec![m | 24, b];
    }
    let mut out = Vec::with_capacity(9);
    if let Ok(v) = u16::try_from(arg) {
        out.push(m | 25);
        out.extend(v.to_be_bytes());
    } else if let Ok(v) = u32::try_from(arg) {
        out.push(m | 26);
        out.extend(v.to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend(arg.to_be_bytes());
    }
    out
}

/// An encoded byte string with head width `width` when the length fits it
/// (preferred otherwise, and for `Indefinite`).
pub(crate) fn bstr(contents: &[u8], width: Width) -> Vec<u8> {
    let width = if width == Width::Indefinite {
        Width::Immediate
    } else {
        width
    };
    // A byte string always encodes.
    encode(
        &Item::bytes(Cow::Borrowed(contents)).with_width(width),
        EncodeMode::Preserve,
    )
    .unwrap_or_default()
}

/// The argument width of a definite head of `head_len` bytes.
pub(crate) fn width_of_head(head_len: usize) -> Width {
    match head_len {
        2 => Width::U8,
        3 => Width::U16,
        5 => Width::U32,
        9 => Width::U64,
        _ => Width::Immediate,
    }
}

/// `span` moved by `by` bytes.
pub(crate) fn shift(span: Span, by: usize) -> Span {
    Span {
        start: span.start.saturating_add(by),
        end: span.end.saturating_add(by),
        head_len: span.head_len,
    }
}

/// The bytes a span covers.
pub(crate) fn slice(bytes: &[u8], span: Span) -> Option<&[u8]> {
    bytes.get(span.start..span.end)
}

/// Replaces non-overlapping spans of `bytes`; everything else is copied.
pub(crate) fn splice(bytes: &[u8], mut edits: Vec<(Span, Vec<u8>)>) -> Vec<u8> {
    edits.sort_by_key(|(s, _)| s.start);
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    for (span, new) in edits {
        out.extend(bytes.get(at..span.start).unwrap_or_default());
        out.extend(new);
        at = span.end.max(at);
    }
    out.extend(bytes.get(at..).unwrap_or_default());
    out
}

/// A copy of `item` with a new value, keeping its span and width (the
/// encoder falls back to the preferred width when the old one no longer
/// fits).
pub(crate) fn with_value<'a>(item: &Item<'a>, value: Value<'a>) -> Item<'a> {
    Item {
        value,
        span: item.span,
        width: item.width,
        chunks: Vec::new(),
    }
}

/// Encodes with `EncodeMode::Preserve`.
pub(crate) fn enc(item: &Item<'_>) -> Result<Vec<u8>, CoseError> {
    Ok(encode(item, EncodeMode::Preserve)?)
}
