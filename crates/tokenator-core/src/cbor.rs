//! Small CBOR helpers over `tokenator-cbor` items.

use tokenator_cbor::{EncodeMode, Item, Value, Width, decode_seq, encode};
use tokenator_edn::{EncodingIndicators, PrintOptions};
use tokenator_registry::Label;

/// An integer item as `i64`.
pub(crate) fn int_of(item: &Item<'_>) -> Option<i64> {
    match item.value {
        Value::Uint(n) => i64::try_from(n).ok(),
        // -1 - n == !n
        Value::Nint(n) => i64::try_from(n).ok().map(|n| !n),
        _ => None,
    }
}

/// An int or text item as a registry label.
pub(crate) fn label_of(item: &Item<'_>) -> Option<Label> {
    match &item.value {
        Value::Text(t) => Some(Label::Text(t.to_string())),
        _ => int_of(item).map(Label::Int),
    }
}

/// The entries of a map item.
pub(crate) fn entries<'i, 'a>(item: &'i Item<'a>) -> &'i [(Item<'a>, Item<'a>)] {
    match &item.value {
        Value::Map(m) => m,
        _ => &[],
    }
}

/// The first value with integer key `label`.
pub(crate) fn map_get<'i, 'a>(map: &'i Item<'a>, label: i64) -> Option<&'i Item<'a>> {
    entries(map)
        .iter()
        .find(|(k, _)| int_of(k) == Some(label))
        .map(|(_, v)| v)
}

/// Compact EDN without encoding indicators (NodeId segments, labels).
pub(crate) fn compact_edn(item: &Item<'_>) -> String {
    let opts = PrintOptions {
        encoding_indicators: EncodingIndicators::Never,
        ..PrintOptions::new()
    };
    tokenator_edn::print(item, &opts).text
}

/// Compact EDN that re-encodes exactly (values in the SD view).
pub(crate) fn exact_edn(item: &Item<'_>) -> String {
    tokenator_edn::print(item, &PrintOptions::new()).text
}

/// The items of `content` when it is a complete CBOR sequence of one or
/// more items that re-encodes exactly (the printer's rule for `<<…>>`).
pub(crate) fn exact_sequence(content: &[u8]) -> Option<Vec<Item<'_>>> {
    let items = decode_seq(content).ok()?;
    if items.is_empty() {
        return None;
    }
    let mut again = Vec::with_capacity(content.len());
    for item in &items {
        again.extend(encode(item, EncodeMode::Preserve).ok()?);
    }
    (again == content).then_some(items)
}

/// Absolute `start..end` of a decoded item, given the offset its spans are
/// relative to. `None` for built items.
pub(crate) fn abs_span(item: &Item<'_>, base: usize) -> Option<(usize, usize)> {
    (item.span.end > 0).then_some((base + item.span.start, base + item.span.end))
}

/// The contents range of a definite byte string item (absolute).
pub(crate) fn bstr_contents(item: &Item<'_>, base: usize) -> Option<(usize, usize)> {
    match item.value {
        Value::Bytes(_) if item.width != Width::Indefinite && item.span.end > 0 => Some((
            base + item.span.start + item.span.head_len,
            base + item.span.end,
        )),
        _ => None,
    }
}

/// Whether the item tree contains a to-be-redacted (58) or to-be-decoy (62)
/// tag. Iterative, so deep inputs are fine.
pub(crate) fn has_sd_tags(root: &Item<'_>) -> bool {
    let mut stack = vec![root];
    while let Some(item) = stack.pop() {
        match &item.value {
            Value::Tag(58 | 62, _) => return true,
            Value::Tag(_, inner) => stack.push(inner),
            Value::Array(a) => stack.extend(a.iter()),
            Value::Map(m) => {
                for (k, v) in m {
                    stack.push(k);
                    stack.push(v);
                }
            }
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequences_must_reencode() {
        assert_eq!(exact_sequence(&[0x01, 0x02]).map(|v| v.len()), Some(2));
        assert!(
            exact_sequence(&[0x18, 0x01]).is_some(),
            "non-preferred is still exact"
        );
        assert!(exact_sequence(&[0x18]).is_none());
        assert!(exact_sequence(&[]).is_none());
    }

    #[test]
    fn key_edn_drops_indicators() {
        let item = tokenator_cbor::decode(&[0x18, 0x01]).unwrap();
        assert_eq!(compact_edn(&item), "1");
        assert_eq!(exact_edn(&item), "1_0");
    }
}
