//! Encoding, either preserving recorded encoding details or deterministic.

use crate::item::len_u64;
use crate::{FloatWidth, Item, Value, Width, float};

/// How [`encode`] chooses among the encodings RFC 8949 allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeMode {
    /// Reproduce the recorded argument widths, float widths, indefinite
    /// lengths, string chunks, and map arrival order. Encoding a decoded item
    /// gives back the input bytes exactly.
    Preserve,
    /// RFC 8949 §4.2.1 core deterministic encoding: preferred serialization
    /// (shortest arguments, shortest exact floats with NaN payloads kept),
    /// definite lengths only, and map entries sorted by the bytewise
    /// lexicographic order of their deterministically encoded keys. Duplicate
    /// keys are kept (adjacent, in arrival order). Tags, including bignums,
    /// are not rewritten.
    Deterministic,
}

/// Encoding modes, including the internal "preferred serialization" mode
/// (Deterministic without map sorting) used for findings.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Preserve,
    Preferred,
    Deterministic,
}

/// Encodes an item.
///
/// Does not validate: a `Value::Simple` in 24..=31 is emitted as
/// `0xf8 nn`, which is not well-formed.
///
/// ```
/// use tokenator_cbor::{encode, EncodeMode, Item};
///
/// let item = Item::map(vec![
///     (Item::text("b"), Item::int(-1)),
///     (Item::text("a"), Item::float(1.5)),
/// ]);
/// // Preserve keeps arrival order; Deterministic sorts the keys.
/// assert_eq!(
///     encode(&item, EncodeMode::Preserve),
///     [0xa2, 0x61, 0x62, 0x20, 0x61, 0x61, 0xf9, 0x3e, 0x00]
/// );
/// assert_eq!(
///     encode(&item, EncodeMode::Deterministic),
///     [0xa2, 0x61, 0x61, 0xf9, 0x3e, 0x00, 0x61, 0x62, 0x20]
/// );
/// ```
pub fn encode(item: &Item, mode: EncodeMode) -> Vec<u8> {
    let mode = match mode {
        EncodeMode::Preserve => Mode::Preserve,
        EncodeMode::Deterministic => Mode::Deterministic,
    };
    let mut out = Vec::new();
    write_item(&mut out, item, mode);
    out
}

/// Encodes an item in the given internal mode.
pub(crate) fn encode_mode(item: &Item, mode: Mode) -> Vec<u8> {
    let mut out = Vec::new();
    write_item(&mut out, item, mode);
    out
}

/// The width the encoder actually uses for an argument: the recorded one if
/// it fits (and the mode preserves widths), otherwise the preferred one.
pub(crate) fn effective_width(width: Width, arg: u64, mode: Mode) -> Width {
    if mode == Mode::Preserve && width.fits(arg) {
        width
    } else {
        Width::preferred_for(arg)
    }
}

/// Appends a head with a definite argument.
pub(crate) fn write_head(out: &mut Vec<u8>, major: u8, arg: u64, width: Width) {
    let mt = major << 5;
    let be = arg.to_be_bytes();
    let (ai, len) = match width {
        Width::U8 => (24, 1),
        Width::U16 => (25, 2),
        Width::U32 => (26, 4),
        Width::U64 => (27, 8),
        // Immediate; callers never pass Indefinite.
        _ => {
            out.push(mt | (be[7] & 0x1f));
            return;
        }
    };
    out.push(mt | ai);
    out.extend_from_slice(be.get(8 - len..).unwrap_or(&be));
}

fn write_item(out: &mut Vec<u8>, item: &Item, mode: Mode) {
    let indefinite = mode == Mode::Preserve && item.width == Width::Indefinite;
    let head = |out: &mut Vec<u8>, major: u8, arg: u64| {
        write_head(out, major, arg, effective_width(item.width, arg, mode));
    };
    match &item.value {
        Value::Uint(n) => head(out, 0, *n),
        Value::Nint(n) => head(out, 1, *n),
        Value::Bytes(_) | Value::Text(_) if indefinite => write_indefinite_string(out, item),
        Value::Bytes(b) => {
            head(out, 2, len_u64(b.len()));
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            head(out, 3, len_u64(t.len()));
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            if indefinite {
                out.push(0x9f);
            } else {
                head(out, 4, len_u64(items.len()));
            }
            for i in items {
                write_item(out, i, mode);
            }
            if indefinite {
                out.push(0xff);
            }
        }
        Value::Map(entries) => {
            if indefinite {
                out.push(0xbf);
            } else {
                head(out, 5, len_u64(entries.len()));
            }
            if mode == Mode::Deterministic {
                write_sorted_entries(out, entries);
            } else {
                for (k, v) in entries {
                    write_item(out, k, mode);
                    write_item(out, v, mode);
                }
            }
            if indefinite {
                out.push(0xff);
            }
        }
        Value::Tag(tag, inner) => {
            head(out, 6, *tag);
            write_item(out, inner, mode);
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
        Value::Undefined => out.push(0xf7),
        Value::Simple(n) => write_head(out, 7, u64::from(*n), Width::preferred_for(u64::from(*n))),
        Value::Float(f, width) => {
            let width = if mode == Mode::Preserve {
                *width
            } else {
                // The narrowest width; `write` widens it as far as needed.
                FloatWidth::F16
            };
            float::write(out, *f, width);
        }
    }
}

/// Writes map entries in RFC 8949 §4.2.1 order: sorted by the bytewise order
/// of the deterministically encoded keys, duplicates in arrival order.
fn write_sorted_entries(out: &mut Vec<u8>, entries: &[(Item, Item)]) {
    // A plain loop: iterator adapters add several frames per nesting level
    // in debug builds.
    let mut sorted: Vec<(Vec<u8>, &Item)> = Vec::with_capacity(entries.len());
    for (k, v) in entries {
        sorted.push((encode_mode(k, Mode::Deterministic), v));
    }
    // Stable, so duplicate keys keep their arrival order.
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (key, value) in sorted {
        out.extend_from_slice(&key);
        write_item(out, value, Mode::Deterministic);
    }
}

/// Writes an indefinite-length string, using the recorded chunks if they
/// still add up to the value, and the value as one chunk otherwise.
fn write_indefinite_string(out: &mut Vec<u8>, item: &Item) {
    let (major, content): (u8, &[u8]) = match &item.value {
        Value::Bytes(b) => (2, b),
        Value::Text(t) => (3, t.as_bytes()),
        _ => return,
    };
    out.push((major << 5) | 31);
    if chunks_match(item, major, content) {
        for chunk in &item.chunks {
            let bytes = match &chunk.value {
                Value::Bytes(b) => b.as_ref(),
                Value::Text(t) => t.as_bytes(),
                _ => continue,
            };
            let arg = len_u64(bytes.len());
            write_head(
                out,
                major,
                arg,
                effective_width(chunk.width, arg, Mode::Preserve),
            );
            out.extend_from_slice(bytes);
        }
    } else if !content.is_empty() {
        write_head(
            out,
            major,
            len_u64(content.len()),
            Width::preferred_for(len_u64(content.len())),
        );
        out.extend_from_slice(content);
    }
    out.push(0xff);
}

/// Whether every chunk has the string's major type and the chunks
/// concatenate to `content`.
fn chunks_match(item: &Item, major: u8, content: &[u8]) -> bool {
    let mut rest = content;
    for chunk in &item.chunks {
        let bytes = match (&chunk.value, major) {
            (Value::Bytes(b), 2) => b.as_ref(),
            (Value::Text(t), 3) => t.as_bytes(),
            _ => return false,
        };
        match rest.strip_prefix(bytes) {
            Some(r) => rest = r,
            None => return false,
        }
    }
    rest.is_empty()
}
