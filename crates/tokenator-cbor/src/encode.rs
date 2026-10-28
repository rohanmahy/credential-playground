//! Encoding: preserving recorded encoding details, or one of the
//! serializations of draft-ietf-cbor-serialization-11.

use crate::item::len_u64;
use crate::{EncodeError, FloatWidth, Item, Value, Width, float};

/// How [`encode`] chooses among the encodings RFC 8949 allows.
///
/// `PreferredPlus` and `Deterministic` are the serializations defined in
/// draft-ietf-cbor-serialization-11 §4 and §5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeMode {
    /// Reproduce the recorded argument widths, float widths (NaN bit
    /// patterns included), indefinite lengths, string chunks, bignums, and
    /// map arrival order. Encoding a decoded item gives back the input bytes
    /// exactly.
    Preserve,
    /// Preferred-plus serialization (draft-ietf-cbor-serialization-11 §4.1):
    ///
    /// 1. shortest-form arguments;
    /// 2. definite-length strings; 3. definite-length arrays and maps;
    /// 4. floats in the shortest of f16/f32/f64 that is exact, with every
    ///    NaN written as the canonical `0xf97e00`;
    /// 5. bignums (tags 2 and 3 over a byte string) without leading zeros,
    ///    and as major type 0/1 when the value fits there (`c24101` becomes
    ///    `01`, `c340` becomes `20`).
    ///
    /// Map entries keep their arrival order.
    PreferredPlus,
    /// Deterministic serialization (draft-ietf-cbor-serialization-11 §5.1):
    /// preferred-plus, plus map entries sorted by the bytewise lexicographic
    /// order of the deterministic encodings of their keys. Duplicate keys
    /// are kept, adjacent and in arrival order.
    Deterministic,
}

/// [`EncodeMode`] without the public API's stability concerns; findings use
/// it to build replacement bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Preserve,
    PreferredPlus,
    Deterministic,
}

/// Encodes an item.
///
/// Fails with [`EncodeError::InvalidSimple`] in every mode if the item
/// contains a `Value::Simple` in 24..=31, which has no well-formed encoding.
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
///     encode(&item, EncodeMode::Preserve)?,
///     [0xa2, 0x61, 0x62, 0x20, 0x61, 0x61, 0xf9, 0x3e, 0x00]
/// );
/// assert_eq!(
///     encode(&item, EncodeMode::Deterministic)?,
///     [0xa2, 0x61, 0x61, 0xf9, 0x3e, 0x00, 0x61, 0x62, 0x20]
/// );
/// # Ok::<(), tokenator_cbor::EncodeError>(())
/// ```
pub fn encode(item: &Item, mode: EncodeMode) -> Result<Vec<u8>, EncodeError> {
    let mode = match mode {
        EncodeMode::Preserve => Mode::Preserve,
        EncodeMode::PreferredPlus => Mode::PreferredPlus,
        EncodeMode::Deterministic => Mode::Deterministic,
    };
    encode_mode(item, mode)
}

/// Encodes an item in the given internal mode.
pub(crate) fn encode_mode(item: &Item, mode: Mode) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    write_item(&mut out, item, mode)?;
    Ok(out)
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

fn write_item(out: &mut Vec<u8>, item: &Item, mode: Mode) -> Result<(), EncodeError> {
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
                write_item(out, i, mode)?;
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
                write_sorted_entries(out, entries)?;
            } else {
                for (k, v) in entries {
                    write_item(out, k, mode)?;
                    write_item(out, v, mode)?;
                }
            }
            if indefinite {
                out.push(0xff);
            }
        }
        Value::Tag(tag, inner) => match bignum(*tag, inner) {
            Some(magnitude) if mode != Mode::Preserve => write_bignum(out, *tag, magnitude),
            _ => {
                head(out, 6, *tag);
                write_item(out, inner, mode)?;
            }
        },
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
        Value::Undefined => out.push(0xf7),
        Value::Simple(n @ 24..=31) => return Err(EncodeError::InvalidSimple(*n)),
        Value::Simple(n) => write_head(out, 7, u64::from(*n), Width::preferred_for(u64::from(*n))),
        Value::Float(f, width) => {
            if mode == Mode::Preserve {
                float::write(out, *f, *width);
            } else if f.is_nan() {
                out.extend_from_slice(&CANONICAL_NAN);
            } else {
                // The narrowest width; `write` widens it as far as needed.
                float::write(out, *f, FloatWidth::F16);
            }
        }
    }
    Ok(())
}

/// The only NaN encoding that preferred-plus serialization allows
/// (draft-ietf-cbor-serialization-11 §4.1 rule 4).
pub(crate) const CANONICAL_NAN: [u8; 3] = [0xf9, 0x7e, 0x00];

/// If `tag` and `inner` form a bignum (tag 2 or 3 over a byte string), its
/// big-endian magnitude bytes, leading zeros included.
pub(crate) fn bignum<'i>(tag: u64, inner: &'i Item) -> Option<&'i [u8]> {
    match (tag, &inner.value) {
        (2 | 3, Value::Bytes(b)) => Some(b),
        _ => None,
    }
}

/// Writes a bignum in preferred-plus form (§4.1 rule 5): as major type 0
/// (tag 2) or 1 (tag 3) when it fits in 64 bits, otherwise as the tag over
/// its bytes without leading zeros, all with preferred heads.
pub(crate) fn write_bignum(out: &mut Vec<u8>, tag: u64, magnitude: &[u8]) {
    let first = magnitude
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(magnitude.len());
    let digits = magnitude.get(first..).unwrap_or_default();
    if digits.len() <= 8 {
        let n = digits
            .iter()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
        let major = if tag == 3 { 1 } else { 0 };
        write_head(out, major, n, Width::preferred_for(n));
    } else {
        write_head(out, 6, tag, Width::preferred_for(tag));
        let len = len_u64(digits.len());
        write_head(out, 2, len, Width::preferred_for(len));
        out.extend_from_slice(digits);
    }
}

/// Writes map entries in deterministic order (§5.1 rule 2): sorted by the
/// bytewise order of the deterministically encoded keys, duplicates in
/// arrival order.
fn write_sorted_entries(out: &mut Vec<u8>, entries: &[(Item, Item)]) -> Result<(), EncodeError> {
    // A plain loop: iterator adapters add several frames per nesting level
    // in debug builds.
    let mut sorted: Vec<(Vec<u8>, &Item)> = Vec::with_capacity(entries.len());
    for (k, v) in entries {
        sorted.push((encode_mode(k, Mode::Deterministic)?, v));
    }
    // Stable, so duplicate keys keep their arrival order.
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (key, value) in sorted {
        out.extend_from_slice(&key);
        write_item(out, value, Mode::Deterministic)?;
    }
    Ok(())
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
