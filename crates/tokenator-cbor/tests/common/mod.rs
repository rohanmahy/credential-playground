//! Shared helpers for the tokenator-cbor integration tests.
//!
//! These deliberately avoid the crate's own encoder so that expectations do
//! not depend on the code under test: `diag` renders an item as EDN-like text,
//! `check_spans` verifies span invariants against the input bytes.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use tokenator_cbor::{EncodeMode, FloatWidth, Item, Value, Width, encode};

/// Parses hex, ignoring whitespace and `_`.
pub fn h(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'_')
        .collect();
    assert!(digits.len().is_multiple_of(2), "odd hex length: {s:?}");
    digits
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

/// Lower-case hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The shortest argument width for `arg`.
pub fn preferred_width(arg: u64) -> Width {
    match arg {
        0..=23 => Width::Immediate,
        24..=0xff => Width::U8,
        0x100..=0xffff => Width::U16,
        0x1_0000..=0xffff_ffff => Width::U32,
        _ => Width::U64,
    }
}

fn indicator(width: Width, arg: u64) -> &'static str {
    if width == preferred_width(arg) {
        return "";
    }
    match width {
        Width::Immediate => "_i",
        Width::U8 => "_0",
        Width::U16 => "_1",
        Width::U32 => "_2",
        Width::U64 => "_3",
        Width::Indefinite => "_?",
    }
}

fn float_text(f: f64) -> String {
    if f.is_nan() {
        if f.to_bits() == 0x7ff8_0000_0000_0000 {
            "NaN".into()
        } else {
            format!("nan(0x{:016x})", f.to_bits())
        }
    } else if f.is_infinite() {
        if f > 0.0 { "Infinity" } else { "-Infinity" }.into()
    } else {
        format!("{f:?}")
    }
}

fn join(items: impl Iterator<Item = String>) -> String {
    items.collect::<Vec<_>>().join(", ")
}

/// EDN-like rendering that shows encoding details: an EDN encoding
/// indicator (`_i`, `_0`..`_3`) wherever the width is not preferred,
/// `_ ` for indefinite length, chunks of indefinite strings as `(_ a, b)`,
/// and every float's width as `_1` (f16), `_2` (f32), or `_3` (f64).
pub fn diag(item: &Item) -> String {
    let w = item.width;
    let indef = w == Width::Indefinite;
    match &item.value {
        Value::Uint(n) => format!("{n}{}", indicator(w, *n)),
        Value::Nint(n) => format!("{}{}", -1 - i128::from(*n), indicator(w, *n)),
        Value::Bytes(_) | Value::Text(_) if indef => {
            format!("(_ {})", join(item.chunks.iter().map(diag)))
        }
        Value::Bytes(b) => format!("h'{}'{}", hex(b), indicator(w, b.len() as u64)),
        Value::Text(t) => format!("{t:?}{}", indicator(w, t.len() as u64)),
        Value::Array(a) => {
            let open = if indef {
                "_ ".to_string()
            } else {
                let i = indicator(w, a.len() as u64);
                if i.is_empty() {
                    String::new()
                } else {
                    format!("{i} ")
                }
            };
            format!("[{open}{}]", join(a.iter().map(diag)))
        }
        Value::Map(m) => {
            let open = if indef {
                "_ ".to_string()
            } else {
                let i = indicator(w, m.len() as u64);
                if i.is_empty() {
                    String::new()
                } else {
                    format!("{i} ")
                }
            };
            let body = join(m.iter().map(|(k, v)| format!("{}: {}", diag(k), diag(v))));
            format!("{{{open}{body}}}")
        }
        Value::Tag(t, inner) => format!("{t}{}({})", indicator(w, *t), diag(inner)),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".into(),
        Value::Undefined => "undefined".into(),
        Value::Simple(n) => format!("simple({n})"),
        Value::Float(f, fw) => {
            let suffix = match fw {
                FloatWidth::F16 => "_1",
                FloatWidth::F32 => "_2",
                FloatWidth::F64 => "_3",
            };
            format!("{}{suffix}", float_text(*f))
        }
    }
}

fn magnitude(neg: bool, be: &[u8]) -> String {
    let stripped: Vec<u8> = be.iter().copied().skip_while(|b| *b == 0).collect();
    let digits = if stripped.is_empty() {
        "0".to_string()
    } else {
        let s = hex(&stripped);
        s.trim_start_matches('0').to_string()
    };
    format!("int({}{digits})", if neg { '-' } else { '+' })
}

/// Encoding-independent rendering used to compare a decoded item with the
/// expected value from the test vectors. Widths, indefinite lengths, and
/// chunking are ignored; floats are compared by their f64 bit pattern; and
/// integers are unified with bignums (tags 2 and 3 over a byte string), as
/// the vectors' `collapseBigInts` option requires. `int(-m)` means `-1 - m`.
pub fn sem(item: &Item) -> String {
    sem_impl(item, false)
}

/// Like [`sem`], but map entries are sorted, so it is unaffected by the
/// reordering that Deterministic encoding does.
pub fn sem_unordered(item: &Item) -> String {
    sem_impl(item, true)
}

fn sem_impl(item: &Item, sort_maps: bool) -> String {
    let sem = |i: &Item| sem_impl(i, sort_maps);
    match &item.value {
        Value::Uint(n) => magnitude(false, &n.to_be_bytes()),
        Value::Nint(n) => magnitude(true, &n.to_be_bytes()),
        Value::Bytes(b) => format!("h'{}'", hex(b)),
        Value::Text(t) => format!("{t:?}"),
        Value::Array(a) => format!("[{}]", join(a.iter().map(&sem))),
        Value::Map(m) => {
            let mut entries: Vec<String> = m
                .iter()
                .map(|(k, v)| format!("{}: {}", sem(k), sem(v)))
                .collect();
            if sort_maps {
                entries.sort();
            }
            format!("{{{}}}", entries.join(", "))
        }
        Value::Tag(t @ (2 | 3), inner) => match &inner.value {
            Value::Bytes(b) => magnitude(*t == 3, b),
            _ => format!("{t}({})", sem(inner)),
        },
        Value::Tag(t, inner) => format!("{t}({})", sem(inner)),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".into(),
        Value::Undefined => "undefined".into(),
        Value::Simple(n) => format!("simple({n})"),
        Value::Float(f, _) => format!("f{:016x}", f.to_bits()),
    }
}

fn expected_head_len(item: &Item) -> usize {
    match (&item.value, item.width) {
        (Value::Float(_, FloatWidth::F16), _) => 3,
        (Value::Float(_, FloatWidth::F32), _) => 5,
        (Value::Float(_, FloatWidth::F64), _) => 9,
        (Value::Bool(_) | Value::Null | Value::Undefined, _) => 1,
        (Value::Simple(n), _) => {
            if *n < 24 {
                1
            } else {
                2
            }
        }
        (_, Width::Immediate | Width::Indefinite) => 1,
        (_, Width::U8) => 2,
        (_, Width::U16) => 3,
        (_, Width::U32) => 5,
        (_, Width::U64) => 9,
    }
}

fn major(item: &Item) -> u8 {
    match &item.value {
        Value::Uint(_) => 0,
        Value::Nint(_) => 1,
        Value::Bytes(_) => 2,
        Value::Text(_) => 3,
        Value::Array(_) => 4,
        Value::Map(_) => 5,
        Value::Tag(..) => 6,
        _ => 7,
    }
}

/// Checks span invariants of a decoded item (recursively) against `input`:
/// the head length matches the recorded width, the initial byte has the
/// right major type, children are contiguous and inside their parent, an
/// indefinite item ends with a break byte, and each sub-item re-encodes (in
/// Preserve mode) to exactly the bytes its span covers.
pub fn check_spans(item: &Item, input: &[u8]) -> Result<(), String> {
    let s = item.span;
    let at = |what: &str| format!("{what} at span {s:?} ({})", diag(item));
    if !(s.start < s.end && s.start + s.head_len <= s.end && s.end <= input.len()) {
        return Err(at("span out of range"));
    }
    if s.head_len != expected_head_len(item) {
        return Err(at(&format!(
            "head_len {} but width implies {}",
            s.head_len,
            expected_head_len(item)
        )));
    }
    if input[s.start] >> 5 != major(item) {
        return Err(at("initial byte has the wrong major type"));
    }
    let own = &input[s.start..s.end];
    if encode(item, EncodeMode::Preserve) != own {
        return Err(at("Preserve encoding differs from the spanned bytes"));
    }
    let indef = item.width == Width::Indefinite;
    let mut cursor = s.start + s.head_len;
    let mut children: Vec<&Item> = Vec::new();
    match &item.value {
        Value::Array(a) => children.extend(a.iter()),
        Value::Map(m) => m.iter().for_each(|(k, v)| {
            children.push(k);
            children.push(v);
        }),
        Value::Tag(_, inner) => children.push(inner),
        Value::Bytes(_) | Value::Text(_) if indef => children.extend(item.chunks.iter()),
        Value::Bytes(b) => cursor += b.len(),
        Value::Text(t) => cursor += t.len(),
        _ => {}
    }
    for child in children {
        if child.span.start != cursor {
            return Err(at(&format!(
                "child {} starts at {} instead of {cursor}",
                diag(child),
                child.span.start
            )));
        }
        check_spans(child, input)?;
        cursor = child.span.end;
    }
    if indef {
        if input.get(cursor) != Some(&0xff) {
            return Err(at(&format!("no break byte at {cursor}")));
        }
        cursor += 1;
    }
    if cursor != s.end {
        return Err(at(&format!(
            "content ends at {cursor}, span ends at {}",
            s.end
        )));
    }
    Ok(())
}

/// Looks up a text key in a decoded map.
pub fn get<'i, 'a>(map: &'i Item<'a>, key: &str) -> Option<&'i Item<'a>> {
    match &map.value {
        Value::Map(m) => m
            .iter()
            .find(|(k, _)| matches!(&k.value, Value::Text(t) if t == key))
            .map(|(_, v)| v),
        _ => None,
    }
}

/// Decodes `hex_in`, asserts the Preserve round trip and span invariants, and
/// returns the item's `diag` rendering.
pub fn decode_diag(hex_in: &str) -> String {
    let input = h(hex_in);
    let item =
        tokenator_cbor::decode(&input).unwrap_or_else(|e| panic!("decode {hex_in} failed: {e}"));
    assert_eq!(
        hex(&encode(&item, EncodeMode::Preserve)),
        hex(&input),
        "Preserve round trip of {hex_in}"
    );
    check_spans(&item, &input).unwrap_or_else(|e| panic!("{hex_in}: {e}"));
    diag(&item)
}

/// Decodes `hex_in` and returns its deterministic encoding as hex.
pub fn det(hex_in: &str) -> String {
    let input = h(hex_in);
    let item =
        tokenator_cbor::decode(&input).unwrap_or_else(|e| panic!("decode {hex_in} failed: {e}"));
    hex(&encode(&item, EncodeMode::Deterministic))
}
