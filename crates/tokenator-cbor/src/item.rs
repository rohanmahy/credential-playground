//! The CBOR data model: [`Item`], [`Value`], and the encoding details that
//! make an exact round trip possible.

use std::borrow::Cow;

use crate::float;

/// Byte range of an encoded data item within the decoder's input.
///
/// `start..end` covers the whole item: its head, its content, any nested
/// items, and (for indefinite-length items) the final `0xff` break byte.
/// `head_len` is the length of the RFC 8949 *head*: the initial byte plus the
/// argument bytes. For integers, simple values, and floats the head is the
/// whole item, so `head_len == end - start`. For a tag, the head is only the
/// tag number; the tagged item has its own span.
///
/// Items built programmatically (not decoded) carry `Span::default()`, which
/// is all zeros and has no meaning.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Span {
    /// Offset of the initial byte.
    pub start: usize,
    /// Offset one past the last byte of the item.
    pub end: usize,
    /// Length of the head (initial byte + argument bytes).
    pub head_len: usize,
}

/// How the argument of a head was (or should be) encoded.
///
/// RFC 8949 allows any argument to be encoded with more bytes than needed;
/// [`EncodeMode::Preserve`](crate::EncodeMode::Preserve) reproduces the width
/// recorded here. For floats the width lives in [`Value::Float`] instead and
/// this field is ignored; for simple values, booleans, null, and undefined it
/// is derived from the value and ignored by the encoder.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Width {
    /// Argument in the low 5 bits of the initial byte (values 0..=23).
    #[default]
    Immediate,
    /// Additional information 24: one argument byte follows.
    U8,
    /// Additional information 25: two argument bytes follow.
    U16,
    /// Additional information 26: four argument bytes follow.
    U32,
    /// Additional information 27: eight argument bytes follow.
    U64,
    /// Additional information 31: indefinite length. Only meaningful for
    /// byte strings, text strings, arrays, and maps.
    Indefinite,
}

impl Width {
    /// The shortest width that can hold `arg` (the preferred serialization).
    pub fn preferred_for(arg: u64) -> Width {
        match arg {
            0..=23 => Width::Immediate,
            24..=0xff => Width::U8,
            0x100..=0xffff => Width::U16,
            0x1_0000..=0xffff_ffff => Width::U32,
            _ => Width::U64,
        }
    }

    /// Whether an argument of `arg` can be written with this width.
    /// `Indefinite` holds no argument, so it never fits.
    pub(crate) fn fits(self, arg: u64) -> bool {
        match self {
            Width::Immediate => arg < 24,
            Width::U8 => arg <= 0xff,
            Width::U16 => arg <= 0xffff,
            Width::U32 => arg <= 0xffff_ffff,
            Width::U64 => true,
            Width::Indefinite => false,
        }
    }
}

/// Encoded width of a floating-point value (major type 7, ai 25/26/27).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FloatWidth {
    /// IEEE 754 binary16 (`0xf9`).
    F16,
    /// IEEE 754 binary32 (`0xfa`).
    F32,
    /// IEEE 754 binary64 (`0xfb`).
    F64,
}

/// One decoded (or constructed) CBOR data item.
///
/// `value` is the meaning; `span`, `width`, and `chunks` record how it was
/// encoded so that [`encode`](crate::encode) in `Preserve` mode can reproduce
/// the input byte for byte.
#[derive(Clone, Debug, PartialEq)]
pub struct Item<'a> {
    /// The data model value.
    pub value: Value<'a>,
    /// Where the item was found in the input (zeros for built items).
    pub span: Span,
    /// Width of the head argument: the integer value, string/array/map length,
    /// or tag number, or [`Width::Indefinite`].
    ///
    /// If the width is too narrow for the current argument (for example after
    /// the value was edited), the encoder uses the preferred width instead; it
    /// never truncates.
    pub width: Width,
    /// For an indefinite-length byte or text string: the definite-length
    /// chunks as they appeared, each an `Item` holding a `Bytes`/`Text` value.
    /// `value` holds their concatenation. Empty for every other item.
    ///
    /// If the concatenation of the chunks no longer equals `value`, the
    /// encoder ignores the chunks and emits `value` as a single chunk.
    pub chunks: Vec<Item<'a>>,
}

/// The CBOR data model (RFC 8949 §3).
///
/// Definite-length byte and text strings decoded from input borrow from it
/// (`Cow::Borrowed`). Indefinite-length strings are concatenated and owned.
#[derive(Clone, Debug, PartialEq)]
pub enum Value<'a> {
    /// Major type 0: an unsigned integer.
    Uint(u64),
    /// Major type 1: a negative integer. Holds the raw argument `n`; the
    /// value is `-1 - n` (so `Nint(0)` is -1).
    Nint(u64),
    /// Major type 2: a byte string.
    Bytes(Cow<'a, [u8]>),
    /// Major type 3: a UTF-8 text string.
    Text(Cow<'a, str>),
    /// Major type 4: an array.
    Array(Vec<Item<'a>>),
    /// Major type 5: a map, as key/value pairs in arrival order. Duplicate
    /// keys are kept.
    Map(Vec<(Item<'a>, Item<'a>)>),
    /// Major type 6: a tag number and the tagged item. Tags are never
    /// interpreted or validated.
    Tag(u64, Box<Item<'a>>),
    /// Simple values 20 (`false`) and 21 (`true`).
    Bool(bool),
    /// Simple value 22.
    Null,
    /// Simple value 23.
    Undefined,
    /// Any other simple value (0..=19 and 32..=255), assigned or not. Values
    /// 24..=31 are not well-formed and are never produced by the decoder.
    Simple(u8),
    /// A floating-point number and the width it was encoded with.
    ///
    /// Conversions between widths are bit-exact: NaN payloads (including
    /// signaling NaNs) survive decode and Preserve encode unchanged. A
    /// narrower NaN is widened by left-aligning its payload, as IEEE 754
    /// conversion does. If the value is not exactly representable at the
    /// stored width, the encoder uses the shortest width that is.
    Float(f64, FloatWidth),
}

impl<'a> Item<'a> {
    /// Wraps a value with its preferred encoding: the shortest argument width,
    /// definite length, and a default span. A float keeps the width stored in
    /// [`Value::Float`]; use [`Item::float`] for the shortest exact width.
    pub fn new(value: Value<'a>) -> Item<'a> {
        let width = match &value {
            Value::Uint(n) | Value::Nint(n) | Value::Tag(n, _) => Width::preferred_for(*n),
            Value::Bytes(b) => Width::preferred_for(len_u64(b.len())),
            Value::Text(t) => Width::preferred_for(len_u64(t.len())),
            Value::Array(a) => Width::preferred_for(len_u64(a.len())),
            Value::Map(m) => Width::preferred_for(len_u64(m.len())),
            Value::Simple(n) => Width::preferred_for(u64::from(*n)),
            Value::Bool(_) | Value::Null | Value::Undefined => Width::Immediate,
            Value::Float(_, FloatWidth::F16) => Width::U16,
            Value::Float(_, FloatWidth::F32) => Width::U32,
            Value::Float(_, FloatWidth::F64) => Width::U64,
        };
        Item {
            value,
            span: Span::default(),
            width,
            chunks: Vec::new(),
        }
    }

    /// An integer item (`Uint` or `Nint`), preferred width.
    pub fn int(n: i64) -> Item<'a> {
        Item::new(match u64::try_from(n) {
            Ok(u) => Value::Uint(u),
            // -1 - n == !n, which is non-negative here.
            Err(_) => Value::Nint((!n).unsigned_abs()),
        })
    }

    /// A byte string item, preferred width.
    pub fn bytes(b: impl Into<Cow<'a, [u8]>>) -> Item<'a> {
        Item::new(Value::Bytes(b.into()))
    }

    /// A text string item, preferred width.
    pub fn text(s: impl Into<Cow<'a, str>>) -> Item<'a> {
        Item::new(Value::Text(s.into()))
    }

    /// An array item, preferred (definite) length.
    pub fn array(items: Vec<Item<'a>>) -> Item<'a> {
        Item::new(Value::Array(items))
    }

    /// A map item, preferred (definite) length, entries in the given order.
    pub fn map(entries: Vec<(Item<'a>, Item<'a>)>) -> Item<'a> {
        Item::new(Value::Map(entries))
    }

    /// A tagged item, preferred tag-number width.
    pub fn tag(tag: u64, item: Item<'a>) -> Item<'a> {
        Item::new(Value::Tag(tag, Box::new(item)))
    }

    /// A float item with the shortest width that represents `f` exactly.
    pub fn float(f: f64) -> Item<'a> {
        Item::new(Value::Float(f, float::shortest_width(f)))
    }

    /// A simple value. 20..=23 become `Bool`/`Null`/`Undefined`.
    pub fn simple(n: u8) -> Item<'a> {
        Item::new(match n {
            20 => Value::Bool(false),
            21 => Value::Bool(true),
            22 => Value::Null,
            23 => Value::Undefined,
            _ => Value::Simple(n),
        })
    }

    /// An indefinite-length byte or text string built from definite-length
    /// chunks, which must all be `Bytes` or all be `Text`. `value` becomes
    /// their concatenation. With no chunks, an empty indefinite byte string.
    ///
    /// The first chunk decides the string type. Chunks of the other type are
    /// left out of `value`, so the encoder then ignores the chunks.
    pub fn indefinite_string(chunks: Vec<Item<'a>>) -> Item<'a> {
        let value = match chunks.first().map(|c| &c.value) {
            Some(Value::Text(_)) => Value::Text(Cow::Owned(
                chunks
                    .iter()
                    .filter_map(|c| match &c.value {
                        Value::Text(t) => Some(t.as_ref()),
                        _ => None,
                    })
                    .collect(),
            )),
            _ => Value::Bytes(Cow::Owned(
                chunks
                    .iter()
                    .filter_map(|c| match &c.value {
                        Value::Bytes(b) => Some(b.as_ref()),
                        _ => None,
                    })
                    .flatten()
                    .copied()
                    .collect(),
            )),
        };
        Item {
            value,
            span: Span::default(),
            width: Width::Indefinite,
            chunks,
        }
    }

    /// Replaces the recorded argument width, e.g. to produce a non-preferred
    /// encoding on purpose (EDN encoding indicators `_0`..`_3`, `_i`).
    pub fn with_width(self, width: Width) -> Item<'a> {
        Item { width, ..self }
    }

    /// Copies all borrowed data so the item no longer borrows the input.
    ///
    /// Works with an explicit stack, so deep nesting costs heap rather than
    /// call stack.
    pub fn into_owned(self) -> Item<'static> {
        let mut tasks = vec![Task::Visit(self)];
        let mut done: Vec<Item<'static>> = Vec::new();
        while let Some(task) = tasks.pop() {
            match task {
                Task::Visit(item) => {
                    let Item {
                        value,
                        span,
                        width,
                        chunks,
                    } = item;
                    let (shape, children) = match value {
                        Value::Array(items) => (Shape::Array, items),
                        Value::Map(entries) => {
                            let mut flat = Vec::with_capacity(entries.len() * 2);
                            for (k, v) in entries {
                                flat.push(k);
                                flat.push(v);
                            }
                            (Shape::Map, flat)
                        }
                        Value::Tag(tag, inner) => (Shape::Tag(tag), vec![*inner]),
                        leaf => (Shape::Leaf(leaf.into_owned_leaf()), Vec::new()),
                    };
                    tasks.push(Task::Build {
                        shape,
                        span,
                        width,
                        chunks: chunks.len(),
                        children: children.len(),
                    });
                    // Reversed, so they finish in order.
                    tasks.extend(children.into_iter().rev().map(Task::Visit));
                    tasks.extend(chunks.into_iter().rev().map(Task::Visit));
                }
                Task::Build {
                    shape,
                    span,
                    width,
                    chunks,
                    children,
                } => {
                    let mut kids = done.split_off(done.len().saturating_sub(chunks + children));
                    let rest = kids.split_off(chunks.min(kids.len()));
                    let value = match shape {
                        Shape::Leaf(value) => value,
                        Shape::Array => Value::Array(rest),
                        Shape::Map => {
                            let mut entries = Vec::with_capacity(rest.len() / 2);
                            let mut it = rest.into_iter();
                            while let (Some(k), Some(v)) = (it.next(), it.next()) {
                                entries.push((k, v));
                            }
                            Value::Map(entries)
                        }
                        Shape::Tag(tag) => match rest.into_iter().next() {
                            Some(inner) => Value::Tag(tag, Box::new(inner)),
                            None => Value::Null,
                        },
                    };
                    done.push(Item {
                        value,
                        span,
                        width,
                        chunks: kids,
                    });
                }
            }
        }
        done.pop().unwrap_or_else(|| Item::new(Value::Null))
    }
}

/// Work items for [`Item::into_owned`].
enum Task<'a> {
    /// Convert this item: schedule its children, then its `Build`.
    Visit(Item<'a>),
    /// Assemble an item from the last `chunks + children` finished items.
    Build {
        shape: Shape,
        span: Span,
        width: Width,
        chunks: usize,
        children: usize,
    },
}

enum Shape {
    Leaf(Value<'static>),
    Array,
    Map,
    Tag(u64),
}

impl Value<'_> {
    /// An owned copy of a value without child items. Containers become empty.
    fn into_owned_leaf(self) -> Value<'static> {
        match self {
            Value::Uint(n) => Value::Uint(n),
            Value::Nint(n) => Value::Nint(n),
            Value::Bytes(b) => Value::Bytes(Cow::Owned(b.into_owned())),
            Value::Text(t) => Value::Text(Cow::Owned(t.into_owned())),
            Value::Array(_) => Value::Array(Vec::new()),
            Value::Map(_) => Value::Map(Vec::new()),
            Value::Tag(..) | Value::Null => Value::Null,
            Value::Bool(b) => Value::Bool(b),
            Value::Undefined => Value::Undefined,
            Value::Simple(n) => Value::Simple(n),
            Value::Float(f, w) => Value::Float(f, w),
        }
    }
}

/// A length as a CBOR argument. `usize` is at most 64 bits on every
/// supported target.
pub(crate) fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}
