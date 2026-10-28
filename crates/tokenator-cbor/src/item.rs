//! The CBOR data model: [`Item`], [`Value`], and the encoding details that
//! make an exact round trip possible.

use std::borrow::Cow;

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
        let _ = arg;
        unimplemented!()
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
    /// definite length, the shortest exact float width, and a default span.
    pub fn new(value: Value<'a>) -> Item<'a> {
        let _ = value;
        unimplemented!()
    }

    /// An integer item (`Uint` or `Nint`), preferred width.
    pub fn int(n: i64) -> Item<'a> {
        let _ = n;
        unimplemented!()
    }

    /// A byte string item, preferred width.
    pub fn bytes(b: impl Into<Cow<'a, [u8]>>) -> Item<'a> {
        let _ = b.into();
        unimplemented!()
    }

    /// A text string item, preferred width.
    pub fn text(s: impl Into<Cow<'a, str>>) -> Item<'a> {
        let _ = s.into();
        unimplemented!()
    }

    /// An array item, preferred (definite) length.
    pub fn array(items: Vec<Item<'a>>) -> Item<'a> {
        let _ = items;
        unimplemented!()
    }

    /// A map item, preferred (definite) length, entries in the given order.
    pub fn map(entries: Vec<(Item<'a>, Item<'a>)>) -> Item<'a> {
        let _ = entries;
        unimplemented!()
    }

    /// A tagged item, preferred tag-number width.
    pub fn tag(tag: u64, item: Item<'a>) -> Item<'a> {
        let _ = (tag, item);
        unimplemented!()
    }

    /// A float item with the shortest width that represents `f` exactly.
    pub fn float(f: f64) -> Item<'a> {
        let _ = f;
        unimplemented!()
    }

    /// A simple value. 20..=23 become `Bool`/`Null`/`Undefined`.
    pub fn simple(n: u8) -> Item<'a> {
        let _ = n;
        unimplemented!()
    }

    /// An indefinite-length byte or text string built from definite-length
    /// chunks, which must all be `Bytes` or all be `Text`. `value` becomes
    /// their concatenation. With no chunks, an empty indefinite byte string.
    pub fn indefinite_string(chunks: Vec<Item<'a>>) -> Item<'a> {
        let _ = chunks;
        unimplemented!()
    }

    /// Replaces the recorded argument width, e.g. to produce a non-preferred
    /// encoding on purpose (EDN encoding indicators `_0`..`_3`, `_i`).
    pub fn with_width(self, width: Width) -> Item<'a> {
        let _ = width;
        unimplemented!()
    }

    /// Copies all borrowed data so the item no longer borrows the input.
    pub fn into_owned(self) -> Item<'static> {
        unimplemented!()
    }
}
