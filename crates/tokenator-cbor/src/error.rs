//! Decode errors.

use std::fmt;

/// Why decoding failed, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeError {
    /// Byte offset in the input. For [`DecodeErrorKind::UnexpectedEof`] it is
    /// the start of the innermost item that could not be completed; for the
    /// other kinds it is the offset of the offending initial byte (for
    /// `InvalidUtf8`, the start of the text string or chunk; for
    /// `TrailingBytes`, the first trailing byte).
    pub offset: usize,
    /// What went wrong.
    pub kind: DecodeErrorKind,
}

/// The kinds of malformed or unsupported input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeErrorKind {
    /// The input ended before the item was complete. Also used when a
    /// declared length or element count exceeds the remaining input, so huge
    /// declared lengths never cause allocation.
    UnexpectedEof,
    /// Additional information 28, 29, or 30 (reserved).
    ReservedAdditionalInfo(u8),
    /// Additional information 31 on major type 0, 1, or 6.
    InvalidIndefinite,
    /// A `0xff` break where no indefinite-length item is open.
    UnexpectedBreak,
    /// A chunk of an indefinite-length string that is not a definite-length
    /// string of the same major type.
    InvalidChunk,
    /// A text string (or text chunk) that is not valid UTF-8.
    InvalidUtf8,
    /// A two-byte simple value (`0xf8 nn`) with `nn < 32`.
    InvalidSimple(u8),
    /// Arrays, maps, and tags nested deeper than [`MAX_DEPTH`](crate::MAX_DEPTH).
    DepthLimit,
    /// [`decode`](crate::decode) found bytes after the single item.
    TrailingBytes,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} at offset {}", self.kind, self.offset)
    }
}

impl std::error::Error for DecodeError {}
