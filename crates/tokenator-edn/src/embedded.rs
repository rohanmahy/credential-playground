//! Decoding a byte string the user picked by hand (issue #15).

use std::ops::Range;

use tokenator_cbor::{DecodeError, Item};

/// Something odd about manually decoded embedded CBOR.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EmbeddedWarning {
    /// The first data item ended before the byte string did: `len` bytes
    /// starting at absolute offset `offset` were not decoded.
    TrailingBytes {
        /// Absolute offset (in the outer input) of the first byte not decoded.
        offset: usize,
        /// Number of bytes not decoded.
        len: usize,
    },
}

/// The result of [`decode_embedded`].
#[derive(Clone, Debug, PartialEq)]
pub struct EmbeddedView<'a> {
    /// The first data item of the content. Its spans (and those of all its
    /// children) are absolute offsets into the outer input, so
    /// [`print`](crate::print) reports CBOR spans and
    /// [`annotated_hex`](crate::annotated_hex) (given the outer input) rows
    /// that line up with the original bytes.
    pub item: Item<'a>,
    /// Warnings, such as trailing bytes.
    pub warnings: Vec<EmbeddedWarning>,
}

/// Decodes the content of a byte string as embedded CBOR, for when a user
/// explicitly asks to decode a byte string that the format does not mark
/// as CBOR.
///
/// `content` is the byte string's content within `outer` (for a decoded
/// definite-length byte string with span `s`, that is
/// `s.start + s.head_len..s.end`). For content that is not contiguous in the
/// input (an indefinite-length byte string), pass the concatenation as
/// `outer` and `0..len` as `content`.
///
/// The first data item is decoded. If bytes follow it, they are reported as
/// [`EmbeddedWarning::TrailingBytes`] rather than as an error. Empty,
/// truncated, or malformed content is an error, with an absolute offset; so
/// is a `content` range outside `outer` (`UnexpectedEof` at `outer.len()`).
#[allow(unused_variables)] // skeleton until issue #15 is implemented
pub fn decode_embedded(
    outer: &[u8],
    content: Range<usize>,
) -> Result<EmbeddedView<'_>, DecodeError> {
    unimplemented!("issue #15 manual embedded-CBOR decoding")
}
