//! Span-preserving, zero-copy decoding.

use crate::{DecodeError, Item};

/// Maximum nesting of arrays, maps, and tags. An item nested inside
/// `MAX_DEPTH` containers decodes; one more level is
/// [`DecodeErrorKind::DepthLimit`](crate::DecodeErrorKind::DepthLimit).
pub const MAX_DEPTH: usize = 1024;

/// Decodes exactly one data item. Bytes after it are an error
/// ([`TrailingBytes`](crate::DecodeErrorKind::TrailingBytes)).
///
/// Only well-formedness and UTF-8 validity are checked. Tags are not
/// interpreted, duplicate map keys are kept, and unassigned simple values are
/// accepted. Never panics, whatever the input.
pub fn decode(bytes: &[u8]) -> Result<Item<'_>, DecodeError> {
    let _ = bytes;
    unimplemented!()
}

/// Decodes a CBOR sequence (RFC 8742): zero or more items back to back.
/// Empty input gives an empty vector.
pub fn decode_seq(bytes: &[u8]) -> Result<Vec<Item<'_>>, DecodeError> {
    let _ = bytes;
    unimplemented!()
}
