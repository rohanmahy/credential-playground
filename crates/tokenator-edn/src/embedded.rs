//! Decoding a byte string the user picked by hand (issue #15).

use std::ops::Range;

use tokenator_cbor::{DecodeError, DecodeErrorKind, Item, Value, decode};

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
pub fn decode_embedded(
    outer: &[u8],
    content: Range<usize>,
) -> Result<EmbeddedView<'_>, DecodeError> {
    let Range { start, end } = content;
    let Some(bytes) = outer.get(start..end) else {
        return Err(DecodeError {
            offset: outer.len(),
            kind: DecodeErrorKind::UnexpectedEof,
        });
    };
    if bytes.is_empty() {
        return Err(DecodeError {
            offset: start,
            kind: DecodeErrorKind::UnexpectedEof,
        });
    }
    let absolute = |e: DecodeError| DecodeError {
        offset: e.offset + start,
        kind: e.kind,
    };
    // The decoder reports where the first item ended; decode just that.
    let (mut item, warnings) = match decode(bytes) {
        Ok(item) => (item, Vec::new()),
        Err(DecodeError {
            offset,
            kind: DecodeErrorKind::TrailingBytes,
        }) => {
            let first = bytes.get(..offset).unwrap_or_default();
            let item = decode(first).map_err(absolute)?;
            let warning = EmbeddedWarning::TrailingBytes {
                offset: start + offset,
                len: bytes.len() - offset,
            };
            (item, vec![warning])
        }
        Err(e) => return Err(absolute(e)),
    };
    shift_spans(&mut item, start);
    Ok(EmbeddedView { item, warnings })
}

/// Adds `by` to the spans of `item` and all its descendants (iteratively).
fn shift_spans(item: &mut Item<'_>, by: usize) {
    let mut stack = vec![item];
    while let Some(it) = stack.pop() {
        it.span.start += by;
        it.span.end += by;
        match &mut it.value {
            Value::Array(items) => stack.extend(items.iter_mut()),
            Value::Map(entries) => {
                for (k, v) in entries {
                    stack.push(k);
                    stack.push(v);
                }
            }
            Value::Tag(_, inner) => stack.push(inner),
            _ => {}
        }
        stack.extend(it.chunks.iter_mut());
    }
}
