//! Span-preserving, zero-copy decoding.
//!
//! The decoder is iterative: open arrays, maps, and tags live on an explicit
//! stack, so nesting depth costs heap, not call stack.

use std::borrow::Cow;

use crate::{DecodeError, DecodeErrorKind, FloatWidth, Item, Span, Value, Width, float};

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
///
/// ```
/// use tokenator_cbor::{decode, Value};
///
/// let item = decode(&[0x82, 0x01, 0x61, 0x61])?; // [1, "a"]
/// let Value::Array(items) = &item.value else { unreachable!() };
/// assert_eq!(items[1].value, Value::Text("a".into()));
/// assert_eq!((items[1].span.start, items[1].span.end), (2, 4));
/// # Ok::<(), tokenator_cbor::DecodeError>(())
/// ```
pub fn decode(bytes: &[u8]) -> Result<Item<'_>, DecodeError> {
    let mut d = Decoder {
        input: bytes,
        pos: 0,
    };
    let item = d.item()?;
    if d.pos < bytes.len() {
        return Err(err(d.pos, DecodeErrorKind::TrailingBytes));
    }
    Ok(item)
}

/// Decodes a CBOR sequence (RFC 8742): zero or more items back to back.
/// Empty input gives an empty vector.
pub fn decode_seq(bytes: &[u8]) -> Result<Vec<Item<'_>>, DecodeError> {
    let mut d = Decoder {
        input: bytes,
        pos: 0,
    };
    let mut items = Vec::new();
    while d.pos < bytes.len() {
        items.push(d.item()?);
    }
    Ok(items)
}

fn err(offset: usize, kind: DecodeErrorKind) -> DecodeError {
    DecodeError { offset, kind }
}

/// A decoded head: initial byte plus argument.
struct Head {
    start: usize,
    major: u8,
    /// Additional information (low 5 bits of the initial byte).
    ai: u8,
    /// The argument; 0 for ai 31.
    arg: u64,
    width: Width,
}

/// An array, map, or tag whose content is still being read.
struct Frame<'a> {
    start: usize,
    head_len: usize,
    width: Width,
    kind: FrameKind<'a>,
}

enum FrameKind<'a> {
    /// `remaining` is `None` for an indefinite-length array.
    Array {
        items: Vec<Item<'a>>,
        remaining: Option<u64>,
    },
    /// `remaining` counts entries; `key` holds a key awaiting its value.
    Map {
        entries: Vec<(Item<'a>, Item<'a>)>,
        key: Option<Item<'a>>,
        remaining: Option<u64>,
    },
    Tag(u64),
}

struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.pos)
    }

    /// Takes `n` bytes, or fails with `UnexpectedEof` at `item_start`.
    fn take(&mut self, n: usize, item_start: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(err(item_start, DecodeErrorKind::UnexpectedEof))?;
        let bytes = self
            .input
            .get(self.pos..end)
            .ok_or(err(item_start, DecodeErrorKind::UnexpectedEof))?;
        self.pos = end;
        Ok(bytes)
    }

    /// Takes `len` bytes of string content. A length beyond the remaining
    /// input fails before anything is allocated.
    fn content(&mut self, len: u64, item_start: usize) -> Result<&'a [u8], DecodeError> {
        let len =
            usize::try_from(len).map_err(|_| err(item_start, DecodeErrorKind::UnexpectedEof))?;
        self.take(len, item_start)
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    /// Reads a head. Rejects reserved additional information; ai 31 is
    /// returned as `Width::Indefinite` for the caller to judge.
    fn head(&mut self) -> Result<Head, DecodeError> {
        let start = self.pos;
        let [initial] = *self.take(1, start)? else {
            return Err(err(start, DecodeErrorKind::UnexpectedEof));
        };
        let major = initial >> 5;
        let ai = initial & 0x1f;
        let (arg, width) = match ai {
            0..=23 => (u64::from(ai), Width::Immediate),
            24 => (self.uint::<1>(start)?, Width::U8),
            25 => (self.uint::<2>(start)?, Width::U16),
            26 => (self.uint::<4>(start)?, Width::U32),
            27 => (self.uint::<8>(start)?, Width::U64),
            28..=30 => return Err(err(start, DecodeErrorKind::ReservedAdditionalInfo(ai))),
            _ => (0, Width::Indefinite),
        };
        Ok(Head {
            start,
            major,
            ai,
            arg,
            width,
        })
    }

    /// Reads an `N`-byte big-endian argument.
    fn uint<const N: usize>(&mut self, item_start: usize) -> Result<u64, DecodeError> {
        let bytes = self.take(N, item_start)?;
        Ok(bytes.iter().fold(0, |acc, b| (acc << 8) | u64::from(*b)))
    }

    /// Decodes one complete item starting at `self.pos`.
    fn item(&mut self) -> Result<Item<'a>, DecodeError> {
        let mut stack: Vec<Frame<'a>> = Vec::new();
        loop {
            let start = self.pos;
            let Some(byte) = self.peek() else {
                let at = stack.last().map_or(start, |f| f.start);
                return Err(err(at, DecodeErrorKind::UnexpectedEof));
            };

            let mut done = if byte == 0xff {
                // A break closes the innermost indefinite array or map.
                let closable = match stack.last() {
                    Some(Frame {
                        kind: FrameKind::Array { remaining, .. },
                        ..
                    }) => remaining.is_none(),
                    Some(Frame {
                        kind: FrameKind::Map { remaining, key, .. },
                        ..
                    }) => remaining.is_none() && key.is_none(),
                    _ => false,
                };
                let frame = match stack.pop() {
                    Some(frame) if closable => frame,
                    _ => return Err(err(start, DecodeErrorKind::UnexpectedBreak)),
                };
                self.pos += 1;
                self.finish(frame)
            } else {
                if stack.len() > MAX_DEPTH {
                    let at = stack.last().map_or(start, |f| f.start);
                    return Err(err(at, DecodeErrorKind::DepthLimit));
                }
                match self.start_item()? {
                    Started::Done(item) => item,
                    Started::Open(frame) => {
                        stack.push(frame);
                        continue;
                    }
                }
            };

            // Hand the finished item to its parent, closing every parent that
            // it completes.
            loop {
                let Some(top) = stack.last_mut() else {
                    return Ok(done);
                };
                let complete = match &mut top.kind {
                    FrameKind::Array { items, remaining } => {
                        items.push(done);
                        count_down(remaining)
                    }
                    FrameKind::Map {
                        entries,
                        key,
                        remaining,
                    } => match key.take() {
                        None => {
                            *key = Some(done);
                            false
                        }
                        Some(k) => {
                            entries.push((k, done));
                            count_down(remaining)
                        }
                    },
                    FrameKind::Tag(tag) => {
                        let tag = *tag;
                        let span = Span {
                            start: top.start,
                            end: done.span.end,
                            head_len: top.head_len,
                        };
                        let width = top.width;
                        stack.pop();
                        done = Item {
                            value: Value::Tag(tag, Box::new(done)),
                            span,
                            width,
                            chunks: Vec::new(),
                        };
                        continue;
                    }
                };
                if !complete {
                    break;
                }
                let Some(frame) = stack.pop() else {
                    break;
                };
                done = self.finish(frame);
            }
        }
    }

    /// Builds the item for a closed frame that ends at `self.pos`.
    fn finish(&self, frame: Frame<'a>) -> Item<'a> {
        let value = match frame.kind {
            FrameKind::Array { items, .. } => Value::Array(items),
            FrameKind::Map { entries, .. } => Value::Map(entries),
            // A tag is completed as soon as its content is; never here.
            FrameKind::Tag(_) => Value::Null,
        };
        Item {
            value,
            span: Span {
                start: frame.start,
                end: self.pos,
                head_len: frame.head_len,
            },
            width: frame.width,
            chunks: Vec::new(),
        }
    }

    /// Reads a head and either the whole item (scalars and strings) or the
    /// opening of a container or tag.
    fn start_item(&mut self) -> Result<Started<'a>, DecodeError> {
        let head = self.head()?;
        let start = head.start;
        let head_len = self.pos - start;
        let indefinite = head.width == Width::Indefinite;
        let leaf = |value, end| {
            Started::Done(Item {
                value,
                span: Span {
                    start,
                    end,
                    head_len,
                },
                width: head.width,
                chunks: Vec::new(),
            })
        };
        let open = |kind| {
            Started::Open(Frame {
                start,
                head_len,
                width: head.width,
                kind,
            })
        };
        Ok(match head.major {
            0 | 1 | 6 if indefinite => {
                return Err(err(start, DecodeErrorKind::InvalidIndefinite));
            }
            0 => leaf(Value::Uint(head.arg), self.pos),
            1 => leaf(Value::Nint(head.arg), self.pos),
            2 | 3 if indefinite => return self.indefinite_string(head).map(Started::Done),
            2 => {
                let b = self.content(head.arg, start)?;
                leaf(Value::Bytes(Cow::Borrowed(b)), self.pos)
            }
            3 => {
                let b = self.content(head.arg, start)?;
                let t =
                    std::str::from_utf8(b).map_err(|_| err(start, DecodeErrorKind::InvalidUtf8))?;
                leaf(Value::Text(Cow::Borrowed(t)), self.pos)
            }
            4 | 5 if head.arg == 0 && !indefinite => {
                let value = if head.major == 4 {
                    Value::Array(Vec::new())
                } else {
                    Value::Map(Vec::new())
                };
                leaf(value, self.pos)
            }
            4 => {
                let remaining = count(&head);
                let items = self.capacity(remaining, 1);
                open(FrameKind::Array { items, remaining })
            }
            5 => {
                let remaining = count(&head);
                let entries = self.capacity(remaining, 2);
                open(FrameKind::Map {
                    entries,
                    key: None,
                    remaining,
                })
            }
            6 => open(FrameKind::Tag(head.arg)),
            _ => leaf(self.simple_or_float(&head)?, self.pos),
        })
    }

    /// An empty vector with room for `count` elements of at least
    /// `min_bytes` each, but never more than the remaining input can hold:
    /// a declared count is not trusted.
    fn capacity<T>(&self, count: Option<u64>, min_bytes: usize) -> Vec<T> {
        let fit = self.remaining() / min_bytes;
        let n = count.map_or(0, |n| usize::try_from(n).unwrap_or(usize::MAX));
        Vec::with_capacity(n.min(fit))
    }

    fn simple_or_float(&mut self, head: &Head) -> Result<Value<'a>, DecodeError> {
        let arg = head.arg;
        Ok(match head.ai {
            20 => Value::Bool(false),
            21 => Value::Bool(true),
            22 => Value::Null,
            23 => Value::Undefined,
            24 => {
                let n = u8::try_from(arg).unwrap_or(u8::MAX);
                if n < 32 {
                    return Err(err(head.start, DecodeErrorKind::InvalidSimple(n)));
                }
                Value::Simple(n)
            }
            25 => Value::Float(
                float::from_f16(u16::try_from(arg).unwrap_or(u16::MAX)),
                FloatWidth::F16,
            ),
            26 => Value::Float(
                float::from_f32(u32::try_from(arg).unwrap_or(u32::MAX)),
                FloatWidth::F32,
            ),
            27 => Value::Float(f64::from_bits(arg), FloatWidth::F64),
            // ai 31 (break) is handled by the caller; 0..=19 remain.
            _ => Value::Simple(head.ai),
        })
    }

    /// Reads the chunks of an indefinite-length string up to its break.
    fn indefinite_string(&mut self, head: Head) -> Result<Item<'a>, DecodeError> {
        let start = head.start;
        let mut chunks = Vec::new();
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            let chunk_start = self.pos;
            let Some(initial) = self.peek() else {
                return Err(err(start, DecodeErrorKind::UnexpectedEof));
            };
            if initial == 0xff {
                self.pos += 1;
                break;
            }
            if initial >> 5 != head.major || initial & 0x1f == 31 {
                return Err(err(chunk_start, DecodeErrorKind::InvalidChunk));
            }
            let chunk_head = self.head()?;
            let head_len = self.pos - chunk_start;
            let content = self.content(chunk_head.arg, chunk_start)?;
            let value = if head.major == 2 {
                Value::Bytes(Cow::Borrowed(content))
            } else {
                let t = std::str::from_utf8(content)
                    .map_err(|_| err(chunk_start, DecodeErrorKind::InvalidUtf8))?;
                Value::Text(Cow::Borrowed(t))
            };
            bytes.extend_from_slice(content);
            chunks.push(Item {
                value,
                span: Span {
                    start: chunk_start,
                    end: self.pos,
                    head_len,
                },
                width: chunk_head.width,
                chunks: Vec::new(),
            });
        }
        let value = if head.major == 2 {
            Value::Bytes(Cow::Owned(bytes))
        } else {
            // Every chunk is valid UTF-8, so the concatenation is too.
            let text =
                String::from_utf8(bytes).map_err(|_| err(start, DecodeErrorKind::InvalidUtf8))?;
            Value::Text(Cow::Owned(text))
        };
        Ok(Item {
            value,
            span: Span {
                start,
                end: self.pos,
                head_len: 1,
            },
            width: Width::Indefinite,
            chunks,
        })
    }
}

enum Started<'a> {
    Done(Item<'a>),
    Open(Frame<'a>),
}

/// Decrements a definite count; returns whether the container is complete.
fn count_down(remaining: &mut Option<u64>) -> bool {
    match remaining {
        Some(n) => {
            *n = n.saturating_sub(1);
            *n == 0
        }
        None => false,
    }
}

/// The element count of an array or map head (`None` if indefinite).
fn count(head: &Head) -> Option<u64> {
    (head.width != Width::Indefinite).then_some(head.arg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncodeMode, deterministic_findings, encode};

    /// Decode, encode, findings, `into_owned`, and drop at `MAX_DEPTH` fit
    /// in the default 2 MiB test thread stack in debug builds, and in the
    /// 1 MiB that WASM gets in release builds.
    #[test]
    fn max_depth_fits_in_a_small_stack() {
        let run = || {
            let shapes: [(&[u8], &[u8]); 4] = [
                (&[0x81], &[]),
                (&[0x9f], &[0xff]),
                (&[0xa1], &[0x00]),
                (&[0xc1], &[]),
            ];
            for (prefix, suffix) in shapes {
                let mut input = prefix.repeat(MAX_DEPTH);
                input.push(0x00);
                input.extend(suffix.repeat(MAX_DEPTH));
                let item = decode(&input).unwrap();
                assert_eq!(encode(&item, EncodeMode::Preserve), input);
                let _ = encode(&item, EncodeMode::Deterministic);
                let _ = deterministic_findings(&item);
                let owned = item.into_owned();
                assert_eq!(encode(&owned, EncodeMode::Preserve), input);
            }
        };
        let stack = if cfg!(debug_assertions) {
            2 << 20
        } else {
            1 << 20
        };
        std::thread::Builder::new()
            .stack_size(stack)
            .spawn(run)
            .unwrap()
            .join()
            .unwrap();
    }
}
