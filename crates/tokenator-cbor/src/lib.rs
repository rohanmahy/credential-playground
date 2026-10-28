//! Span-preserving, zero-copy CBOR decoder/encoder.
//!
//! [`decode`] turns bytes into an [`Item`] tree that borrows from the input
//! and records every encoding choice (argument widths, indefinite lengths,
//! string chunks, float widths, map arrival order), so
//! `encode(&item, EncodeMode::Preserve)` gives back the input exactly.
//! `EncodeMode::Deterministic` produces RFC 8949 §4.2.1 encoding instead.
//! [`preferred_findings`] and [`deterministic_findings`] locate encodings that
//! are not preferred or not deterministic, with the bytes that would fix them.
//!
//! ```
//! use tokenator_cbor::{decode, encode, EncodeMode, preferred_findings};
//!
//! let input = [0x18, 0x01]; // 1, with a needlessly long argument
//! let item = decode(&input)?;
//! assert_eq!(encode(&item, EncodeMode::Preserve), input);
//! assert_eq!(encode(&item, EncodeMode::Deterministic), [0x01]);
//! assert_eq!(preferred_findings(&item)[0].preferred_bytes, [0x01]);
//! # Ok::<(), tokenator_cbor::DecodeError>(())
//! ```
//!
//! Editing a decoded document changes only the edited bytes, and the
//! findings say exactly which byte ranges to replace:
//!
//! ```
//! use std::borrow::Cow;
//! use tokenator_cbor::{
//!     decode, deterministic_findings, encode, EncodeMode, FindingKind, Value,
//! };
//!
//! // {_ "b": 1, "a": h'00'}: indefinite length, keys out of order
//! let input = [0xbf, 0x61, 0x62, 0x01, 0x61, 0x61, 0x41, 0x00, 0xff];
//! let mut item = decode(&input)?;
//!
//! let kinds: Vec<_> = deterministic_findings(&item).iter().map(|f| f.kind).collect();
//! assert_eq!(kinds, [FindingKind::IndefiniteLength, FindingKind::MapKeyOrder]);
//!
//! // Replace the value of "a"; everything else is re-encoded verbatim.
//! let Value::Map(entries) = &mut item.value else { unreachable!() };
//! entries[1].1.value = Value::Bytes(Cow::Borrowed(&[0xff]));
//! assert_eq!(
//!     encode(&item, EncodeMode::Preserve),
//!     [0xbf, 0x61, 0x62, 0x01, 0x61, 0x61, 0x41, 0xff, 0xff]
//! );
//! assert_eq!(
//!     encode(&item, EncodeMode::Deterministic),
//!     [0xa2, 0x61, 0x61, 0x41, 0xff, 0x61, 0x62, 0x01]
//! );
//! # Ok::<(), tokenator_cbor::DecodeError>(())
//! ```

mod decode;
mod encode;
mod error;
mod findings;
mod float;
mod item;

pub use decode::{MAX_DEPTH, decode, decode_seq};
pub use encode::{EncodeMode, encode};
pub use error::{DecodeError, DecodeErrorKind};
pub use findings::{EncodingFinding, FindingKind, deterministic_findings, preferred_findings};
pub use item::{FloatWidth, Item, Span, Value, Width};
