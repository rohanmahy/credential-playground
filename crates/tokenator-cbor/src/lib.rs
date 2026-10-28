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
//! ```ignore
//! use tokenator_cbor::{decode, encode, EncodeMode, preferred_findings};
//!
//! let input = [0x18, 0x01]; // 1, with a needlessly long argument
//! let item = decode(&input)?;
//! assert_eq!(encode(&item, EncodeMode::Preserve), input);
//! assert_eq!(encode(&item, EncodeMode::Deterministic), [0x01]);
//! assert_eq!(preferred_findings(&item)[0].preferred_bytes, [0x01]);
//! ```

// Skeleton only: the implementation replaces these bodies.
#![allow(clippy::unimplemented)]

mod decode;
mod encode;
mod error;
mod findings;
mod item;

pub use decode::{MAX_DEPTH, decode, decode_seq};
pub use encode::{EncodeMode, encode};
pub use error::{DecodeError, DecodeErrorKind};
pub use findings::{EncodingFinding, FindingKind, deterministic_findings, preferred_findings};
pub use item::{FloatWidth, Item, Span, Value, Width};
