//! CBOR Extended Diagnostic Notation parser and printer.
//!
//! Implements draft-ietf-cbor-edn-literals-28 ("Concise Diagnostic Notation").
//! EDN text parses into a [`tokenator_cbor::Item`] and items print back to
//! EDN. Encoding indicators (`_i`, `_0`..`_3`, `_`) carry every encoding
//! choice, so for a decoded item
//! `encode(&parse(&print(&item, &PrintOptions::default()).text)?, Preserve)`
//! gives back the original bytes.
//!
//! - [`parse`], [`parse_seq`], [`parse_with`]: EDN text to items, with
//!   app-extensions ([`AppExtension`], [`Extensions`]) and warnings.
//! - [`print`]: items to EDN text plus a [`SpanMap`] that maps each node's
//!   [`Path`] to its text range, line range, and CBOR byte span.
//! - [`annotated_hex`]: one [`HexRow`] per encoded data item, aligned with
//!   the printed lines by [`Path`].
//! - [`datetime`]: pure conversions for the date/time chit.
//!
//! ```ignore
//! use tokenator_cbor::{decode, encode, EncodeMode};
//! use tokenator_edn::{parse, print, PrintOptions};
//!
//! let bytes = [0x82, 0x18, 0x01, 0x9f, 0xff]; // [1_0, [_ ]]
//! let item = decode(&bytes)?;
//! let rendered = print(&item, &PrintOptions::default());
//! assert_eq!(rendered.text, "[1_0, [_ ]]");
//! assert_eq!(encode(&parse(&rendered.text)?, EncodeMode::Preserve), bytes);
//! ```

mod annotate;
pub mod datetime;
mod error;
mod ext;
mod hex;
mod parse;
mod path;
mod print;
mod spans;

pub use annotate::Annotator;
pub use error::{EdnError, EdnErrorKind, Position, Warning, WarningKind};
pub use ext::{AppExtension, ExtError, Extensions, UNRESOLVED_EXTENSION_TAG};
pub use hex::{HexOptions, HexRow, HexRowKind, HexRows, annotated_hex};
pub use parse::{ParseOptions, Parsed, UnknownExtensions, parse, parse_seq, parse_with};
pub use path::{Path, PathParseError, PathSegment};
pub use print::{
    ByteStyle, EmbeddedCbor, EncodingIndicators, IndefiniteStringStyle, Layout, PrintOptions,
    Rendered, print,
};
pub use spans::{NodeSpan, SpanMap};
