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
//! ```
//! use tokenator_cbor::{decode, encode, EncodeMode};
//! use tokenator_edn::{parse, print, PrintOptions};
//!
//! let bytes = [0x82, 0x18, 0x01, 0x9f, 0xff]; // [1_0, [_ ]]
//! let item = decode(&bytes)?;
//! let rendered = print(&item, &PrintOptions::default());
//! assert_eq!(rendered.text, "[1_0, [_ ]]");
//! assert_eq!(encode(&parse(&rendered.text)?, EncodeMode::Preserve), bytes);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! A custom app-extension, unknown prefixes kept as opaque values with a
//! warning, and printing them back:
//!
//! ```
//! use tokenator_cbor::{encode, EncodeMode, Item, Value};
//! use tokenator_edn::{
//!     parse_with, print, AppExtension, ExtError, Extensions, ParseOptions, PrintOptions,
//!     WarningKind,
//! };
//!
//! /// `rev'abc'` is the text string "cba".
//! struct Rev;
//!
//! impl AppExtension for Rev {
//!     fn name(&self) -> &str {
//!         "rev"
//!     }
//!
//!     fn evaluate(&self, args: &[Item<'static>], _upper: bool) -> Result<Item<'static>, ExtError> {
//!         match args {
//!             [Item { value: Value::Text(t), .. }] => Ok(Item::text(t.chars().rev().collect::<String>())),
//!             _ => Err(ExtError("expected one text string".into())),
//!         }
//!     }
//! }
//!
//! let mut extensions = Extensions::builtin();
//! extensions.register(Box::new(Rev));
//! let options = ParseOptions { extensions, ..ParseOptions::default() };
//! let parsed = parse_with("[rev'abc', cri'https://example.com']", &options)?;
//! assert_eq!(parsed.warnings[0].kind, WarningKind::UnknownExtension("cri".into()));
//!
//! let item = &parsed.items[0];
//! let text = print(item, &PrintOptions::new()).text;
//! assert_eq!(text, r#"["cba", cri'https://example.com']"#);
//! let Value::Array(items) = &item.value else { unreachable!() };
//! assert_eq!(encode(&items[1], EncodeMode::Preserve)[..3], [0xd9, 0x03, 0xe7]); // tag 999
//! # Ok::<(), tokenator_edn::EdnError>(())
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
