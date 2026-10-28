//! EDN text to items.

use tokenator_cbor::Item;

use crate::error::{EdnError, Warning};
use crate::ext::Extensions;
use crate::spans::SpanMap;

/// What to do with a prefixed literal whose prefix has no extension.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UnknownExtensions {
    /// Keep it as an opaque `999([prefix, [args…]])` value and add a
    /// [`WarningKind::UnknownExtension`](crate::WarningKind::UnknownExtension).
    #[default]
    Opaque,
    /// Fail with [`EdnErrorKind::UnknownExtension`](crate::EdnErrorKind::UnknownExtension).
    Error,
}

/// Options for [`parse_with`].
#[derive(Debug, Default)]
pub struct ParseOptions {
    /// The app-extensions available to prefixed literals.
    pub extensions: Extensions,
    /// Policy for prefixes with no extension.
    pub unknown_extensions: UnknownExtensions,
    /// Parse a CBOR sequence (zero or more items) instead of exactly one item.
    pub sequence: bool,
}

/// The result of [`parse_with`].
#[derive(Debug)]
pub struct Parsed {
    /// The items: exactly one unless [`ParseOptions::sequence`] was set.
    pub items: Vec<Item<'static>>,
    /// Warnings in source order.
    pub warnings: Vec<Warning>,
    /// Source text ranges of the parsed nodes. Paths of a sequence's items
    /// start with [`PathSegment::Index`](crate::PathSegment::Index) of the
    /// item within the sequence; for a single item they start at the root.
    /// Entries have no CBOR span. Nodes created by an app-extension share the
    /// literal's range; items written inside `<<…>>` get
    /// [`PathSegment::Embedded`](crate::PathSegment::Embedded) entries and
    /// streamstring chunks get [`PathSegment::Chunk`](crate::PathSegment::Chunk)
    /// entries.
    pub spans: SpanMap,
}

/// Parses exactly one item, with the built-in extensions; unknown prefixes
/// become opaque values (their warnings are dropped; use [`parse_with`] to
/// see them).
///
/// Encoding indicators are honored, and items without one get preferred
/// serialization with definite lengths, so
/// `encode(&item, EncodeMode::Preserve)` produces the bytes the EDN describes.
pub fn parse(text: &str) -> Result<Item<'static>, EdnError> {
    unimplemented!()
}

/// Parses a CBOR sequence: zero or more items separated by commas or blank
/// space (the `seq` rule).
pub fn parse_seq(text: &str) -> Result<Vec<Item<'static>>, EdnError> {
    unimplemented!()
}

/// Parses with options, returning warnings and source spans too.
pub fn parse_with(text: &str, options: &ParseOptions) -> Result<Parsed, EdnError> {
    unimplemented!()
}
