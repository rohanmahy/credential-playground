//! Parse errors and warnings.

use std::fmt;

/// A position in EDN source text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Position {
    /// Byte offset into the source.
    pub offset: usize,
    /// 1-based line number. A CRLF pair counts as one line break.
    pub line: usize,
    /// 1-based column, counted in Unicode scalar values (not bytes).
    pub column: usize,
}

/// Why parsing failed, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdnError {
    /// What went wrong.
    pub kind: EdnErrorKind,
    /// Where it went wrong: the first character that could not be accepted
    /// (for [`EdnErrorKind::UnexpectedEnd`], the end of the input).
    pub pos: Position,
}

/// The kinds of malformed EDN.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EdnErrorKind {
    /// The input ended inside an item, string, or comment, or contained no item.
    UnexpectedEnd,
    /// A character that cannot start or continue the current construct.
    UnexpectedChar(char),
    /// [`parse`](crate::parse) found another item or other text after the
    /// single item.
    TrailingInput,
    /// Two items, or two map entries, without a comma or blank space between
    /// them (as in `[[][]]`).
    MissingSeparator,
    /// A malformed number: leading zeros, no digits after `0x`/`0o`/`0b`, a
    /// digit outside the base, or a float that overflows binary64.
    InvalidNumber,
    /// A tag number or `simple()` argument that is out of range (tags above
    /// 2^64-1, simple values 24..=31 or above 255) or has leading zeros.
    OutOfRange,
    /// An unknown or disallowed escape in a string literal (including `\u`
    /// escapes of printable ASCII and `\/` in single-quoted strings).
    InvalidEscape,
    /// A `\u` escape that is a lone surrogate or above U+10FFFF.
    InvalidCodePoint,
    /// A control character (other than LF and CR) inside a string literal.
    ControlCharacter,
    /// An encoding indicator that cannot hold the value (`256_0`, `1.1_1`),
    /// or `_` (indefinite) on an item that cannot be indefinite.
    InvalidEncodingIndicator,
    /// Chunks of a streamstring `(_ …)` that are not all byte strings or all
    /// text strings, or a streamstring with no chunks.
    InvalidChunks,
    /// An ellipsis (`...`), which has no CBOR representation.
    Ellipsis,
    /// A prefix that is not all lowercase or all uppercase, or a reserved
    /// word (`true`, `false`, `null`, `undefined`) used as a prefix.
    InvalidPrefix,
    /// An app-extension prefix with no registered extension, under
    /// [`UnknownExtensions::Error`](crate::UnknownExtensions::Error).
    UnknownExtension(String),
    /// An app-extension rejected its input (bad hex, bad date, unknown hash
    /// algorithm, invalid UTF-8 from `t1`, …).
    Extension {
        /// The prefix as written (`h`, `DT`, …).
        prefix: String,
        /// Why the extension rejected the input.
        message: String,
    },
    /// Arrays, maps, tags, and embedded sequences nested deeper than
    /// [`tokenator_cbor::MAX_DEPTH`].
    DepthLimit,
}

impl fmt::Display for EdnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unimplemented!()
    }
}

impl std::error::Error for EdnError {}

/// Something accepted but worth telling the user about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    /// What was noticed.
    pub kind: WarningKind,
    /// Where it starts in the source.
    pub pos: Position,
}

/// The kinds of warnings.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WarningKind {
    /// An app-extension prefix with no registered extension. The literal
    /// became an opaque tag-999 value (see
    /// [`UNRESOLVED_EXTENSION_TAG`](crate::UNRESOLVED_EXTENSION_TAG)).
    UnknownExtension(String),
    /// A reserved encoding indicator (`_4`..`_7` or other word characters);
    /// it was ignored. Holds the indicator text after the `_`.
    ReservedEncodingIndicator(String),
    /// An encoding indicator that has no meaning here (for example on an
    /// integer literal that became a bignum); it was ignored.
    IgnoredEncodingIndicator,
}
