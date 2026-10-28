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
    /// Something that is only a warning normally, rejected because
    /// [`ParseOptions::strict`](crate::ParseOptions::strict) is set.
    Strict(WarningKind),
}

impl fmt::Display for EdnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at line {}, column {}",
            self.kind, self.pos.line, self.pos.column
        )
    }
}

impl fmt::Display for EdnErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EdnErrorKind::UnexpectedEnd => f.write_str("unexpected end of input"),
            EdnErrorKind::UnexpectedChar(c) => write!(f, "unexpected character {c:?}"),
            EdnErrorKind::TrailingInput => f.write_str("unexpected input after the item"),
            EdnErrorKind::MissingSeparator => f.write_str("missing comma or blank space"),
            EdnErrorKind::InvalidNumber => f.write_str("invalid number"),
            EdnErrorKind::OutOfRange => f.write_str("number out of range"),
            EdnErrorKind::InvalidEscape => f.write_str("invalid escape"),
            EdnErrorKind::InvalidCodePoint => f.write_str("invalid code point"),
            EdnErrorKind::ControlCharacter => f.write_str("control character in string"),
            EdnErrorKind::InvalidEncodingIndicator => f.write_str("invalid encoding indicator"),
            EdnErrorKind::InvalidChunks => f.write_str("invalid streamstring chunks"),
            EdnErrorKind::InvalidPrefix => f.write_str("invalid app-extension prefix"),
            EdnErrorKind::UnknownExtension(p) => write!(f, "unknown app-extension {p:?}"),
            EdnErrorKind::Extension { prefix, message } => write!(f, "{prefix}'': {message}"),
            EdnErrorKind::DepthLimit => f.write_str("nesting too deep"),
            EdnErrorKind::Strict(w) => write!(f, "{w:?} (strict mode)"),
        }
    }
}

impl Position {
    /// The position of byte `offset` in `src`.
    pub(crate) fn locate(src: &str, offset: usize) -> Position {
        let mut line = 1;
        let mut column = 1;
        for (i, c) in src.char_indices() {
            if i >= offset {
                break;
            }
            if c == '\n' {
                line += 1;
                column = 1;
            } else if c != '\r' {
                column += 1;
            }
        }
        Position {
            offset,
            line,
            column,
        }
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
    /// An ellipsis inside `h''`, or a tag 888 written in the input. An
    /// ellipsis becomes the draft-ietf-cbor-edn-literals-27 §5.2 "CPA888"
    /// form (see [`ELLIPSIS_TAG`](crate::ELLIPSIS_TAG)). One warning per
    /// literal or tag, at its first character.
    Ellipsis,
    /// The deprecated streamstring syntax `(_ …)`
    /// (draft-ietf-cbor-edn-literals-28 §4.3); `ilbs<<…>>`/`ilts<<…>>`
    /// replace it. At the `(`.
    Streamstring,
    /// An end-of-line comment (`#` or `//`) at the end of the input with no
    /// line feed after it. At the `#` or `//`.
    EolCommentAtEof,
    /// A NaN whose encoding is not the canonical `f97e00`: a payload, a
    /// signaling NaN, the sign bit, or a wider width (`float'7fc00001'`,
    /// `NaN_2`). It is kept as written, but preferred-plus and deterministic
    /// encoding replace it (draft-ietf-cbor-serialization-11 §4.1, #7). At
    /// the start of the literal.
    NonCanonicalNaN,
}
