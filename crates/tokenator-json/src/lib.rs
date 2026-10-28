//! Span-preserving, order-preserving JSON parser.
//!
//! Every [`Node`] knows the exact byte range it came from. Object members are
//! kept in arrival order, and duplicate names are preserved so a linter can
//! report them. Number lexemes are kept verbatim, and strings without escapes
//! borrow from the input. [`print()`] re-emits a tree, copying the original
//! bytes of every unedited region.
//!
//! Reading a document:
//!
//! ```
//! use tokenator_json::{Value, parse};
//!
//! let input = br#"{"iss": "me", "exp": 1.7e9, "iss": "you"}"#;
//! let root = parse(input)?;
//! let exp = root.get("exp").unwrap();
//! assert!(matches!(exp.value(), Value::Number(n) if n == "1.7e9"));
//! assert_eq!(exp.raw(), Some("1.7e9"));
//! assert_eq!(&input[exp.span().unwrap().start..][..5], b"1.7e9");
//! assert_eq!(root.get_all("iss").len(), 2); // duplicates are kept
//! # Ok::<(), tokenator_json::JsonError>(())
//! ```
//!
//! Editing a document. Only the edited parts change; the layout of
//! everything else is copied from the source:
//!
//! ```
//! use tokenator_json::{Member, Node, PrintStyle, Value, parse, print};
//!
//! let input = "{\n  \"b\": 1.0,\n  \"a\": \"x\"\n}";
//! let mut root = parse(input.as_bytes())?;
//! root.pointer_mut("/a").unwrap().set_value(Value::String("y\"".into()));
//! if let Value::Object(members) = root.value_mut() {
//!     members.push(Member::new("c", Node::new(Value::Array(vec![]))));
//! }
//! assert_eq!(
//!     print(&root, PrintStyle::Original),
//!     "{\n  \"b\": 1.0,\n  \"a\": \"y\\\"\",\n  \"c\": []\n}"
//! );
//! assert_eq!(
//!     print(&root, PrintStyle::Compact),
//!     r#"{"b":1.0,"a":"y\"","c":[]}"#
//! );
//! # Ok::<(), tokenator_json::JsonError>(())
//! ```
//!
//! Parsing, printing, [`Node::is_original`] and dropping a tree recurse once
//! per nesting level, so [`ParseOptions::max_depth`] also bounds stack use.

use std::borrow::Cow;
use std::fmt;

mod parse;
mod print;

/// Default maximum container nesting depth accepted by [`parse`].
pub const DEFAULT_MAX_DEPTH: usize = 128;

/// Half-open byte range `start..end` into the parsed input.
///
/// For strings and keys the range includes the quotes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Span {
    /// Offset of the first byte.
    pub start: usize,
    /// Offset one past the last byte.
    pub end: usize,
}

impl Span {
    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// True if the span is empty.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// Options for [`parse_with_options`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseOptions {
    /// Maximum number of nested arrays/objects. `[1]` has depth 1. The
    /// check happens before descending, so hostile input cannot overflow
    /// the stack.
    pub max_depth: usize,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }
}

/// What went wrong while parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Input ended before the value was complete. Offset is `input.len()`.
    UnexpectedEnd,
    /// A byte that cannot start or continue the current construct.
    UnexpectedCharacter,
    /// Non-whitespace data after the top-level value.
    TrailingCharacters,
    /// Malformed number lexeme.
    InvalidNumber,
    /// Unknown escape or malformed `\u` escape. Offset is the `\`.
    InvalidEscape,
    /// Unescaped U+0000..=U+001F inside a string. Offset is that byte.
    ControlCharacterInString,
    /// `\uD800`-`\uDFFF` escape not part of a valid pair. Offset is the `\`.
    LoneSurrogate,
    /// Nesting exceeds [`ParseOptions::max_depth`]. Offset is the `[` or `{`.
    DepthLimitExceeded,
    /// Input starts with a UTF-8 byte order mark. Offset is 0.
    ByteOrderMark,
}

/// Parse error with the byte offset where it was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonError {
    /// Byte offset into the input.
    pub offset: usize,
    /// Kind of error.
    pub kind: ErrorKind,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} at byte {}", self.kind, self.offset)
    }
}

impl std::error::Error for JsonError {}

/// Something suspicious that did not stop the parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WarningKind {
    /// Invalid UTF-8 inside a string or key. The decoded value has U+FFFD in
    /// its place, exactly as [`String::from_utf8_lossy`] would produce. One
    /// warning per U+FFFD. Offset is the first byte of the invalid sequence.
    InvalidUtf8,
    /// Integer lexeme (no fraction, no exponent) with magnitude above
    /// 2^53 - 1 (`Number.MAX_SAFE_INTEGER`), so JavaScript loses precision.
    /// Offset is the start of the number.
    UnsafeInteger,
    /// The number's magnitude rounds to infinity as an `f64`. Takes
    /// precedence over `UnsafeInteger`. Offset is the start of the number.
    NumberOverflow,
    /// A lexeme with a non-zero digit rounds to zero as an `f64`. Offset is
    /// the start of the number.
    NumberUnderflow,
}

/// A parse warning with the byte offset it refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Warning {
    /// Byte offset into the input.
    pub offset: usize,
    /// Kind of warning.
    pub kind: WarningKind,
}

/// Result of [`parse_with_options`]: the tree plus warnings in offset order.
#[derive(Debug, Clone)]
pub struct Parsed<'a> {
    /// Root node.
    pub node: Node<'a>,
    /// Warnings, sorted by offset.
    pub warnings: Vec<Warning>,
}

/// A JSON value. Containers hold child [`Node`]s.
#[derive(Debug, Clone)]
pub enum Value<'a> {
    /// `null`
    Null,
    /// `true` / `false`
    Bool(bool),
    /// Number, as its verbatim lexeme (e.g. `1.0`, `-0`, `1E+3`).
    Number(Cow<'a, str>),
    /// Decoded string. Borrowed when the source had no escapes.
    String(Cow<'a, str>),
    /// Array elements in order.
    Array(Vec<Node<'a>>),
    /// Object members in arrival order, duplicates included.
    Object(Vec<Member<'a>>),
}

/// A value plus where it came from.
#[derive(Debug, Clone)]
pub struct Node<'a> {
    span: Option<Span>,
    raw: Option<&'a [u8]>,
    value: Value<'a>,
    edited: bool,
}

impl<'a> Node<'a> {
    /// A synthesized node with no source location.
    pub fn new(value: Value<'a>) -> Self {
        Self {
            span: None,
            raw: None,
            value,
            edited: true,
        }
    }

    /// Original byte range. `None` for synthesized nodes. Edited nodes keep
    /// the span they were parsed from.
    pub fn span(&self) -> Option<Span> {
        self.span
    }

    /// The original source text of this node. `None` for synthesized nodes,
    /// and also `None` when the source bytes are not valid UTF-8 (see
    /// [`Node::raw_bytes`]).
    pub fn raw(&self) -> Option<&'a str> {
        self.raw.and_then(|b| std::str::from_utf8(b).ok())
    }

    /// The exact original source bytes of this node, even when they are not
    /// valid UTF-8. `None` for synthesized nodes.
    pub fn raw_bytes(&self) -> Option<&'a [u8]> {
        self.raw
    }

    /// The value.
    pub fn value(&self) -> &Value<'a> {
        &self.value
    }

    /// Mutable access to the value. Marks this node as edited.
    pub fn value_mut(&mut self) -> &mut Value<'a> {
        self.edited = true;
        &mut self.value
    }

    /// Replace the value. Marks this node as edited.
    pub fn set_value(&mut self, value: Value<'a>) {
        self.value = value;
        self.edited = true;
    }

    /// True if this node and all its descendants are unedited parsed nodes,
    /// so the printer can copy [`Node::raw_bytes`] verbatim.
    pub fn is_original(&self) -> bool {
        !self.edited
            && self.raw.is_some()
            && match &self.value {
                Value::Array(xs) => xs.iter().all(Node::is_original),
                Value::Object(ms) => ms.iter().all(Member::is_original),
                _ => true,
            }
    }

    /// Object members, or `None` if this is not an object.
    pub fn members(&self) -> Option<&[Member<'a>]> {
        match &self.value {
            Value::Object(ms) => Some(ms),
            _ => None,
        }
    }

    /// Array elements, or `None` if this is not an array.
    pub fn elements(&self) -> Option<&[Node<'a>]> {
        match &self.value {
            Value::Array(xs) => Some(xs),
            _ => None,
        }
    }

    /// Mutable object members (keys and values can be edited in place; the
    /// list itself cannot grow or shrink). Does not mark `self` edited.
    pub fn members_mut(&mut self) -> Option<&mut [Member<'a>]> {
        match &mut self.value {
            Value::Object(ms) => Some(ms),
            _ => None,
        }
    }

    /// Mutable array elements. Does not mark `self` edited.
    pub fn elements_mut(&mut self) -> Option<&mut [Node<'a>]> {
        match &mut self.value {
            Value::Array(xs) => Some(xs),
            _ => None,
        }
    }

    /// First member value named `name`, if this is an object.
    pub fn get(&self, name: &str) -> Option<&Node<'a>> {
        self.members()?
            .iter()
            .find(|m| m.key == name)
            .map(|m| &m.value)
    }

    /// Mutable first member value named `name`. Does not mark `self` edited.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut Node<'a>> {
        self.members_mut()?
            .iter_mut()
            .find(|m| m.key == name)
            .map(|m| &mut m.value)
    }

    /// All member values named `name`, in arrival order.
    pub fn get_all(&self, name: &str) -> Vec<&Node<'a>> {
        self.members()
            .unwrap_or_default()
            .iter()
            .filter(|m| m.key == name)
            .map(|m| &m.value)
            .collect()
    }

    /// Array element `i`, if this is an array.
    pub fn index(&self, i: usize) -> Option<&Node<'a>> {
        self.elements()?.get(i)
    }

    /// Mutable array element `i`. Does not mark `self` edited.
    pub fn index_mut(&mut self, i: usize) -> Option<&mut Node<'a>> {
        self.elements_mut()?.get_mut(i)
    }

    /// RFC 6901 JSON Pointer lookup (`""` is the node itself). On duplicate
    /// names the first member wins.
    pub fn pointer(&self, pointer: &str) -> Option<&Node<'a>> {
        let mut cur = self;
        for token in pointer_tokens(pointer)? {
            let token = token?;
            cur = match &cur.value {
                Value::Object(_) => cur.get(&token)?,
                _ => cur.index(array_index(&token)?)?,
            };
        }
        Some(cur)
    }

    /// Mutable [`Node::pointer`]. Does not mark the ancestors edited.
    pub fn pointer_mut(&mut self, pointer: &str) -> Option<&mut Node<'a>> {
        let mut cur = self;
        for token in pointer_tokens(pointer)? {
            let token = token?;
            cur = match cur.value {
                Value::Object(_) => cur.get_mut(&token)?,
                _ => cur.index_mut(array_index(&token)?)?,
            };
        }
        Some(cur)
    }
}

/// One `"key": value` object member.
#[derive(Debug, Clone)]
pub struct Member<'a> {
    key_span: Option<Span>,
    key_raw: Option<&'a [u8]>,
    key: Cow<'a, str>,
    key_edited: bool,
    value: Node<'a>,
}

impl<'a> Member<'a> {
    /// A synthesized member.
    pub fn new(key: impl Into<Cow<'a, str>>, value: Node<'a>) -> Self {
        Self {
            key_span: None,
            key_raw: None,
            key: key.into(),
            key_edited: true,
            value,
        }
    }

    /// Decoded key. Borrowed when the source had no escapes.
    pub fn key(&self) -> &Cow<'a, str> {
        &self.key
    }

    /// Byte range of the key including quotes. `None` if synthesized.
    pub fn key_span(&self) -> Option<Span> {
        self.key_span
    }

    /// Original key text including quotes. `None` if synthesized or if the
    /// source bytes are not valid UTF-8 (see [`Member::key_raw_bytes`]).
    pub fn key_raw(&self) -> Option<&'a str> {
        self.key_raw.and_then(|b| std::str::from_utf8(b).ok())
    }

    /// Exact original key bytes including quotes. `None` if synthesized.
    pub fn key_raw_bytes(&self) -> Option<&'a [u8]> {
        self.key_raw
    }

    /// Replace the key. Marks the key as edited.
    pub fn set_key(&mut self, key: impl Into<Cow<'a, str>>) {
        self.key = key.into();
        self.key_edited = true;
    }

    /// True if the key is unedited and the value [`Node::is_original`].
    pub fn is_original(&self) -> bool {
        !self.key_edited && self.key_raw.is_some() && self.value.is_original()
    }

    /// The member value.
    pub fn value(&self) -> &Node<'a> {
        &self.value
    }

    /// Mutable member value.
    pub fn value_mut(&mut self) -> &mut Node<'a> {
        &mut self.value
    }
}

/// Output layout for [`print()`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrintStyle {
    /// Copy original bytes (including inner whitespace) for every unedited
    /// region. Only edited parts are newly emitted, laid out according to
    /// [`PrintOptions::inserted`].
    #[default]
    Original,
    /// No insignificant whitespace.
    Compact,
    /// Two-space indent, `": "` separator, `{}`/`[]` when empty. String and
    /// key escapes are normalized: U+0020..=U+007E print literally except
    /// `\"` and `\\`, controls use `\b\f\n\r\t` or lowercase `\u00xx`, and
    /// characters above U+007E keep their original (escaped or literal) form.
    Pretty,
}

/// Layout of synthesized or inserted content under [`PrintStyle::Original`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InsertedLayout {
    /// Synthesized subtrees have no insignificant whitespace; separators
    /// around inserted children are borrowed from neighbouring gaps.
    #[default]
    Compact,
    /// Canonical spacing (`", "`, `": "`) and indentation that follows the
    /// enclosing container (falling back to two spaces).
    Canonical,
}

/// Options for [`print_with`] and [`print_bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrintOptions {
    /// Overall style.
    pub style: PrintStyle,
    /// Layout of new content; only used with [`PrintStyle::Original`].
    pub inserted: InsertedLayout,
}

/// Parse a single JSON text (RFC 8259) with [`ParseOptions::default`].
///
/// A leading BOM is rejected. Invalid UTF-8 inside strings is accepted
/// (see [`WarningKind::InvalidUtf8`]); anywhere else it is an
/// [`ErrorKind::UnexpectedCharacter`], which is also how UTF-16 input fails.
/// Warnings are discarded; use [`parse_with_options`] to see them. Leading
/// and trailing whitespace is allowed but falls outside the root node's span.
///
/// ```
/// let root = tokenator_json::parse(b" [1, \"two\"] ")?;
/// assert_eq!(root.elements().unwrap().len(), 2);
/// assert_eq!(root.raw(), Some("[1, \"two\"]"));
/// # Ok::<(), tokenator_json::JsonError>(())
/// ```
pub fn parse(input: &[u8]) -> Result<Node<'_>, JsonError> {
    parse_with_options(input, &ParseOptions::default()).map(|p| p.node)
}

/// Parse with explicit options, also returning [`Warning`]s.
pub fn parse_with_options<'a>(
    input: &'a [u8],
    options: &ParseOptions,
) -> Result<Parsed<'a>, JsonError> {
    parse::parse(input, options)
}

/// Serialize `node`. Member order is never changed.
///
/// In every style, unedited scalars and keys keep their original token text.
/// New strings use minimal escaping.
pub fn print(node: &Node<'_>, style: PrintStyle) -> String {
    print_with(
        node,
        &PrintOptions {
            style,
            inserted: InsertedLayout::Compact,
        },
    )
}

/// Serialize with explicit [`PrintOptions`]. Source bytes that are not
/// valid UTF-8 come out as U+FFFD; use [`print_bytes`] for exact output.
pub fn print_with(node: &Node<'_>, options: &PrintOptions) -> String {
    match String::from_utf8(print_bytes(node, options)) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}

/// Like [`print_with`], but copies original bytes exactly, even when they
/// are not valid UTF-8.
pub fn print_bytes(node: &Node<'_>, options: &PrintOptions) -> Vec<u8> {
    print::print(node, options)
}

/// Split an RFC 6901 pointer into unescaped reference tokens. `None` if it
/// does not start with `/`; an item is `None` for a bad `~` escape.
fn pointer_tokens(pointer: &str) -> Option<impl Iterator<Item = Option<Cow<'_, str>>>> {
    let rest = match pointer {
        "" => None,
        _ => Some(pointer.strip_prefix('/')?),
    };
    Some(rest.into_iter().flat_map(|r| r.split('/')).map(|t| {
        if !t.contains('~') {
            return Some(Cow::Borrowed(t));
        }
        let mut out = String::with_capacity(t.len());
        let mut chars = t.chars();
        while let Some(c) = chars.next() {
            if c != '~' {
                out.push(c);
                continue;
            }
            match chars.next()? {
                '0' => out.push('~'),
                '1' => out.push('/'),
                _ => return None,
            }
        }
        Some(Cow::Owned(out))
    }))
}

/// RFC 6901 array index: `0` or a digit string without a leading zero.
fn array_index(token: &str) -> Option<usize> {
    let canonical = token == "0"
        || (!token.starts_with('0')
            && !token.is_empty()
            && token.bytes().all(|b| b.is_ascii_digit()));
    canonical.then(|| token.parse().ok()).flatten()
}
