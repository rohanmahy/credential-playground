//! EDN text to items.
//!
//! A hand-written, iterative parser: open arrays, maps, tags, embedded
//! sequences, app-extension sequences, and streamstrings live on an explicit
//! stack of [`Frame`]s, so nesting costs heap rather than call stack.

use std::ops::Range;

use tokenator_cbor::{EncodeMode, FloatWidth, Item, MAX_DEPTH, Value, Width, encode};

use crate::error::{EdnError, EdnErrorKind, Position, Warning, WarningKind};
use crate::ext::{ELLIPSIS_TAG, Extensions, UNRESOLVED_EXTENSION_TAG};
use crate::path::{Path, PathSegment};
use crate::spans::{NodeSpan, SpanMap};

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
    /// Strict mode: every warning except
    /// [`WarningKind::UnknownExtension`](crate::WarningKind::UnknownExtension)
    /// (which [`ParseOptions::unknown_extensions`] controls) becomes an
    /// [`EdnErrorKind::Strict`](crate::EdnErrorKind::Strict) error at the
    /// warning's position.
    pub strict: bool,
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
///
/// ```
/// use tokenator_cbor::{encode, EncodeMode};
///
/// let item = tokenator_edn::parse(r#"{1: "a", 2: h'00ff'}"#)?;
/// assert_eq!(
///     encode(&item, EncodeMode::Preserve)?,
///     [0xa2, 0x01, 0x61, 0x61, 0x02, 0x42, 0x00, 0xff]
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// Encoding indicators, comments, embedded CBOR, and app-extensions:
///
/// ```
/// use tokenator_cbor::{encode, EncodeMode};
///
/// let edn = "
///     / a COSE-ish header / {_
///         1: -7,           # alg
///         4: 'kid'_0,      # non-preferred length
///         6: dt'2013-03-21T20:04:00Z',
///     }";
/// let item = tokenator_edn::parse(edn)?;
/// let bytes = encode(&item, EncodeMode::Preserve)?;
/// assert_eq!(bytes[0], 0xbf); // indefinite-length map
/// assert_eq!(&bytes[4..9], [0x58, 0x03, b'k', b'i', b'd']);
/// assert_eq!(&bytes[9..], [0x06, 0x1a, 0x51, 0x4b, 0x67, 0xb0, 0xff]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn parse(text: &str) -> Result<Item<'static>, EdnError> {
    let options = ParseOptions::default();
    let mut items = Parser::new(text, &options, false).run(false)?;
    items.pop().ok_or_else(|| EdnError {
        kind: EdnErrorKind::UnexpectedEnd,
        pos: Position::locate(text, text.len()),
    })
}

/// Parses a CBOR sequence: zero or more items separated by commas or blank
/// space (the `seq` rule).
///
/// ```
/// let items = tokenator_edn::parse_seq("1, [2]\n\"three\"")?;
/// assert_eq!(items.len(), 3);
/// assert!(tokenator_edn::parse_seq("")?.is_empty());
/// # Ok::<(), tokenator_edn::EdnError>(())
/// ```
pub fn parse_seq(text: &str) -> Result<Vec<Item<'static>>, EdnError> {
    let options = ParseOptions::default();
    Parser::new(text, &options, false).run(true)
}

/// Parses with options, returning warnings and source spans too.
///
/// ```
/// use tokenator_edn::{parse_with, ParseOptions, Path, PathSegment, WarningKind};
///
/// let text = "[1, cri'https://example.com']";
/// let parsed = parse_with(text, &ParseOptions::default())?;
/// assert_eq!(parsed.warnings[0].kind, WarningKind::UnknownExtension("cri".into()));
/// let span = parsed.spans.get(&Path::from([PathSegment::Index(1)])).unwrap();
/// assert_eq!(&text[span.text.clone()], "cri'https://example.com'");
/// # Ok::<(), tokenator_edn::EdnError>(())
/// ```
pub fn parse_with(text: &str, options: &ParseOptions) -> Result<Parsed, EdnError> {
    let mut parser = Parser::new(text, options, true);
    let items = parser.run(options.sequence)?;
    let mut warnings = parser.warnings;
    warnings.sort_by_key(|w| w.0);
    let mut locator = Locator::new(text);
    let warnings = warnings
        .into_iter()
        .map(|(offset, kind)| Warning {
            kind,
            pos: locator.locate(offset),
        })
        .collect();
    let lines = LineIndex::new(text);
    let mut spans = SpanMap::new();
    for (path, range) in parser.spans {
        spans.push(
            path,
            NodeSpan {
                lines: lines.lines(&range),
                text: range,
                cbor: None,
            },
        );
    }
    Ok(Parsed {
        items,
        warnings,
        spans,
    })
}

/// Positions of many offsets, visited in increasing order.
struct Locator<'s> {
    src: &'s str,
    at: usize,
    line: usize,
    column: usize,
}

impl<'s> Locator<'s> {
    fn new(src: &'s str) -> Self {
        Locator {
            src,
            at: 0,
            line: 1,
            column: 1,
        }
    }

    fn locate(&mut self, offset: usize) -> Position {
        if offset < self.at {
            return Position::locate(self.src, offset);
        }
        let rest = self.src.get(self.at..offset).unwrap_or_default();
        for c in rest.chars() {
            if c == '\n' {
                self.line += 1;
                self.column = 1;
            } else if c != '\r' {
                self.column += 1;
            }
        }
        self.at = offset;
        Position {
            offset,
            line: self.line,
            column: self.column,
        }
    }
}

/// Maps byte ranges of a text to 0-based line ranges.
pub(crate) struct LineIndex {
    newlines: Vec<usize>,
}

impl LineIndex {
    pub(crate) fn new(text: &str) -> Self {
        LineIndex {
            newlines: text
                .bytes()
                .enumerate()
                .filter(|(_, b)| *b == b'\n')
                .map(|(i, _)| i)
                .collect(),
        }
    }

    fn line_of(&self, offset: usize) -> usize {
        self.newlines.partition_point(|&nl| nl < offset)
    }

    /// The lines that `range` touches.
    pub(crate) fn lines(&self, range: &Range<usize>) -> Range<usize> {
        let first = self.line_of(range.start);
        let last = self.line_of(range.end.max(range.start + 1) - 1);
        first..last + 1
    }
}

/// An encoding indicator as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Spec {
    /// `_`
    Indefinite,
    /// `_i`, `_0`..`_3`
    Width(Width),
    /// Anything else after `_`.
    Reserved(String),
}

/// What an open frame is collecting.
enum Kind {
    Root {
        seq: bool,
        items: Vec<Item<'static>>,
    },
    Array(Vec<Item<'static>>),
    Map {
        entries: Vec<(Item<'static>, Item<'static>)>,
        key: Option<Item<'static>>,
    },
    Tag {
        number: u64,
        width: Width,
        content: Option<Item<'static>>,
    },
    Embedded(Vec<Item<'static>>),
    ExtSeq {
        prefix: String,
        items: Vec<Item<'static>>,
    },
    Stream(Vec<Item<'static>>),
}

/// An open construct.
struct Frame {
    kind: Kind,
    /// Offset of the construct's first character.
    start: usize,
    /// The container's encoding indicator (arrays and maps), with its offset.
    spec: Option<(usize, Spec)>,
    path: Path,
    /// Index of the frame's span entry.
    entry: Option<usize>,
    /// How many nesting levels the frame adds.
    weight: usize,
}

impl Frame {
    /// The path segment of the next child.
    fn child_segment(&self) -> Option<PathSegment> {
        Some(match &self.kind {
            Kind::Root { seq: false, .. } => return None,
            Kind::Root { items, .. } | Kind::Array(items) => PathSegment::Index(items.len()),
            Kind::Map { entries, key } => match key {
                Some(_) => PathSegment::Value(entries.len()),
                None => PathSegment::Key(entries.len()),
            },
            Kind::Tag { .. } => PathSegment::TagContent,
            Kind::Embedded(items) | Kind::ExtSeq { items, .. } => {
                PathSegment::Embedded(items.len())
            }
            Kind::Stream(chunks) => PathSegment::Chunk(chunks.len()),
        })
    }

    fn deliver(&mut self, item: Item<'static>) {
        match &mut self.kind {
            Kind::Root { items, .. }
            | Kind::Array(items)
            | Kind::Embedded(items)
            | Kind::ExtSeq { items, .. }
            | Kind::Stream(items) => items.push(item),
            Kind::Map { entries, key } => match key.take() {
                Some(k) => entries.push((k, item)),
                None => *key = Some(item),
            },
            Kind::Tag { content, .. } => *content = Some(item),
        }
    }
}

/// The result of starting an item.
enum Begun {
    /// A complete item (literal, number, string, …).
    Item(Item<'static>),
    /// An opened construct, to be completed by later input.
    Open(Kind, Option<(usize, Spec)>, usize),
}

struct Parser<'s, 'o> {
    src: &'s str,
    b: &'s [u8],
    pos: usize,
    options: &'o ParseOptions,
    warnings: Vec<(usize, WarningKind)>,
    record: bool,
    spans: Vec<(Path, Range<usize>)>,
    /// Number of open app-extension sequences; their content gets no spans.
    suppress: usize,
}

type Res<T> = Result<T, EdnError>;

fn is_word(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn is_blank_start(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'#')
}

fn can_start_item(c: u8) -> bool {
    matches!(
        c,
        b'[' | b'{' | b'<' | b'(' | b'"' | b'\'' | b'`' | b'+' | b'-' | b'.'
    ) || c.is_ascii_alphanumeric()
}

/// Tree height: 0 for a leaf.
pub(crate) fn height(item: &Item<'_>) -> usize {
    let mut max = 0;
    let mut stack = vec![(item, 0usize)];
    while let Some((it, d)) = stack.pop() {
        max = max.max(d);
        match &it.value {
            Value::Array(items) => stack.extend(items.iter().map(|c| (c, d + 1))),
            Value::Map(entries) => {
                for (k, v) in entries {
                    stack.push((k, d + 1));
                    stack.push((v, d + 1));
                }
            }
            Value::Tag(_, inner) => stack.push((inner, d + 1)),
            _ => {}
        }
    }
    max
}

/// Whether `width` can hold `arg`.
pub(crate) fn fits(width: Width, arg: u64) -> bool {
    match width {
        Width::Immediate => arg < 24,
        Width::U8 => arg <= 0xff,
        Width::U16 => arg <= 0xffff,
        Width::U32 => arg <= 0xffff_ffff,
        Width::U64 => true,
        Width::Indefinite => false,
    }
}

/// Whether `f` is exactly representable at `width`.
pub(crate) fn float_fits(f: f64, width: FloatWidth) -> bool {
    let len = match width {
        FloatWidth::F16 => 3,
        FloatWidth::F32 => 5,
        FloatWidth::F64 => return true,
    };
    // The encoder widens a value that does not fit, bit-exactly.
    encode(&Item::new(Value::Float(f, width)), EncodeMode::Preserve).is_ok_and(|b| b.len() == len)
}

fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

impl<'s, 'o> Parser<'s, 'o> {
    fn new(src: &'s str, options: &'o ParseOptions, record: bool) -> Self {
        Parser {
            src,
            b: src.as_bytes(),
            pos: 0,
            options,
            warnings: Vec::new(),
            record,
            spans: Vec::new(),
            suppress: 0,
        }
    }

    fn fail<T>(&self, offset: usize, kind: EdnErrorKind) -> Res<T> {
        Err(EdnError {
            kind,
            pos: Position::locate(self.src, offset),
        })
    }

    /// Records a warning, or fails with it in strict mode.
    fn warn(&mut self, offset: usize, kind: WarningKind) -> Res<()> {
        if self.options.strict && !matches!(kind, WarningKind::UnknownExtension(_)) {
            return self.fail(offset, EdnErrorKind::Strict(kind));
        }
        self.warnings.push((offset, kind));
        Ok(())
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn peek_at(&self, ahead: usize) -> Option<u8> {
        self.b.get(self.pos + ahead).copied()
    }

    fn peek_char(&self) -> Option<char> {
        self.src.get(self.pos..).and_then(|s| s.chars().next())
    }

    /// An error for the character at the current position (or the end).
    fn unexpected<T>(&self) -> Res<T> {
        match self.peek_char() {
            Some(c) => self.fail(self.pos, EdnErrorKind::UnexpectedChar(c)),
            None => self.fail(self.b.len(), EdnErrorKind::UnexpectedEnd),
        }
    }

    fn starts_with(&self, s: &[u8]) -> bool {
        self.b.get(self.pos..).is_some_and(|r| r.starts_with(s))
    }

    // ------------------------------------------------------------ blank space

    /// Skips blank space and comments; returns whether there was any.
    fn skip_blank(&mut self) -> Res<bool> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            match c {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                b'#' => self.skip_line()?,
                b'/' => match self.peek_at(1) {
                    Some(b'/') => self.skip_line()?,
                    Some(b'*') => {
                        let from = self.pos + 2;
                        match self.find(from, b"*/") {
                            Some(p) => self.pos = p + 2,
                            None => return self.fail(self.b.len(), EdnErrorKind::UnexpectedEnd),
                        }
                    }
                    _ => {
                        let from = self.pos + 1;
                        match self.find(from, b"/") {
                            Some(p) => self.pos = p + 1,
                            None => return self.fail(self.b.len(), EdnErrorKind::UnexpectedEnd),
                        }
                    }
                },
                _ => break,
            }
        }
        Ok(self.pos > start)
    }

    /// Skips an end-of-line comment, which warns if the input ends first.
    fn skip_line(&mut self) -> Res<()> {
        match self.find(self.pos, b"\n") {
            Some(p) => self.pos = p + 1,
            None => {
                self.warn(self.pos, WarningKind::EolCommentAtEof)?;
                self.pos = self.b.len();
            }
        }
        Ok(())
    }

    fn find(&self, from: usize, needle: &[u8]) -> Option<usize> {
        let hay = self.b.get(from..)?;
        if let [n] = needle {
            return hay.iter().position(|c| c == n).map(|p| p + from);
        }
        hay.windows(needle.len())
            .position(|w| w == needle)
            .map(|p| p + from)
    }

    // ------------------------------------------------------------ spans

    fn record_start(&mut self, path: &Path, start: usize) -> Option<usize> {
        if !self.record || self.suppress > 0 {
            return None;
        }
        self.spans.push((path.clone(), start..start));
        Some(self.spans.len() - 1)
    }

    fn record_end(&mut self, entry: Option<usize>, end: usize) {
        if let Some((_, r)) = entry.and_then(|i| self.spans.get_mut(i)) {
            r.end = end;
        }
    }

    /// Entries for the descendants of an item built by an extension, all
    /// with the literal's range.
    fn record_subtree(&mut self, entry: Option<usize>, item: &Item<'_>) {
        let Some((path, range)) = entry.and_then(|i| self.spans.get(i)).cloned() else {
            return;
        };
        let mut stack: Vec<(Path, &Item<'_>)> = Vec::new();
        push_children(&mut stack, &path, item);
        while let Some((p, it)) = stack.pop() {
            push_children(&mut stack, &p, it);
            self.spans.push((p, range.clone()));
        }
    }

    // ------------------------------------------------------------ main loop

    fn run(&mut self, seq: bool) -> Res<Vec<Item<'static>>> {
        let mut stack = vec![Frame {
            kind: Kind::Root {
                seq,
                items: Vec::new(),
            },
            start: 0,
            spec: None,
            path: Path::root(),
            entry: None,
            weight: 0,
        }];
        let mut depth = 0usize;
        self.skip_blank()?;
        loop {
            // At the start of an element; blank space is skipped.
            let Some(top) = stack.last() else {
                return Ok(Vec::new());
            };
            let mut value = if self.at_closer(&top.kind) {
                let missing = match &top.kind {
                    Kind::Map { key, .. } => key.is_some(),
                    Kind::Tag { content, .. } => content.is_none(),
                    Kind::Root { seq: false, .. } => true,
                    _ => false,
                };
                if missing {
                    return self.unexpected();
                }
                let Some(frame) = stack.pop() else {
                    return Ok(Vec::new());
                };
                depth -= frame.weight;
                match self.close(frame, depth)? {
                    Closed::Item(item) => item,
                    Closed::Done(items) => return Ok(items),
                }
            } else {
                match self.peek() {
                    None => return self.fail(self.b.len(), EdnErrorKind::UnexpectedEnd),
                    Some(b',') => return self.unexpected(),
                    Some(_) => {}
                }
                if depth > MAX_DEPTH {
                    return self.fail(self.pos, EdnErrorKind::DepthLimit);
                }
                let start = self.pos;
                let path = match top.child_segment() {
                    Some(seg) => top.path.child(seg),
                    None => top.path.clone(),
                };
                let in_stream = match top.kind {
                    Kind::Stream(_) => Some(top.start),
                    _ => None,
                };
                let entry = self.record_start(&path, start);
                match self.begin(in_stream, depth)? {
                    Begun::Item(item) => {
                        self.record_end(entry, self.pos);
                        self.record_subtree(entry, &item);
                        item
                    }
                    Begun::Open(kind, spec, weight) => {
                        if matches!(kind, Kind::ExtSeq { .. }) {
                            self.suppress += 1;
                        }
                        depth += weight;
                        stack.push(Frame {
                            kind,
                            start,
                            spec,
                            path,
                            entry,
                            weight,
                        });
                        self.skip_blank()?;
                        continue;
                    }
                }
            };
            // Deliver the finished value, then handle what follows it. A
            // closing delimiter finishes another value, hence the loop.
            loop {
                let Some(top) = stack.last_mut() else {
                    return Ok(Vec::new());
                };
                top.deliver(value);
                let blank = self.skip_blank()?;
                let top = match stack.last() {
                    Some(t) => t,
                    None => return Ok(Vec::new()),
                };
                match &top.kind {
                    Kind::Root { seq: false, .. } => {
                        if self.peek().is_some() {
                            return self.fail(self.pos, EdnErrorKind::TrailingInput);
                        }
                    }
                    Kind::Map { key: Some(_), .. } => {
                        if self.peek() != Some(b':') {
                            return self.unexpected();
                        }
                        self.pos += 1;
                        self.skip_blank()?;
                        break;
                    }
                    Kind::Tag { .. } => {
                        if self.peek() != Some(b')') {
                            return self.unexpected();
                        }
                    }
                    _ => {
                        if self.peek() == Some(b',') {
                            self.pos += 1;
                            self.skip_blank()?;
                            break;
                        }
                        if !self.at_closer(&top.kind) {
                            match self.peek() {
                                None => {
                                    return self.fail(self.b.len(), EdnErrorKind::UnexpectedEnd);
                                }
                                Some(_) if blank => break,
                                Some(c) if can_start_item(c) => {
                                    return self.fail(self.pos, EdnErrorKind::MissingSeparator);
                                }
                                Some(_) => return self.unexpected(),
                            }
                        }
                    }
                }
                // At a closer.
                let Some(frame) = stack.pop() else {
                    return Ok(Vec::new());
                };
                depth -= frame.weight;
                value = match self.close(frame, depth)? {
                    Closed::Item(item) => item,
                    Closed::Done(items) => return Ok(items),
                };
            }
        }
    }

    fn at_closer(&self, kind: &Kind) -> bool {
        match kind {
            Kind::Root { .. } => self.pos >= self.b.len(),
            Kind::Array(_) => self.peek() == Some(b']'),
            Kind::Map { .. } => self.peek() == Some(b'}'),
            Kind::Tag { .. } | Kind::Stream(_) => self.peek() == Some(b')'),
            Kind::Embedded(_) | Kind::ExtSeq { .. } => self.starts_with(b">>"),
        }
    }

    /// Consumes the closing delimiter of `frame` and builds its item.
    fn close(&mut self, frame: Frame, depth: usize) -> Res<Closed> {
        let Frame {
            kind,
            start,
            spec,
            entry,
            ..
        } = frame;
        let item = match kind {
            Kind::Root { items, .. } => return Ok(Closed::Done(items)),
            Kind::Array(items) => {
                self.pos += 1;
                self.apply_container_spec(Item::array(items), spec)?
            }
            Kind::Map { entries, .. } => {
                self.pos += 1;
                self.apply_container_spec(Item::map(entries), spec)?
            }
            Kind::Tag {
                number,
                width,
                content,
            } => {
                self.pos += 1;
                match content {
                    Some(c) => Item::tag(number, c).with_width(width),
                    None => return self.fail(start, EdnErrorKind::UnexpectedEnd),
                }
            }
            Kind::Embedded(items) => {
                self.pos += 2;
                let mut bytes = Vec::new();
                for item in &items {
                    // The parser rejects simple(24..=31), so this never fails.
                    match encode(item, EncodeMode::Preserve) {
                        Ok(b) => bytes.extend(b),
                        Err(_) => return self.fail(start, EdnErrorKind::OutOfRange),
                    }
                }
                self.with_spec(Item::bytes(bytes))?
            }
            Kind::ExtSeq { prefix, items } => {
                self.pos += 2;
                self.suppress = self.suppress.saturating_sub(1);
                let item = self.evaluate(&prefix, items, start)?;
                if depth + height(&item) > MAX_DEPTH {
                    return self.fail(start, EdnErrorKind::DepthLimit);
                }
                let item = self.with_spec(item)?;
                self.check_nan(start, &item)?;
                self.record_end(entry, self.pos);
                self.record_subtree(entry, &item);
                return Ok(Closed::Item(item));
            }
            Kind::Stream(chunks) => {
                self.pos += 1;
                let text = matches!(chunks.first().map(|c| &c.value), Some(Value::Text(_)));
                let ok = !chunks.is_empty()
                    && chunks.iter().all(|c| {
                        c.width != Width::Indefinite
                            && match &c.value {
                                Value::Text(_) => text,
                                Value::Bytes(_) => !text,
                                _ => false,
                            }
                    });
                if !ok {
                    return self.fail(start, EdnErrorKind::InvalidChunks);
                }
                Item::indefinite_string(chunks)
            }
        };
        self.record_end(entry, self.pos);
        Ok(Closed::Item(item))
    }

    // ------------------------------------------------------------ items

    /// Starts the item at the current position.
    fn begin(&mut self, in_stream: Option<usize>, depth: usize) -> Res<Begun> {
        let start = self.pos;
        let Some(c) = self.peek() else {
            return self.fail(start, EdnErrorKind::UnexpectedEnd);
        };
        if let Some(stream_start) = in_stream
            && !(matches!(c, b'"' | b'\'' | b'`')
                || c.is_ascii_alphabetic()
                || self.starts_with(b"<<"))
        {
            // Chunks are strings; reject anything else before it nests.
            return self.fail(stream_start, EdnErrorKind::InvalidChunks);
        }
        match c {
            b'[' | b'{' => {
                self.pos += 1;
                let spec = self.container_spec(if c == b'[' { b']' } else { b'}' })?;
                let kind = if c == b'[' {
                    Kind::Array(Vec::new())
                } else {
                    Kind::Map {
                        entries: Vec::new(),
                        key: None,
                    }
                };
                Ok(Begun::Open(kind, spec, 1))
            }
            b'<' if self.peek_at(1) == Some(b'<') => {
                self.pos += 2;
                Ok(Begun::Open(Kind::Embedded(Vec::new()), None, 1))
            }
            b'(' if self.peek_at(1) == Some(b'_') => {
                self.pos += 2;
                if !self.skip_blank()? {
                    return self.unexpected();
                }
                self.warn(start, WarningKind::Streamstring)?;
                Ok(Begun::Open(Kind::Stream(Vec::new()), None, 0))
            }
            b'"' => {
                let t = self.dq_string()?;
                Ok(Begun::Item(self.with_spec(Item::text(t))?))
            }
            b'\'' => {
                let t = self.sq_string()?;
                Ok(Begun::Item(self.with_spec(Item::bytes(t.into_bytes()))?))
            }
            b'`' => {
                let t = self.raw_string()?;
                Ok(Begun::Item(self.with_spec(Item::text(t))?))
            }
            b'0'..=b'9' | b'+' | b'-' | b'.' => self.number(),
            c if c.is_ascii_alphabetic() => self.word(depth),
            _ => self.unexpected(),
        }
    }

    /// The optional indicator right after `[` or `{`, which must be followed
    /// by blank space or the closing delimiter.
    fn container_spec(&mut self, closer: u8) -> Res<Option<(usize, Spec)>> {
        let spec = self.spec();
        if spec.is_some() {
            match self.peek() {
                Some(c) if c == closer || is_blank_start(c) => {}
                _ => return self.unexpected(),
            }
        }
        Ok(spec)
    }

    /// An encoding indicator at the current position, if any.
    fn spec(&mut self) -> Option<(usize, Spec)> {
        if self.peek() != Some(b'_') {
            return None;
        }
        let at = self.pos;
        self.pos += 1;
        let from = self.pos;
        while self.peek().is_some_and(is_word) {
            self.pos += 1;
        }
        let word = self.src.get(from..self.pos).unwrap_or_default();
        let spec = match word {
            "" => Spec::Indefinite,
            "i" => Spec::Width(Width::Immediate),
            "0" => Spec::Width(Width::U8),
            "1" => Spec::Width(Width::U16),
            "2" => Spec::Width(Width::U32),
            "3" => Spec::Width(Width::U64),
            other => Spec::Reserved(other.to_owned()),
        };
        Some((at, spec))
    }

    /// Reads an optional indicator and applies it to `item`.
    fn with_spec(&mut self, item: Item<'static>) -> Res<Item<'static>> {
        match self.spec() {
            None => Ok(item),
            Some(spec) => self.apply_spec(item, spec),
        }
    }

    fn apply_container_spec(
        &mut self,
        item: Item<'static>,
        spec: Option<(usize, Spec)>,
    ) -> Res<Item<'static>> {
        match spec {
            None => Ok(item),
            Some(spec) => self.apply_spec(item, spec),
        }
    }

    fn apply_spec(
        &mut self,
        mut item: Item<'static>,
        (at, spec): (usize, Spec),
    ) -> Res<Item<'static>> {
        let bad = |p: &Self| p.fail(at, EdnErrorKind::InvalidEncodingIndicator);
        let width = match spec {
            Spec::Reserved(word) => {
                self.warn(at, WarningKind::ReservedEncodingIndicator(word))?;
                return Ok(item);
            }
            Spec::Indefinite => {
                return match &item.value {
                    Value::Array(_) | Value::Map(_) => Ok(item.with_width(Width::Indefinite)),
                    Value::Bytes(b) if b.is_empty() && item.chunks.is_empty() => {
                        Ok(item.with_width(Width::Indefinite))
                    }
                    Value::Text(t) if t.is_empty() && item.chunks.is_empty() => {
                        Ok(item.with_width(Width::Indefinite))
                    }
                    _ => bad(self),
                };
            }
            Spec::Width(w) => w,
        };
        let arg = match &item.value {
            Value::Uint(n) | Value::Nint(n) | Value::Tag(n, _) => *n,
            Value::Bytes(b) => len_u64(b.len()),
            Value::Text(t) => len_u64(t.len()),
            Value::Array(a) => len_u64(a.len()),
            Value::Map(m) => len_u64(m.len()),
            Value::Float(f, _) => {
                let fw = match width {
                    Width::U16 => FloatWidth::F16,
                    Width::U32 => FloatWidth::F32,
                    Width::U64 => FloatWidth::F64,
                    _ => return bad(self),
                };
                if !float_fits(*f, fw) {
                    return bad(self);
                }
                item.value = Value::Float(*f, fw);
                return Ok(item);
            }
            Value::Bool(_) | Value::Null | Value::Undefined | Value::Simple(_) => return bad(self),
        };
        if !fits(width, arg) {
            return bad(self);
        }
        item.chunks.clear();
        Ok(item.with_width(width))
    }

    // ------------------------------------------------------------ words

    /// An identifier: a keyword, `simple(…)`, or an app-extension prefix.
    fn word(&mut self, depth: usize) -> Res<Begun> {
        let start = self.pos;
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            self.pos += 1;
        }
        let word = self.src.get(start..self.pos).unwrap_or_default();
        let next = self.peek();
        if matches!(next, Some(b'\'' | b'`')) || self.starts_with(b"<<") {
            return self.prefixed(word, start, depth);
        }
        let item = match word {
            "false" => Item::new(Value::Bool(false)),
            "true" => Item::new(Value::Bool(true)),
            "null" => Item::new(Value::Null),
            "undefined" => Item::new(Value::Undefined),
            "Infinity" => Item::float(f64::INFINITY),
            "NaN" => Item::float(f64::from_bits(CANONICAL_NAN)),
            "simple" if next == Some(b'(') => {
                self.pos += 1;
                self.skip_blank()?;
                let at = self.pos;
                let digits = self.digits(10);
                if digits == 0 {
                    return self.unexpected();
                }
                let text = self.src.get(at..self.pos).unwrap_or_default();
                let n: u64 = text.parse().unwrap_or(u64::MAX);
                if (digits > 1 && text.starts_with('0')) || n > 255 || (24..32).contains(&n) {
                    return self.fail(at, EdnErrorKind::OutOfRange);
                }
                self.skip_blank()?;
                if self.peek() != Some(b')') {
                    return self.unexpected();
                }
                self.pos += 1;
                Item::simple(u8::try_from(n).unwrap_or(0))
            }
            _ => {
                self.pos = start;
                return self.unexpected();
            }
        };
        let item = self.with_spec(item)?;
        self.check_nan(start, &item)?;
        Ok(Begun::Item(item))
    }

    /// Warns about a NaN that does not encode as the canonical `f97e00`.
    fn check_nan(&mut self, start: usize, item: &Item<'_>) -> Res<()> {
        if let Value::Float(f, _) = item.value
            && f.is_nan()
            && encode(item, EncodeMode::Preserve).ok().as_deref() != Some(&CANONICAL_NAN_CBOR[..])
        {
            self.warn(start, WarningKind::NonCanonicalNaN)?;
        }
        Ok(())
    }

    /// A prefixed literal: `p'…'`, ``p`…` ``, or `p<<…>>` (opened).
    fn prefixed(&mut self, prefix: &'s str, start: usize, depth: usize) -> Res<Begun> {
        let lower = prefix
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
        let upper = prefix
            .bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'-');
        if !(lower || upper) || matches!(prefix, "true" | "false" | "null" | "undefined") {
            return self.fail(start, EdnErrorKind::InvalidPrefix);
        }
        let known = self
            .options
            .extensions
            .get(&prefix.to_ascii_lowercase())
            .is_some();
        if !known && self.options.unknown_extensions == UnknownExtensions::Error {
            return self.fail(start, EdnErrorKind::UnknownExtension(prefix.to_owned()));
        }
        let content = match self.peek() {
            Some(b'\'') => self.sq_string()?,
            Some(b'`') => self.raw_string()?,
            _ => {
                self.pos += 2;
                let kind = Kind::ExtSeq {
                    prefix: prefix.to_owned(),
                    items: Vec::new(),
                };
                // An unresolved literal nests its arguments in a tag and
                // two arrays.
                return Ok(Begun::Open(kind, None, if known { 1 } else { 3 }));
            }
        };
        let item = self.evaluate(prefix, vec![Item::text(content)], start)?;
        if depth + height(&item) > MAX_DEPTH {
            return self.fail(start, EdnErrorKind::DepthLimit);
        }
        let item = self.with_spec(item)?;
        self.check_nan(start, &item)?;
        Ok(Begun::Item(item))
    }

    /// Runs the extension for `prefix`, or builds the opaque value.
    fn evaluate(
        &mut self,
        prefix: &str,
        args: Vec<Item<'static>>,
        start: usize,
    ) -> Res<Item<'static>> {
        let uppercase = prefix.bytes().any(|c| c.is_ascii_uppercase());
        let name = prefix.to_ascii_lowercase();
        let Some(ext) = self.options.extensions.get(&name) else {
            if self.options.unknown_extensions == UnknownExtensions::Error {
                return self.fail(start, EdnErrorKind::UnknownExtension(prefix.to_owned()));
            }
            self.warn(start, WarningKind::UnknownExtension(prefix.to_owned()))?;
            return Ok(Item::tag(
                UNRESOLVED_EXTENSION_TAG,
                Item::array(vec![Item::text(prefix.to_owned()), Item::array(args)]),
            ));
        };
        match ext.evaluate(&args, uppercase) {
            Ok(item) => {
                // `h''` with an ellipsis gives the tag-888 form.
                if matches!(item.value, Value::Tag(ELLIPSIS_TAG, _)) {
                    self.warn(start, WarningKind::Ellipsis)?;
                }
                Ok(item)
            }
            Err(e) => self.fail(
                start,
                EdnErrorKind::Extension {
                    prefix: prefix.to_owned(),
                    message: e.0,
                },
            ),
        }
    }

    // ------------------------------------------------------------ numbers

    /// Consumes digits of `radix`; returns how many.
    fn digits(&mut self, radix: u32) -> usize {
        let from = self.pos;
        while self.peek().is_some_and(|c| char::from(c).is_digit(radix)) {
            self.pos += 1;
        }
        self.pos - from
    }

    fn number(&mut self) -> Res<Begun> {
        let start = self.pos;
        let neg = match self.peek() {
            Some(b'-') => {
                self.pos += 1;
                true
            }
            Some(b'+') => {
                self.pos += 1;
                false
            }
            _ => false,
        };
        let signed = self.pos > start;
        if neg && self.starts_with(b"Infinity") {
            self.pos += 8;
            if self.peek().is_some_and(|c| c.is_ascii_alphanumeric()) {
                return self.fail(start, EdnErrorKind::InvalidNumber);
            }
            return Ok(Begun::Item(self.with_spec(Item::float(f64::NEG_INFINITY))?));
        }
        let radix = match (self.peek(), self.peek_at(1)) {
            (Some(b'0'), Some(b'x' | b'X')) => 16,
            (Some(b'0'), Some(b'o' | b'O')) => 8,
            (Some(b'0'), Some(b'b' | b'B')) => 2,
            _ => 10,
        };
        let num = if radix == 16 {
            self.pos += 2;
            let int = self.pos;
            let n_int = self.digits(16);
            let int_digits = int..self.pos;
            let mut frac_digits = self.pos..self.pos;
            let mut dot = false;
            if self.peek() == Some(b'.') {
                dot = true;
                self.pos += 1;
                let f = self.pos;
                self.digits(16);
                frac_digits = f..self.pos;
            }
            if n_int == 0 && frac_digits.is_empty() {
                return self.fail(start, EdnErrorKind::InvalidNumber);
            }
            if matches!(self.peek(), Some(b'p' | b'P')) {
                self.pos += 1;
                let exp = self
                    .exponent()
                    .ok_or(())
                    .or_else(|()| self.fail(start, EdnErrorKind::InvalidNumber))?;
                let f = self
                    .hex_float(int_digits, frac_digits, exp, neg)
                    .ok_or(())
                    .or_else(|()| self.fail(start, EdnErrorKind::InvalidNumber))?;
                Num::Float(f)
            } else if dot {
                return self.fail(start, EdnErrorKind::InvalidNumber);
            } else {
                Num::Int(int_digits)
            }
        } else if radix != 10 {
            self.pos += 2;
            let from = self.pos;
            if self.digits(radix) == 0 {
                return self.fail(start, EdnErrorKind::InvalidNumber);
            }
            Num::Int(from..self.pos)
        } else {
            let int = self.pos;
            let n_int = self.digits(10);
            let int_digits = int..self.pos;
            let mut is_float = false;
            let mut n_frac = 0;
            if self.peek() == Some(b'.') {
                is_float = true;
                self.pos += 1;
                n_frac = self.digits(10);
            }
            if n_int == 0 && n_frac == 0 {
                return self.fail(start, EdnErrorKind::InvalidNumber);
            }
            if n_int > 1 && self.b.get(int) == Some(&b'0') {
                // Leading zeros; a tag number reports them as out of range.
                if !is_float && !signed && self.after_spec_is_paren() {
                    return self.fail(start, EdnErrorKind::OutOfRange);
                }
                return self.fail(start, EdnErrorKind::InvalidNumber);
            }
            if matches!(self.peek(), Some(b'e' | b'E')) {
                is_float = true;
                self.pos += 1;
                self.exponent()
                    .ok_or(())
                    .or_else(|()| self.fail(start, EdnErrorKind::InvalidNumber))?;
            }
            if is_float {
                let text = self.src.get(start..self.pos).unwrap_or_default();
                let f: f64 = text
                    .strip_prefix('+')
                    .unwrap_or(text)
                    .parse()
                    .or_else(|_| self.fail(start, EdnErrorKind::InvalidNumber))?;
                if f.is_infinite() {
                    return self.fail(start, EdnErrorKind::InvalidNumber);
                }
                Num::Float(f)
            } else {
                Num::Int(int_digits)
            }
        };
        if self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == b'.')
        {
            return self.fail(start, EdnErrorKind::InvalidNumber);
        }
        let spec = self.spec();
        match num {
            Num::Float(f) => {
                let item = Item::float(f);
                Ok(Begun::Item(match spec {
                    Some(s) => self.apply_spec(item, s)?,
                    None => item,
                }))
            }
            Num::Int(digits) => {
                let text = self.src.get(digits).unwrap_or_default();
                let magnitude = big_uint(text, radix);
                if radix == 10 && !signed && self.peek() == Some(b'(') {
                    return self.open_tag(start, &magnitude, spec);
                }
                self.integer(neg, magnitude, spec).map(Begun::Item)
            }
        }
    }

    /// Whether an optional indicator and then `(` follow.
    fn after_spec_is_paren(&self) -> bool {
        let mut i = self.pos;
        if self.b.get(i) == Some(&b'_') {
            i += 1;
            while self.b.get(i).copied().is_some_and(is_word) {
                i += 1;
            }
        }
        self.b.get(i) == Some(&b'(')
    }

    /// `N(`: opens a tag.
    fn open_tag(
        &mut self,
        start: usize,
        magnitude: &[u8],
        spec: Option<(usize, Spec)>,
    ) -> Res<Begun> {
        let Some(number) = to_u64(magnitude) else {
            return self.fail(start, EdnErrorKind::OutOfRange);
        };
        if number == ELLIPSIS_TAG {
            self.warn(start, WarningKind::Ellipsis)?;
        }
        let mut width = Width::preferred_for(number);
        match spec {
            None => {}
            Some((at, Spec::Reserved(word))) => {
                self.warn(at, WarningKind::ReservedEncodingIndicator(word))?;
            }
            Some((_, Spec::Width(w))) if fits(w, number) => width = w,
            Some((at, _)) => return self.fail(at, EdnErrorKind::InvalidEncodingIndicator),
        }
        self.pos += 1;
        let kind = Kind::Tag {
            number,
            width,
            content: None,
        };
        Ok(Begun::Open(kind, None, 1))
    }

    /// An integer literal: an int, or a bignum (tag 2/3) beyond 64 bits.
    fn integer(
        &mut self,
        neg: bool,
        magnitude: Vec<u8>,
        spec: Option<(usize, Spec)>,
    ) -> Res<Item<'static>> {
        let small = if neg {
            match magnitude.as_slice() {
                [] => Some(Value::Uint(0)),
                _ => to_u64(&minus_one(&magnitude)).map(Value::Nint),
            }
        } else {
            to_u64(&magnitude).map(Value::Uint)
        };
        if let Some(value) = small {
            let item = Item::new(value);
            return match spec {
                Some(s) => self.apply_spec(item, s),
                None => Ok(item),
            };
        }
        let (tag, bytes) = if neg {
            (3, minus_one(&magnitude))
        } else {
            (2, magnitude)
        };
        match spec {
            None => {}
            Some((at, Spec::Reserved(word))) => {
                self.warn(at, WarningKind::ReservedEncodingIndicator(word))?
            }
            Some((at, Spec::Indefinite)) => {
                return self.fail(at, EdnErrorKind::InvalidEncodingIndicator);
            }
            Some((at, Spec::Width(_))) => self.warn(at, WarningKind::IgnoredEncodingIndicator)?,
        }
        Ok(Item::tag(tag, Item::bytes(bytes)))
    }

    /// `[sign] 1*DIGIT` after `e` or `p`, saturated to ±2^40.
    fn exponent(&mut self) -> Option<i64> {
        let neg = match self.peek() {
            Some(b'-') => {
                self.pos += 1;
                true
            }
            Some(b'+') => {
                self.pos += 1;
                false
            }
            _ => false,
        };
        let from = self.pos;
        if self.digits(10) == 0 {
            return None;
        }
        let mut e: i64 = 0;
        for &d in self.b.get(from..self.pos).unwrap_or_default() {
            e = (e * 10 + i64::from(d - b'0')).min(1 << 40);
        }
        Some(if neg { -e } else { e })
    }

    /// A hex float, correctly rounded; `None` if it overflows.
    fn hex_float(&self, int: Range<usize>, frac: Range<usize>, exp: i64, neg: bool) -> Option<f64> {
        let mut m: u64 = 0;
        let mut sig = 0;
        let mut sticky = false;
        let mut e = exp;
        let int = self.b.get(int).unwrap_or_default();
        let frac = self.b.get(frac).unwrap_or_default();
        let digits = int
            .iter()
            .map(|d| (d, false))
            .chain(frac.iter().map(|d| (d, true)));
        for (&d, is_frac) in digits {
            let d = char::from(d).to_digit(16).map_or(0, u64::from);
            if is_frac {
                e -= 4;
            }
            if m == 0 && d == 0 {
                continue;
            }
            if sig < 16 {
                m = m << 4 | d;
                sig += 1;
            } else {
                e += 4;
                sticky |= d != 0;
            }
        }
        make_f64(m, sticky, e, neg)
    }

    // ------------------------------------------------------------ strings

    /// A `"…"` text string.
    fn dq_string(&mut self) -> Res<String> {
        self.quoted(b'"', |c| match c {
            '"' | '\\' | '/' => Some(c),
            _ => None,
        })
    }

    /// A `'…'` string (byte string or app-string content).
    fn sq_string(&mut self) -> Res<String> {
        self.quoted(b'\'', |c| match c {
            '\'' | '\\' => Some(c),
            _ => None,
        })
    }

    /// A quoted string; `simple_escape` maps the characters that may follow
    /// a backslash (besides `b f n r t u`) to themselves.
    fn quoted(&mut self, quote: u8, simple_escape: fn(char) -> Option<char>) -> Res<String> {
        self.pos += 1;
        let mut out = String::new();
        loop {
            // Copy the run of ordinary characters at once.
            let rest = self.b.get(self.pos..).unwrap_or_default();
            let run = rest
                .iter()
                .position(|&c| c == quote || c == b'\\' || c < 0x20)
                .unwrap_or(rest.len());
            out.push_str(self.src.get(self.pos..self.pos + run).unwrap_or_default());
            self.pos += run;
            let Some(c) = self.peek() else {
                return self.fail(self.b.len(), EdnErrorKind::UnexpectedEnd);
            };
            match c {
                _ if c == quote => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    let at = self.pos;
                    self.pos += 1;
                    let Some(e) = self.peek_char() else {
                        return self.fail(self.b.len(), EdnErrorKind::UnexpectedEnd);
                    };
                    self.pos += e.len_utf8();
                    let decoded = match e {
                        'b' => '\u{8}',
                        'f' => '\u{c}',
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        'u' => {
                            let cp = self.unicode_escape(at)?;
                            if quote == b'\'' && (' '..='~').contains(&cp) {
                                return self.fail(at, EdnErrorKind::InvalidEscape);
                            }
                            cp
                        }
                        _ => match simple_escape(e) {
                            Some(c) => c,
                            None => return self.fail(at, EdnErrorKind::InvalidEscape),
                        },
                    };
                    out.push(decoded);
                }
                b'\r' => self.pos += 1,
                b'\n' => {
                    out.push('\n');
                    self.pos += 1;
                }
                _ => return self.fail(self.pos, EdnErrorKind::ControlCharacter),
            }
        }
    }

    /// The rest of a `\u` escape that started at `at`.
    fn unicode_escape(&mut self, at: usize) -> Res<char> {
        if self.peek() == Some(b'{') {
            self.pos += 1;
            let mut cp: u32 = 0;
            let mut n = 0;
            loop {
                match self.peek() {
                    None => return self.fail(self.b.len(), EdnErrorKind::UnexpectedEnd),
                    Some(b'}') if n > 0 => {
                        self.pos += 1;
                        break;
                    }
                    Some(c) => match char::from(c).to_digit(16) {
                        Some(d) => {
                            cp = cp.saturating_mul(16).saturating_add(d);
                            n += 1;
                            self.pos += 1;
                        }
                        None => return self.fail(at, EdnErrorKind::InvalidEscape),
                    },
                }
            }
            return char::from_u32(cp)
                .ok_or(())
                .or_else(|()| self.fail(at, EdnErrorKind::InvalidCodePoint));
        }
        let first = self.hex4(at)?;
        let cp = match first {
            0xd800..=0xdbff => {
                if !self.starts_with(b"\\u") {
                    return self.fail(at, EdnErrorKind::InvalidCodePoint);
                }
                self.pos += 2;
                let low = self.hex4(at)?;
                if !(0xdc00..=0xdfff).contains(&low) {
                    return self.fail(at, EdnErrorKind::InvalidCodePoint);
                }
                0x10000 + ((first - 0xd800) << 10) + (low - 0xdc00)
            }
            _ => first,
        };
        char::from_u32(cp)
            .ok_or(())
            .or_else(|()| self.fail(at, EdnErrorKind::InvalidCodePoint))
    }

    fn hex4(&mut self, at: usize) -> Res<u32> {
        let mut v = 0;
        for _ in 0..4 {
            match self.peek() {
                None => return self.fail(self.b.len(), EdnErrorKind::UnexpectedEnd),
                Some(c) => match char::from(c).to_digit(16) {
                    Some(d) => v = v * 16 + d,
                    None => return self.fail(at, EdnErrorKind::InvalidEscape),
                },
            }
            self.pos += 1;
        }
        Ok(v)
    }

    /// A raw string between runs of backquotes.
    fn raw_string(&mut self) -> Res<String> {
        let open = self.pos;
        while self.peek() == Some(b'`') {
            self.pos += 1;
        }
        let n = self.pos - open;
        let mut out = String::new();
        loop {
            let rest = self.b.get(self.pos..).unwrap_or_default();
            let run = rest
                .iter()
                .position(|&c| c == b'`' || (c < 0x20 && c != b'\n'))
                .unwrap_or(rest.len());
            out.push_str(self.src.get(self.pos..self.pos + run).unwrap_or_default());
            self.pos += run;
            match self.peek() {
                None => return self.fail(self.b.len(), EdnErrorKind::UnexpectedEnd),
                Some(b'`') => {
                    let from = self.pos;
                    while self.peek() == Some(b'`') {
                        self.pos += 1;
                    }
                    if self.pos - from == n {
                        break;
                    }
                    out.push_str(self.src.get(from..self.pos).unwrap_or_default());
                }
                Some(b'\r') => self.pos += 1,
                Some(_) => return self.fail(self.pos, EdnErrorKind::ControlCharacter),
            }
        }
        if let Some(rest) = out.strip_prefix('\n') {
            return Ok(rest.to_owned());
        }
        if out.len() >= 2 && out.starts_with(' ') && out.ends_with(' ') {
            return Ok(out.get(1..out.len() - 1).unwrap_or_default().to_owned());
        }
        Ok(out)
    }
}

/// The canonical NaN as CBOR.
const CANONICAL_NAN_CBOR: [u8; 3] = [0xf9, 0x7e, 0x00];

/// The quiet NaN with no payload.
pub(crate) const CANONICAL_NAN: u64 = 0x7ff8_0000_0000_0000;

enum Num {
    Int(Range<usize>),
    Float(f64),
}

enum Closed {
    Item(Item<'static>),
    Done(Vec<Item<'static>>),
}

/// Pushes the children of `item` (at `path`) so they pop in pre-order.
pub(crate) fn push_children<'i, 'a>(
    stack: &mut Vec<(Path, &'i Item<'a>)>,
    path: &Path,
    item: &'i Item<'a>,
) {
    let mut kids: Vec<(Path, &Item<'_>)> = Vec::new();
    match &item.value {
        Value::Array(items) => {
            for (i, c) in items.iter().enumerate() {
                kids.push((path.child(PathSegment::Index(i)), c));
            }
        }
        Value::Map(entries) => {
            for (i, (k, v)) in entries.iter().enumerate() {
                kids.push((path.child(PathSegment::Key(i)), k));
                kids.push((path.child(PathSegment::Value(i)), v));
            }
        }
        Value::Tag(_, inner) => kids.push((path.child(PathSegment::TagContent), inner)),
        _ => {
            for (i, c) in item.chunks.iter().enumerate() {
                kids.push((path.child(PathSegment::Chunk(i)), c));
            }
        }
    }
    stack.extend(kids.into_iter().rev());
}

/// Digits in `radix` as a minimal big-endian magnitude (empty for zero).
fn big_uint(digits: &str, radix: u32) -> Vec<u8> {
    let values = digits.chars().filter_map(|c| c.to_digit(radix));
    let mut out: Vec<u8> = if radix.is_power_of_two() {
        // Pack bits from the least significant digit up: linear time.
        let bits = radix.trailing_zeros();
        let mut out = Vec::new();
        let (mut acc, mut n) = (0u32, 0u32);
        for d in values.rev() {
            acc |= d << n;
            n += bits;
            while n >= 8 {
                out.push(acc as u8);
                acc >>= 8;
                n -= 8;
            }
        }
        if n > 0 {
            out.push(acc as u8);
        }
        out.reverse();
        out
    } else {
        // Little-endian 32-bit limbs, nine decimal digits at a time.
        let mut limbs: Vec<u32> = Vec::new();
        let mut chunk = (0u64, 1u64);
        let flush = |limbs: &mut Vec<u32>, (value, scale): (u64, u64)| {
            let mut carry = value;
            for limb in limbs.iter_mut() {
                let v = u64::from(*limb) * scale + carry;
                *limb = v as u32;
                carry = v >> 32;
            }
            if carry > 0 {
                limbs.push(carry as u32);
            }
        };
        for d in values {
            chunk = (
                chunk.0 * u64::from(radix) + u64::from(d),
                chunk.1 * u64::from(radix),
            );
            if chunk.1 >= 1_000_000_000 {
                flush(&mut limbs, chunk);
                chunk = (0, 1);
            }
        }
        if chunk.1 > 1 {
            flush(&mut limbs, chunk);
        }
        limbs.iter().rev().flat_map(|l| l.to_be_bytes()).collect()
    };
    let zeros = out.iter().take_while(|&&b| b == 0).count();
    out.drain(..zeros);
    out
}

/// A non-zero magnitude minus one, minimal.
fn minus_one(magnitude: &[u8]) -> Vec<u8> {
    let mut out = magnitude.to_vec();
    for b in out.iter_mut().rev() {
        let (v, borrow) = b.overflowing_sub(1);
        *b = v;
        if !borrow {
            break;
        }
    }
    let zeros = out.iter().take_while(|&&b| b == 0).count();
    out.drain(..zeros);
    out
}

fn to_u64(magnitude: &[u8]) -> Option<u64> {
    if magnitude.len() > 8 {
        return None;
    }
    Some(
        magnitude
            .iter()
            .fold(0u64, |acc, &b| acc << 8 | u64::from(b)),
    )
}

/// `m * 2^e` (with `sticky` standing for nonzero bits below `m`), rounded
/// to nearest-even binary64; `None` on overflow.
fn make_f64(m: u64, sticky: bool, e: i64, neg: bool) -> Option<f64> {
    let sign = if neg { 1u64 << 63 } else { 0 };
    if m == 0 {
        return Some(f64::from_bits(sign));
    }
    let lz = m.leading_zeros();
    let m = m << lz;
    // Exponent of the leading bit.
    let top = e - i64::from(lz) + 63;
    if top > 1023 {
        return None;
    }
    let shift = if top >= -1022 { 11 } else { 11 + (-1022 - top) };
    if shift > 64 {
        return Some(f64::from_bits(sign));
    }
    let shift = shift as u32;
    let mm = u128::from(m);
    let mut kept = (mm >> shift) as u64;
    let rem = mm & ((1u128 << shift) - 1);
    let half = 1u128 << (shift - 1);
    if rem > half || (rem == half && (sticky || kept & 1 == 1)) {
        kept += 1;
    }
    let bits = if top >= -1022 {
        let (kept, top) = if kept == 1 << 53 {
            (kept >> 1, top + 1)
        } else {
            (kept, top)
        };
        if top > 1023 {
            return None;
        }
        ((top + 1023) as u64) << 52 | (kept & ((1 << 52) - 1))
    } else {
        // Subnormal; rounding up to 2^52 gives the smallest normal.
        kept
    };
    Some(f64::from_bits(sign | bits))
}
