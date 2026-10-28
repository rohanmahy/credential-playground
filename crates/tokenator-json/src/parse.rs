//! Recursive-descent parser. Recursion depth is bounded by
//! [`ParseOptions::max_depth`], which is checked before descending.

use std::borrow::Cow;

use crate::{
    ErrorKind, JsonError, Member, Node, ParseOptions, Parsed, Span, Value, Warning, WarningKind,
};

const BOM: &[u8] = b"\xEF\xBB\xBF";

pub(crate) fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// Largest integer JavaScript represents exactly (`Number.MAX_SAFE_INTEGER`).
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

pub(crate) fn parse<'a>(input: &'a [u8], options: &ParseOptions) -> Result<Parsed<'a>, JsonError> {
    if input.starts_with(BOM) {
        return Err(JsonError {
            offset: 0,
            kind: ErrorKind::ByteOrderMark,
        });
    }
    let mut p = Parser {
        bytes: input,
        pos: 0,
        max_depth: options.max_depth,
        warnings: Vec::new(),
    };
    p.skip_ws();
    let root = p.value(0)?;
    p.skip_ws();
    if p.pos < input.len() {
        return Err(p.err(ErrorKind::TrailingCharacters, p.pos));
    }
    Ok(Parsed {
        node: root,
        // Produced left to right, so already sorted by offset.
        warnings: p.warnings,
    })
}

/// Text of a byte range the parser has already validated as UTF-8.
fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap_or_default()
}

/// Range warning for a number lexeme, if any.
fn number_warning(lexeme: &str) -> Option<WarningKind> {
    let has_exp = lexeme.contains(['e', 'E']);
    // Short plain lexemes are always within range: |x| < 1e15, x >= 1e-13.
    if !has_exp && lexeme.len() <= 15 {
        return None;
    }
    let v: f64 = lexeme.parse().ok()?;
    let mantissa = lexeme.split(['e', 'E']).next().unwrap_or_default();
    if v.is_infinite() {
        Some(WarningKind::NumberOverflow)
    } else if !has_exp && !lexeme.contains('.') && v.abs() > MAX_SAFE_INTEGER {
        Some(WarningKind::UnsafeInteger)
    } else if v == 0.0 && mantissa.bytes().any(|b| matches!(b, b'1'..=b'9')) {
        Some(WarningKind::NumberUnderflow)
    } else {
        None
    }
}

/// Length of the UTF-8 sequence led by `lead` (assumed valid).
fn utf8_len(lead: u8) -> usize {
    match lead {
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    max_depth: usize,
    warnings: Vec<Warning>,
}

impl<'a> Parser<'a> {
    fn err(&self, kind: ErrorKind, offset: usize) -> JsonError {
        JsonError { offset, kind }
    }

    fn end(&self) -> JsonError {
        self.err(ErrorKind::UnexpectedEnd, self.bytes.len())
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Next byte, or `UnexpectedEnd`.
    fn need(&self) -> Result<u8, JsonError> {
        self.peek().ok_or_else(|| self.end())
    }

    fn skip_ws(&mut self) {
        while self.peek().is_some_and(is_ws) {
            self.pos += 1;
        }
    }

    fn slice(&self, start: usize, end: usize) -> &'a [u8] {
        self.bytes.get(start..end).unwrap_or_default()
    }

    fn warn(&mut self, kind: WarningKind, offset: usize) {
        self.warnings.push(Warning { offset, kind });
    }

    fn node(&self, start: usize, value: Value<'a>) -> Node<'a> {
        Node {
            span: Some(Span {
                start,
                end: self.pos,
            }),
            raw: Some(self.slice(start, self.pos)),
            value,
            edited: false,
        }
    }

    /// Parse a value at `self.pos` (whitespace already skipped). `depth` is
    /// the number of enclosing containers.
    fn value(&mut self, depth: usize) -> Result<Node<'a>, JsonError> {
        let start = self.pos;
        match self.need()? {
            b'[' | b'{' if depth >= self.max_depth => {
                Err(self.err(ErrorKind::DepthLimitExceeded, start))
            }
            b'[' => self.array(depth + 1),
            b'{' => self.object(depth + 1),
            b'"' => {
                let s = self.string()?;
                Ok(self.node(start, Value::String(s)))
            }
            b't' => self.literal(b"true", Value::Bool(true)),
            b'f' => self.literal(b"false", Value::Bool(false)),
            b'n' => self.literal(b"null", Value::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(self.err(ErrorKind::UnexpectedCharacter, start)),
        }
    }

    fn literal(&mut self, word: &[u8], value: Value<'a>) -> Result<Node<'a>, JsonError> {
        let start = self.pos;
        for &want in word {
            if self.need()? != want {
                return Err(self.err(ErrorKind::UnexpectedCharacter, self.pos));
            }
            self.pos += 1;
        }
        Ok(self.node(start, value))
    }

    fn digits(&mut self) {
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.pos += 1;
        }
    }

    /// At least one digit is required here.
    fn require_digit(&mut self) -> Result<(), JsonError> {
        if !self.need()?.is_ascii_digit() {
            return Err(self.err(ErrorKind::InvalidNumber, self.pos));
        }
        self.digits();
        Ok(())
    }

    fn number(&mut self) -> Result<Node<'a>, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.need()? {
            b'0' => {
                self.pos += 1;
                if self.peek().is_some_and(|b| b.is_ascii_digit()) {
                    return Err(self.err(ErrorKind::InvalidNumber, self.pos));
                }
            }
            b'1'..=b'9' => self.digits(),
            _ => return Err(self.err(ErrorKind::InvalidNumber, self.pos)),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            self.require_digit()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            self.require_digit()?;
        }
        let lexeme = text(self.slice(start, self.pos));
        if let Some(kind) = number_warning(lexeme) {
            self.warn(kind, start);
        }
        Ok(self.node(start, Value::Number(Cow::Borrowed(lexeme))))
    }

    /// Parse a string at the opening quote. Borrows unless it has escapes
    /// or invalid UTF-8 (which decodes to U+FFFD, like
    /// [`String::from_utf8_lossy`], with one warning per replacement).
    fn string(&mut self) -> Result<Cow<'a, str>, JsonError> {
        self.pos += 1;
        let mut run = self.pos;
        let mut buf: Option<String> = None;
        loop {
            match self.need()? {
                b'"' => {
                    let tail = text(self.slice(run, self.pos));
                    self.pos += 1;
                    return Ok(match buf {
                        None => Cow::Borrowed(tail),
                        Some(mut s) => {
                            s.push_str(tail);
                            Cow::Owned(s)
                        }
                    });
                }
                b'\\' => {
                    let s = buf.get_or_insert_with(String::new);
                    s.push_str(text(self.slice(run, self.pos)));
                    s.push(self.escape()?);
                    run = self.pos;
                }
                0..=0x1f => return Err(self.err(ErrorKind::ControlCharacterInString, self.pos)),
                0x20..=0x7f => self.pos += 1,
                lead => {
                    let window =
                        self.slice(self.pos, self.pos.saturating_add(4).min(self.bytes.len()));
                    match std::str::from_utf8(window) {
                        Ok(_) => self.pos += utf8_len(lead),
                        Err(e) if e.valid_up_to() > 0 => self.pos += utf8_len(lead),
                        // Incomplete sequence at the end of the input.
                        Err(e) => {
                            let bad = e.error_len().ok_or_else(|| self.end())?;
                            let s = buf.get_or_insert_with(String::new);
                            s.push_str(text(self.slice(run, self.pos)));
                            s.push(char::REPLACEMENT_CHARACTER);
                            self.warn(WarningKind::InvalidUtf8, self.pos);
                            self.pos += bad;
                            run = self.pos;
                        }
                    }
                }
            }
        }
    }

    /// Decode one escape starting at the backslash.
    fn escape(&mut self) -> Result<char, JsonError> {
        let esc = self.pos;
        self.pos += 1;
        let b = self.need()?;
        self.pos += 1;
        Ok(match b {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => return self.unicode(esc),
            _ => return Err(self.err(ErrorKind::InvalidEscape, esc)),
        })
    }

    /// Decode the hex digits of a `\u` escape (and its low surrogate, if any).
    fn unicode(&mut self, esc: usize) -> Result<char, JsonError> {
        let lone = self.err(ErrorKind::LoneSurrogate, esc);
        let hi = self.hex4(esc)?;
        let cp = match hi {
            0xD800..=0xDBFF => {
                if self.need()? != b'\\' {
                    return Err(lone);
                }
                let esc2 = self.pos;
                match self.bytes.get(esc2 + 1) {
                    None => return Err(self.end()),
                    Some(b'u') => {}
                    Some(_) => return Err(lone),
                }
                self.pos += 2;
                let lo = self.hex4(esc2)?;
                if !(0xDC00..=0xDFFF).contains(&lo) {
                    return Err(lone);
                }
                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
            }
            0xDC00..=0xDFFF => return Err(lone),
            _ => hi,
        };
        char::from_u32(cp).ok_or(lone)
    }

    fn hex4(&mut self, esc: usize) -> Result<u32, JsonError> {
        let mut v = 0;
        for _ in 0..4 {
            let d = char::from(self.need()?)
                .to_digit(16)
                .ok_or_else(|| self.err(ErrorKind::InvalidEscape, esc))?;
            v = v * 16 + d;
            self.pos += 1;
        }
        Ok(v)
    }

    /// After a member or element: consume `,` (returning true) or `close`.
    fn separator(&mut self, close: u8) -> Result<bool, JsonError> {
        self.skip_ws();
        let b = self.need()?;
        self.pos += 1;
        match b {
            b',' => Ok(true),
            _ if b == close => Ok(false),
            _ => Err(self.err(ErrorKind::UnexpectedCharacter, self.pos - 1)),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Node<'a>, JsonError> {
        let start = self.pos;
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.need()? == b']' {
            self.pos += 1;
        } else {
            loop {
                self.skip_ws();
                items.push(self.value(depth)?);
                if !self.separator(b']')? {
                    break;
                }
            }
        }
        Ok(self.node(start, Value::Array(items)))
    }

    fn object(&mut self, depth: usize) -> Result<Node<'a>, JsonError> {
        let start = self.pos;
        self.pos += 1;
        let mut members = Vec::new();
        self.skip_ws();
        if self.need()? == b'}' {
            self.pos += 1;
        } else {
            loop {
                self.skip_ws();
                let key_start = self.pos;
                if self.need()? != b'"' {
                    return Err(self.err(ErrorKind::UnexpectedCharacter, key_start));
                }
                let key = self.string()?;
                let key_end = self.pos;
                self.skip_ws();
                if self.need()? != b':' {
                    return Err(self.err(ErrorKind::UnexpectedCharacter, self.pos));
                }
                self.pos += 1;
                self.skip_ws();
                let value = self.value(depth)?;
                members.push(Member {
                    key_span: Some(Span {
                        start: key_start,
                        end: key_end,
                    }),
                    key_raw: Some(self.slice(key_start, key_end)),
                    key,
                    key_edited: false,
                    value,
                });
                if !self.separator(b'}')? {
                    break;
                }
            }
        }
        Ok(self.node(start, Value::Object(members)))
    }
}
