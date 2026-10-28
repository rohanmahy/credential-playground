//! Serializer for the three [`PrintStyle`]s. Output is bytes, so source text
//! that is not valid UTF-8 can be copied exactly.
//!
//! `Original` prints containers that still have source text by copying the
//! source "gaps" (whitespace plus one `[`, `,`, `:`, or `]`) between
//! neighbours that are still adjacent in the source. Nothing else is needed
//! to decide what to copy: a gap is only reused if its text is exactly
//! whitespace around the right punctuation, so the output stays valid even
//! when nodes were moved, removed, or replaced. Everything that cannot be
//! copied follows [`InsertedLayout`].

use std::borrow::Cow;

use crate::parse::is_ws;
use crate::{InsertedLayout, Member, Node, PrintOptions, PrintStyle, Value};

/// Indent unit when no multi-line source container suggests one.
const DEFAULT_UNIT: &[u8] = b"  ";

pub(crate) fn print(node: &Node<'_>, options: &PrintOptions) -> Vec<u8> {
    let mut p = Printer {
        out: Vec::with_capacity(node.raw.map_or(64, <[u8]>::len)),
        canonical: options.inserted == InsertedLayout::Canonical,
    };
    match options.style {
        PrintStyle::Original => p.original(node, DEFAULT_UNIT),
        PrintStyle::Compact => p.compact(node),
        PrintStyle::Pretty => p.layout(node, &[], DEFAULT_UNIT, 0, Tokens::Normalized),
    }
    p.out
}

/// How unedited scalar and key tokens are emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tokens {
    /// Source text verbatim.
    Source,
    /// Pretty: string escapes normalized (see [`normalized`]).
    Normalized,
}

struct Printer {
    out: Vec<u8>,
    /// `InsertedLayout::Canonical` (only consulted by `original`).
    canonical: bool,
}

impl Printer {
    fn push(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }

    /// Token for a scalar: the source text if unedited, else freshly made.
    fn scalar(&mut self, node: &Node<'_>, tokens: Tokens) {
        if let (false, Some(raw)) = (node.edited, node.raw) {
            match (tokens, &node.value) {
                (Tokens::Normalized, Value::String(_)) => normalized(raw, &mut self.out),
                _ => self.push(raw),
            }
            return;
        }
        match &node.value {
            Value::Null => self.push(b"null"),
            Value::Bool(true) => self.push(b"true"),
            Value::Bool(false) => self.push(b"false"),
            Value::Number(n) => self.push(n.as_bytes()),
            Value::String(s) => escaped(s, &mut self.out),
            Value::Array(_) | Value::Object(_) => {}
        }
    }

    fn key(&mut self, member: &Member<'_>, tokens: Tokens) {
        match (member.key_edited, member.key_raw, tokens) {
            (false, Some(raw), Tokens::Source) => self.push(raw),
            (false, Some(raw), Tokens::Normalized) => normalized(raw, &mut self.out),
            _ => escaped(&member.key, &mut self.out),
        }
    }

    fn compact(&mut self, node: &Node<'_>) {
        match &node.value {
            Value::Array(xs) => {
                self.push(b"[");
                for (i, x) in xs.iter().enumerate() {
                    if i > 0 {
                        self.push(b",");
                    }
                    self.compact(x);
                }
                self.push(b"]");
            }
            Value::Object(ms) => {
                self.push(b"{");
                for (i, m) in ms.iter().enumerate() {
                    if i > 0 {
                        self.push(b",");
                    }
                    self.key(m, Tokens::Source);
                    self.push(b":");
                    self.compact(&m.value);
                }
                self.push(b"}");
            }
            _ => self.scalar(node, Tokens::Source),
        }
    }

    fn newline(&mut self, base: &[u8], unit: &[u8], depth: usize) {
        self.push(b"\n");
        self.push(base);
        for _ in 0..depth {
            self.push(unit);
        }
    }

    /// Pretty-style layout: each line starts with `base` plus `depth` units.
    /// Used for `Pretty` (normalized tokens) and for synthesized containers
    /// under `Canonical` (source tokens; children that are source containers
    /// go back to [`Printer::original`]).
    fn layout(&mut self, node: &Node<'_>, base: &[u8], unit: &[u8], depth: usize, tokens: Tokens) {
        match &node.value {
            Value::Array(xs) if xs.is_empty() => self.push(b"[]"),
            Value::Object(ms) if ms.is_empty() => self.push(b"{}"),
            Value::Array(xs) => {
                self.push(b"[");
                for (i, x) in xs.iter().enumerate() {
                    if i > 0 {
                        self.push(b",");
                    }
                    self.newline(base, unit, depth + 1);
                    self.layout_child(x, base, unit, depth + 1, tokens);
                }
                self.newline(base, unit, depth);
                self.push(b"]");
            }
            Value::Object(ms) => {
                self.push(b"{");
                for (i, m) in ms.iter().enumerate() {
                    if i > 0 {
                        self.push(b",");
                    }
                    self.newline(base, unit, depth + 1);
                    self.key(m, tokens);
                    self.push(b": ");
                    self.layout_child(&m.value, base, unit, depth + 1, tokens);
                }
                self.newline(base, unit, depth);
                self.push(b"}");
            }
            _ => self.scalar(node, tokens),
        }
    }

    fn layout_child(
        &mut self,
        node: &Node<'_>,
        base: &[u8],
        unit: &[u8],
        depth: usize,
        tokens: Tokens,
    ) {
        if tokens == Tokens::Source && source_container(node).is_some() {
            self.original(node, unit);
        } else {
            self.layout(node, base, unit, depth, tokens);
        }
    }

    /// Leading whitespace of the output line being written.
    fn line_indent(&self) -> Vec<u8> {
        let start = self
            .out
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |i| i + 1);
        self.out
            .get(start..)
            .unwrap_or_default()
            .iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .copied()
            .collect()
    }

    /// `Original` style. `unit` is the indent unit inherited from the nearest
    /// multi-line source container (used by `Canonical` only).
    fn original<'a>(&mut self, node: &Node<'a>, unit: &'a [u8]) {
        if !matches!(node.value, Value::Array(_) | Value::Object(_)) {
            return self.scalar(node, Tokens::Source);
        }
        let Some(src) = source_container(node) else {
            return self.synthesized(node, unit);
        };
        match &node.value {
            Value::Array(xs) => {
                let g = Gaps::new(src, xs.len(), |i| {
                    let l = locate(src, xs.get(i).and_then(|x| x.raw));
                    (l, l)
                });
                let unit = self.unit(&g, unit);
                g.open(&mut self.out);
                for (i, x) in xs.iter().enumerate() {
                    self.before(&g, i);
                    self.original(x, unit);
                }
                g.close(&mut self.out);
            }
            Value::Object(ms) => {
                let g = Gaps::new(src, ms.len(), |i| {
                    let m = ms.get(i);
                    (
                        locate(src, m.and_then(|m| m.key_raw)),
                        locate(src, m.and_then(|m| m.value.raw)),
                    )
                });
                let unit = self.unit(&g, unit);
                g.open(&mut self.out);
                for (i, m) in ms.iter().enumerate() {
                    self.before(&g, i);
                    self.key(m, Tokens::Source);
                    match (g.colon_gap(i), self.canonical, g.colon) {
                        (Some(c), _, _) | (None, false, Some(c)) => self.push(c),
                        (None, false, None) => self.push(b":"),
                        (None, true, _) => self.push(b": "),
                    }
                    self.original(&m.value, unit);
                }
                g.close(&mut self.out);
            }
            _ => {}
        }
    }

    /// A container without usable source text, under `Original`.
    fn synthesized<'a>(&mut self, node: &Node<'a>, unit: &'a [u8]) {
        if self.canonical {
            let base = self.line_indent();
            return self.layout(node, &base, unit, 0, Tokens::Source);
        }
        // Compact punctuation, but children may have source text of their own.
        match &node.value {
            Value::Array(xs) => {
                self.push(b"[");
                for (i, x) in xs.iter().enumerate() {
                    if i > 0 {
                        self.push(b",");
                    }
                    self.original(x, unit);
                }
                self.push(b"]");
            }
            Value::Object(ms) => {
                self.push(b"{");
                for (i, m) in ms.iter().enumerate() {
                    if i > 0 {
                        self.push(b",");
                    }
                    self.key(m, Tokens::Source);
                    self.push(b":");
                    self.original(&m.value, unit);
                }
                self.push(b"}");
            }
            _ => {}
        }
    }

    /// Indent unit for the children of a source container: its child indent
    /// minus the indent of the line its open bracket is on.
    fn unit<'a, F>(&self, g: &Gaps<'a, F>, inherited: &'a [u8]) -> &'a [u8] {
        if !self.canonical || !g.multiline() {
            return inherited;
        }
        let line = self.line_indent();
        g.child_indent()
            .strip_prefix(line.as_slice())
            .filter(|u| !u.is_empty())
            .unwrap_or(inherited)
    }

    /// Separator in front of child `i`.
    fn before<F: Fn(usize) -> (Loc, Loc)>(&mut self, g: &Gaps<'_, F>, i: usize) {
        if i == 0 {
            return;
        }
        let copied = g.sep_gap(i).or_else(|| g.preceding_gap(i));
        match (copied, self.canonical, g.sep) {
            (Some(s), _, _) | (None, false, Some(s)) => self.push(s),
            (None, false, None) => {
                self.push(b",");
                self.push(g.lead);
            }
            (None, true, _) if g.multiline() => {
                self.push(b",\n");
                self.push(g.child_indent());
            }
            (None, true, _) => self.push(b", "),
        }
    }
}

/// The node's source text, if it is the same kind of container as its value
/// (an edit may have turned `0` into `{...}`).
fn source_container<'a>(node: &Node<'a>) -> Option<&'a [u8]> {
    let open = match node.value {
        Value::Array(_) => b'[',
        Value::Object(_) => b'{',
        _ => return None,
    };
    node.raw.filter(|r| r.first() == Some(&open))
}

/// Write `\b\f\n\r\t` or a lowercase `\u00xx` escape for a control character.
fn control(c: u8, out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    match c {
        0x08 => out.extend_from_slice(b"\\b"),
        0x0c => out.extend_from_slice(b"\\f"),
        b'\n' => out.extend_from_slice(b"\\n"),
        b'\r' => out.extend_from_slice(b"\\r"),
        b'\t' => out.extend_from_slice(b"\\t"),
        _ => {
            out.extend_from_slice(b"\\u00");
            out.extend(
                [c >> 4, c & 0xf]
                    .iter()
                    .filter_map(|&d| HEX.get(usize::from(d))),
            );
        }
    }
}

/// Quote `s` with minimal escaping.
fn escaped(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for &b in s.as_bytes() {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0..=0x1f => control(b, out),
            _ => out.push(b),
        }
    }
    out.push(b'"');
}

fn push_lossy(bytes: &[u8], out: &mut Vec<u8>) {
    match String::from_utf8_lossy(bytes) {
        Cow::Borrowed(s) => out.extend_from_slice(s.as_bytes()),
        Cow::Owned(s) => out.extend_from_slice(s.as_bytes()),
    }
}

/// Re-emit a source string token (quotes included) with Pretty's escape
/// rules: U+0020..=U+007E literal except `\"` and `\\`, controls as short or
/// lowercase `\u00xx` escapes, everything above U+007E in its source form.
/// Invalid UTF-8 becomes U+FFFD.
fn normalized(raw: &[u8], out: &mut Vec<u8>) {
    let inner = raw.get(1..raw.len().saturating_sub(1)).unwrap_or_default();
    out.push(b'"');
    let mut rest = inner;
    while let Some(at) = rest.iter().position(|&b| b == b'\\') {
        let (lit, esc) = rest.split_at(at);
        push_lossy(lit, out);
        let len = match esc.get(1) {
            Some(b'u') => {
                let cp = esc
                    .get(2..6)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match cp {
                    Some(b'"') => out.extend_from_slice(b"\\\""),
                    Some(b'\\') => out.extend_from_slice(b"\\\\"),
                    Some(c @ 0..=0x1f) => control(c, out),
                    Some(c @ 0x20..=0x7e) => out.push(c),
                    _ => out.extend_from_slice(esc.get(..6).unwrap_or(esc)),
                }
                6
            }
            Some(b'/') => {
                out.push(b'/');
                2
            }
            Some(_) => {
                out.extend_from_slice(esc.get(..2).unwrap_or(esc));
                2
            }
            None => 1,
        };
        rest = esc.get(len..).unwrap_or_default();
    }
    push_lossy(rest, out);
    out.push(b'"');
}

/// Byte range of `part` within `src`, if `part` is a slice of `src`.
fn locate(src: &[u8], part: Option<&[u8]>) -> Option<(usize, usize)> {
    let part = part?;
    let start = (part.as_ptr() as usize).checked_sub(src.as_ptr() as usize)?;
    let end = start.checked_add(part.len())?;
    (end <= src.len()).then_some((start, end))
}

fn ws_prefix(b: &[u8]) -> usize {
    b.iter().take_while(|&&c| is_ws(c)).count()
}

fn ws_suffix(b: &[u8]) -> usize {
    b.iter().rev().take_while(|&&c| is_ws(c)).count()
}

type Loc = Option<(usize, usize)>;

/// Gap bookkeeping for one container with source text `src`. Item `i` is
/// located by `(first, last)`: for arrays the element twice, for objects the
/// key and the value.
struct Gaps<'s, F> {
    src: &'s [u8],
    items: usize,
    loc: F,
    /// Whitespace just inside the brackets of the source.
    lead: &'s [u8],
    trail: &'s [u8],
    /// First copyable separator and colon, used by `InsertedLayout::Compact`
    /// for gaps that cannot be copied.
    sep: Option<&'s [u8]>,
    colon: Option<&'s [u8]>,
}

impl<'s, F> Gaps<'s, F> {
    /// The source gap after the open bracket contains a newline.
    fn multiline(&self) -> bool {
        self.lead.contains(&b'\n')
    }

    /// Whitespace after the last newline of the gap after the open bracket.
    fn child_indent(&self) -> &'s [u8] {
        let from = self
            .lead
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |i| i + 1);
        self.lead.get(from..).unwrap_or_default()
    }
}

impl<'s, F: Fn(usize) -> (Loc, Loc)> Gaps<'s, F> {
    fn new(src: &'s [u8], items: usize, loc: F) -> Self {
        let inner = src.get(1..src.len().saturating_sub(1)).unwrap_or_default();
        let mut g = Self {
            src,
            items,
            loc,
            lead: inner.get(..ws_prefix(inner)).unwrap_or_default(),
            trail: inner
                .get(inner.len().saturating_sub(ws_suffix(inner))..)
                .unwrap_or_default(),
            sep: None,
            colon: None,
        };
        g.sep = (1..items).find_map(|i| g.sep_gap(i));
        g.colon = (0..items).find_map(|i| g.colon_gap(i));
        g
    }

    fn start(&self, i: usize) -> Option<usize> {
        (self.loc)(i).0.map(|l| l.0)
    }

    fn end(&self, i: usize) -> Option<usize> {
        (self.loc)(i).1.map(|l| l.1)
    }

    /// `src[start..end]` if it is whitespace around exactly `punct`.
    fn gap(&self, start: Option<usize>, end: Option<usize>, punct: u8) -> Option<&'s [u8]> {
        let text = self.src.get(start?..end?)?;
        let core = text.get(ws_prefix(text)..text.len() - ws_suffix(text))?;
        (core == [punct]).then_some(text)
    }

    /// The gap between items `i - 1` and `i`, if they are still adjacent.
    fn sep_gap(&self, i: usize) -> Option<&'s [u8]> {
        self.gap(self.end(i.checked_sub(1)?), self.start(i), b',')
    }

    /// The `,` gap in front of item `i` in the source, whatever precedes it
    /// now (so an insertion before an original item keeps that item's gap).
    fn preceding_gap(&self, i: usize) -> Option<&'s [u8]> {
        let start = self.start(i)?;
        let before = self.src.get(..start)?;
        let comma = (before.len() - ws_suffix(before)).checked_sub(1)?;
        if before.get(comma) != Some(&b',') {
            return None;
        }
        let head = before.get(..comma)?;
        self.src.get(head.len() - ws_suffix(head)..start)
    }

    fn colon_gap(&self, i: usize) -> Option<&'s [u8]> {
        let (k, v) = (self.loc)(i);
        self.gap(k.map(|l| l.1), v.map(|l| l.0), b':')
    }

    fn open(&self, out: &mut Vec<u8>) {
        let open = self.src.get(..1).unwrap_or_default();
        if self.items == 0 {
            if self.lead.len() + 2 == self.src.len() {
                out.extend_from_slice(self.src);
            } else {
                out.extend_from_slice(open);
                out.extend_from_slice(
                    self.src
                        .get(self.src.len().saturating_sub(1)..)
                        .unwrap_or_default(),
                );
            }
            return;
        }
        match self.gap(
            Some(0),
            self.start(0),
            open.first().copied().unwrap_or(b'['),
        ) {
            Some(g) => out.extend_from_slice(g),
            None => {
                out.extend_from_slice(open);
                out.extend_from_slice(self.lead);
            }
        }
    }

    fn close(&self, out: &mut Vec<u8>) {
        let Some(last) = self.items.checked_sub(1) else {
            return;
        };
        let close = self
            .src
            .get(self.src.len().saturating_sub(1)..)
            .unwrap_or_default();
        match self.gap(
            self.end(last),
            Some(self.src.len()),
            close.first().copied().unwrap_or(b']'),
        ) {
            Some(g) => out.extend_from_slice(g),
            None => {
                out.extend_from_slice(self.trail);
                out.extend_from_slice(close);
            }
        }
    }
}
