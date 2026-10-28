//! Serializer for the three [`PrintStyle`]s.
//!
//! `Original` prints containers that still have source text by copying the
//! source "gaps" (whitespace plus one `[`, `,`, `:`, or `]`) between
//! neighbours that are still adjacent in the source. Nothing else is needed
//! to decide what to copy: a gap is only reused if its text is exactly
//! whitespace around the right punctuation, so the output stays valid even
//! when nodes were moved, removed, or replaced.

use std::fmt::Write as _;

use crate::parse::is_ws;
use crate::{Member, Node, PrintStyle, Value};

pub(crate) fn print(node: &Node<'_>, style: PrintStyle) -> String {
    let mut out = String::with_capacity(node.raw.map_or(64, str::len));
    match style {
        PrintStyle::Original => original(node, &mut out),
        PrintStyle::Compact => compact(node, &mut out),
        PrintStyle::Pretty => pretty(node, 0, &mut out),
    }
    out
}

/// Token text for a scalar: the source text if unedited, else freshly made.
fn scalar(node: &Node<'_>, out: &mut String) {
    if let (false, Some(raw)) = (node.edited, node.raw) {
        out.push_str(raw);
        return;
    }
    match &node.value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(n),
        Value::String(s) => escape(s, out),
        Value::Array(_) | Value::Object(_) => {}
    }
}

fn key(member: &Member<'_>, out: &mut String) {
    match (member.key_edited, member.key_raw) {
        (false, Some(raw)) => out.push_str(raw),
        _ => escape(&member.key, out),
    }
}

/// Quote `s` with minimal escaping.
fn escape(s: &str, out: &mut String) {
    out.push('"');
    let mut run = 0;
    for (i, c) in s.char_indices() {
        let esc = match c {
            '"' => "\\\"",
            '\\' => "\\\\",
            '\u{8}' => "\\b",
            '\u{c}' => "\\f",
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            '\0'..='\u{1f}' => "",
            _ => continue,
        };
        out.push_str(s.get(run..i).unwrap_or_default());
        if esc.is_empty() {
            let _ = write!(out, "\\u{:04x}", u32::from(c));
        } else {
            out.push_str(esc);
        }
        run = i + c.len_utf8();
    }
    out.push_str(s.get(run..).unwrap_or_default());
    out.push('"');
}

fn compact(node: &Node<'_>, out: &mut String) {
    match &node.value {
        Value::Array(xs) => {
            out.push('[');
            for (i, x) in xs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                compact(x, out);
            }
            out.push(']');
        }
        Value::Object(ms) => {
            out.push('{');
            for (i, m) in ms.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                key(m, out);
                out.push(':');
                compact(&m.value, out);
            }
            out.push('}');
        }
        _ => scalar(node, out),
    }
}

fn newline(level: usize, out: &mut String) {
    out.push('\n');
    out.extend(std::iter::repeat_n(' ', 2 * level));
}

fn pretty(node: &Node<'_>, level: usize, out: &mut String) {
    match &node.value {
        Value::Array(xs) if xs.is_empty() => out.push_str("[]"),
        Value::Object(ms) if ms.is_empty() => out.push_str("{}"),
        Value::Array(xs) => {
            out.push('[');
            for (i, x) in xs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(level + 1, out);
                pretty(x, level + 1, out);
            }
            newline(level, out);
            out.push(']');
        }
        Value::Object(ms) => {
            out.push('{');
            for (i, m) in ms.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(level + 1, out);
                key(m, out);
                out.push_str(": ");
                pretty(&m.value, level + 1, out);
            }
            newline(level, out);
            out.push('}');
        }
        _ => scalar(node, out),
    }
}

fn original(node: &Node<'_>, out: &mut String) {
    let (open, items) = match &node.value {
        Value::Array(xs) => (b'[', xs.len()),
        Value::Object(ms) => (b'{', ms.len()),
        _ => return scalar(node, out),
    };
    // The source text is only a usable template if it is the same kind of
    // container (an edit may have turned `0` into `{...}`).
    let src = node.raw.filter(|r| r.as_bytes().first() == Some(&open));
    match (&node.value, src) {
        (Value::Array(xs), Some(src)) => {
            let g = Gaps::new(src, items, |i| {
                let l = locate(src, xs.get(i).and_then(|x| x.raw));
                (l, l)
            });
            g.open(out);
            for (i, x) in xs.iter().enumerate() {
                g.before(i, out);
                original(x, out);
            }
            g.close(out);
        }
        (Value::Object(ms), Some(src)) => {
            let g = Gaps::new(src, items, |i| {
                let m = ms.get(i);
                (
                    locate(src, m.and_then(|m| m.key_raw)),
                    locate(src, m.and_then(|m| m.value.raw)),
                )
            });
            g.open(out);
            for (i, m) in ms.iter().enumerate() {
                g.before(i, out);
                key(m, out);
                g.colon(i, out);
                original(&m.value, out);
            }
            g.close(out);
        }
        // Synthesized (or retyped) container: compact punctuation, but
        // children may still have source text of their own.
        (Value::Array(xs), None) => {
            out.push('[');
            for (i, x) in xs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                original(x, out);
            }
            out.push(']');
        }
        (Value::Object(ms), None) => {
            out.push('{');
            for (i, m) in ms.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                key(m, out);
                out.push(':');
                original(&m.value, out);
            }
            out.push('}');
        }
        _ => {}
    }
}

/// Byte range of `part` within `src`, if `part` is a slice of `src`.
fn locate(src: &str, part: Option<&str>) -> Option<(usize, usize)> {
    let part = part?;
    let start = (part.as_ptr() as usize).checked_sub(src.as_ptr() as usize)?;
    let end = start.checked_add(part.len())?;
    (end <= src.len()).then_some((start, end))
}

type Loc = Option<(usize, usize)>;

/// Gap bookkeeping for one container with source text `src`. Item `i` is
/// located by `(first, last)`: for arrays the element twice, for objects the
/// key and the value.
struct Gaps<'s, F> {
    src: &'s str,
    items: usize,
    loc: F,
    /// Whitespace just inside the brackets of the source.
    lead: &'s str,
    trail: &'s str,
    sep: Option<&'s str>,
    colon: Option<&'s str>,
}

impl<'s, F: Fn(usize) -> (Loc, Loc)> Gaps<'s, F> {
    fn new(src: &'s str, items: usize, loc: F) -> Self {
        let inner = src.get(1..src.len().saturating_sub(1)).unwrap_or_default();
        let lead_len = inner.bytes().take_while(|&b| is_ws(b)).count();
        let trail_len = inner.bytes().rev().take_while(|&b| is_ws(b)).count();
        let mut g = Self {
            src,
            items,
            loc,
            lead: inner.get(..lead_len).unwrap_or_default(),
            trail: inner
                .get(inner.len().saturating_sub(trail_len)..)
                .unwrap_or_default(),
            sep: None,
            colon: None,
        };
        // Templates for gaps that cannot be copied: the first copyable
        // separator and colon in this container.
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
    fn gap(&self, start: Option<usize>, end: Option<usize>, punct: u8) -> Option<&'s str> {
        let text = self.src.get(start?..end?)?;
        let core = text.trim_matches([' ', '\t', '\n', '\r']);
        (core.as_bytes() == [punct]).then_some(text)
    }

    fn sep_gap(&self, i: usize) -> Option<&'s str> {
        self.gap(self.end(i.checked_sub(1)?), self.start(i), b',')
    }

    fn colon_gap(&self, i: usize) -> Option<&'s str> {
        let (k, v) = (self.loc)(i);
        self.gap(k.map(|l| l.1), v.map(|l| l.0), b':')
    }

    fn open(&self, out: &mut String) {
        let close = self.src.get(self.src.len().saturating_sub(1)..);
        if self.items == 0 {
            if self.lead.len() + 2 == self.src.len() {
                out.push_str(self.src);
            } else {
                out.push_str(self.src.get(..1).unwrap_or_default());
                out.push_str(close.unwrap_or_default());
            }
            return;
        }
        let open = self.src.get(..1).unwrap_or_default();
        match self.gap(
            Some(0),
            self.start(0),
            open.as_bytes().first().copied().unwrap_or(b'['),
        ) {
            Some(g) => out.push_str(g),
            None => {
                out.push_str(open);
                out.push_str(self.lead);
            }
        }
    }

    fn before(&self, i: usize, out: &mut String) {
        if i == 0 {
            return;
        }
        match (self.sep_gap(i), self.sep) {
            (Some(g), _) | (None, Some(g)) => out.push_str(g),
            (None, None) => {
                out.push(',');
                out.push_str(self.lead);
            }
        }
    }

    fn colon(&self, i: usize, out: &mut String) {
        out.push_str(self.colon_gap(i).or(self.colon).unwrap_or(":"));
    }

    fn close(&self, out: &mut String) {
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
            close.as_bytes().first().copied().unwrap_or(b']'),
        ) {
            Some(g) => out.push_str(g),
            None => {
                out.push_str(self.trail);
                out.push_str(close);
            }
        }
    }
}
