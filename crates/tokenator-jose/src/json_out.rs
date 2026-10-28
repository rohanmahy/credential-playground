//! The JSON writer behind [`JsonStyle`] for generated headers, payloads,
//! and disclosures.
//!
//! This stays separate from tokenator-json's printer: `Spaced` is one line
//! with `", "`/`": "` (Python `json.dumps` defaults), while
//! `InsertedLayout::Canonical` lays out synthesized trees on multiple lines
//! like Pretty, and tokenator-json has no ASCII-only escaping.

use core::fmt::Write as _;

use tokenator_json::{Node, Value};

use crate::issue::JsonStyle;

/// Serializes `node` in `style`. Number lexemes are copied; strings and keys
/// are escaped afresh: `"`, `\`, and control characters always (short forms
/// where JSON has them), and with `ascii_only` everything outside
/// U+0020..=U+007E as lowercase `\uXXXX` (Python's `json.dumps` rules).
pub(crate) fn write(node: &Node<'_>, style: JsonStyle) -> String {
    let mut out = String::new();
    write_node(&mut out, node, style);
    out
}

fn write_node(out: &mut String, node: &Node<'_>, style: JsonStyle) {
    let (comma, colon, ascii_only) = match style {
        JsonStyle::Compact => (",", ":", false),
        JsonStyle::Spaced { ascii_only } => (", ", ": ", ascii_only),
    };
    match node.value() {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(n),
        Value::String(s) => write_str(out, s, ascii_only),
        Value::Array(xs) => {
            out.push('[');
            for (i, x) in xs.iter().enumerate() {
                if i > 0 {
                    out.push_str(comma);
                }
                write_node(out, x, style);
            }
            out.push(']');
        }
        Value::Object(ms) => {
            out.push('{');
            for (i, m) in ms.iter().enumerate() {
                if i > 0 {
                    out.push_str(comma);
                }
                write_str(out, m.key(), ascii_only);
                out.push_str(colon);
                write_node(out, m.value(), style);
            }
            out.push('}');
        }
    }
}

/// Writes `s` as a JSON string.
pub(crate) fn write_str(out: &mut String, s: &str, ascii_only: bool) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if c < ' ' || (ascii_only && c > '~') => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    // Writing to a String cannot fail.
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
