//! Shared helpers for the tokenator-edn integration tests.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use tokenator_cbor::{EncodeMode, Item, Value, decode, encode};
use tokenator_edn::{
    EmbeddedCbor, EncodingIndicators, IndefiniteStringStyle, Path, PathSegment, PrintOptions,
    Rendered, parse, print,
};

/// Parses hex, ignoring whitespace and `_`.
pub fn h(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'_')
        .collect();
    assert!(digits.len().is_multiple_of(2), "odd hex length: {s:?}");
    digits
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

/// Lower-case hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses EDN (panicking with the error) and encodes it in Preserve mode.
pub fn enc(edn: &str) -> Vec<u8> {
    match parse(edn) {
        Ok(item) => encode(&item, EncodeMode::Preserve).unwrap(),
        Err(e) => panic!("parse({edn:?}) failed: {e:?}"),
    }
}

/// Asserts that `edn` encodes to the hex `expected`.
#[track_caller]
pub fn assert_enc(edn: &str, expected: &str) {
    assert_eq!(hex(&enc(edn)), hex(&h(expected)), "EDN: {edn}");
}

/// Prints the decoding of `bytes` with default options.
pub fn diag(bytes: &[u8]) -> String {
    print(&decode(bytes).unwrap(), &PrintOptions::new()).text
}

/// A set of print options that must all round-trip exactly.
pub fn roundtrip_options() -> Vec<(&'static str, PrintOptions<'static>)> {
    vec![
        ("default", PrintOptions::new()),
        ("indented", PrintOptions::indented(2)),
        ("indented4", PrintOptions::indented(4)),
        (
            "always",
            PrintOptions {
                encoding_indicators: EncodingIndicators::Always,
                ..PrintOptions::new()
            },
        ),
        (
            "ascii+streamstrings+literals",
            PrintOptions {
                ascii: true,
                indefinite_strings: IndefiniteStringStyle::Streamstring,
                dt_literals: true,
                ip_literals: true,
                bytes: tokenator_edn::ByteStyle::Base64,
                ..PrintOptions::new()
            },
        ),
    ]
}

/// decode → print → parse → encode(Preserve) == bytes, for every option set.
pub fn rt(bytes: &[u8]) -> Result<(), String> {
    let item = decode(bytes).map_err(|e| format!("decode: {e}"))?;
    for (name, opts) in roundtrip_options() {
        let rendered = print(&item, &opts);
        let back = parse(&rendered.text)
            .map_err(|e| format!("[{name}] reparse of {:?}: {e:?}", rendered.text))?;
        let again = encode(&back, EncodeMode::Preserve).unwrap();
        if again != bytes {
            return Err(format!(
                "[{name}] {} printed as {:?} re-encodes to {}",
                hex(bytes),
                rendered.text,
                hex(&again)
            ));
        }
    }
    Ok(())
}

/// Paths of every definite-length byte string whose content is a complete
/// CBOR sequence of one or more items, including byte strings inside such
/// content (through `Embedded(i)` segments): what a caller would list to
/// show every decodable byte string as `<<…>>`.
pub fn all_bstr_paths(item: &Item) -> Vec<Path> {
    let mut out = Vec::new();
    let mut todo = vec![(Path::root(), item.clone().into_owned())];
    while let Some((base, it)) = todo.pop() {
        for (path, node) in nodes(&it) {
            let Value::Bytes(b) = &node.value else {
                continue;
            };
            if node.width == tokenator_cbor::Width::Indefinite
                || b.is_empty()
                || path
                    .segments()
                    .last()
                    .is_some_and(|s| matches!(s, PathSegment::Chunk(_)))
            {
                continue;
            }
            let Ok(inner) = tokenator_cbor::decode_seq(b) else {
                continue;
            };
            let mut full = base.0.clone();
            full.extend_from_slice(path.segments());
            let full = Path(full);
            if base.depth() + path.depth() + 2 > tokenator_cbor::MAX_DEPTH / 2 {
                continue;
            }
            for (i, inner) in inner.into_iter().enumerate() {
                todo.push((full.child(PathSegment::Embedded(i)), inner.into_owned()));
            }
            out.push(full);
        }
    }
    out.sort();
    out
}

/// Like [`rt`], with every decodable byte string (and tags 24/63) shown as
/// embedded CBOR, compact and indented.
pub fn rt_embedded(bytes: &[u8]) -> Result<(), String> {
    let item = decode(bytes).map_err(|e| format!("decode: {e}"))?;
    let paths = all_bstr_paths(&item);
    for opts in [PrintOptions::new(), PrintOptions::indented(2)] {
        let opts = PrintOptions {
            embedded_cbor: EmbeddedCbor::at(&paths),
            ..opts
        };
        let rendered = print(&item, &opts);
        let back = parse(&rendered.text)
            .map_err(|e| format!("[embedded] reparse of {:?}: {e:?}", rendered.text))?;
        let again = encode(&back, EncodeMode::Preserve).unwrap();
        if again != bytes {
            return Err(format!(
                "[embedded] {} printed as {:?} re-encodes to {}",
                hex(bytes),
                rendered.text,
                hex(&again)
            ));
        }
    }
    Ok(())
}

/// Every (path, item) pair of the item tree in pre-order, as the printer
/// visits it without embedded-CBOR expansion: array elements, map keys
/// then values, tag content, and chunks of indefinite strings (only when
/// the item is an indefinite string with chunks).
pub fn nodes<'i, 'a>(item: &'i Item<'a>) -> Vec<(Path, &'i Item<'a>)> {
    let mut out = Vec::new();
    let mut stack = vec![(Path::root(), item)];
    while let Some((path, it)) = stack.pop() {
        let mut kids: Vec<(Path, &Item)> = Vec::new();
        match &it.value {
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
                for (i, c) in it.chunks.iter().enumerate() {
                    kids.push((path.child(PathSegment::Chunk(i)), c));
                }
            }
        }
        out.push((path, it));
        stack.extend(kids.into_iter().rev());
    }
    out
}

/// Number of `\n` in `text[..offset]`.
pub fn line_of(text: &str, offset: usize) -> usize {
    text.as_bytes()[..offset]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
}

/// Checks a printed `SpanMap` (printed without embedded-CBOR expansion)
/// against the item it came from and, when `bytes` is given, the bytes the
/// item was decoded from:
///
/// - exactly one entry per node, same paths, pre-order;
/// - text ranges are in bounds, on char boundaries, nested in their parent,
///   and in document order;
/// - line ranges match the text ranges;
/// - CBOR spans equal the items' spans (when decoded);
/// - every text range re-parses to exactly the node's bytes (except nodes
///   sharing their parent's range inside one prefixed literal).
pub fn check_span_map(item: &Item, bytes: Option<&[u8]>, r: &Rendered) -> Result<(), String> {
    let expected = nodes(item);
    let got: Vec<_> = r.spans.iter().collect();
    if got.len() != expected.len() {
        return Err(format!(
            "{} span entries for {} nodes",
            got.len(),
            expected.len()
        ));
    }
    let text = &r.text;
    let mut prev_start = 0;
    for ((path, it), (gpath, span)) in expected.iter().zip(got.iter()) {
        if path != *gpath {
            return Err(format!("expected path {path}, got {gpath}"));
        }
        let t = &span.text;
        if t.start > t.end || t.end > text.len() {
            return Err(format!("{path}: text range {t:?} out of bounds"));
        }
        if !text.is_char_boundary(t.start) || !text.is_char_boundary(t.end) {
            return Err(format!("{path}: text range {t:?} not on char boundaries"));
        }
        if t.start < prev_start {
            return Err(format!("{path}: text range {t:?} out of document order"));
        }
        prev_start = t.start;
        if t.is_empty() {
            return Err(format!("{path}: empty text range"));
        }
        let first = line_of(text, t.start);
        let last = line_of(text, t.end - 1);
        if span.lines != (first..last + 1) {
            return Err(format!(
                "{path}: lines {:?}, expected {:?}",
                span.lines,
                first..last + 1
            ));
        }
        // Nodes inside a single prefixed literal (DT'', IP'', unresolved
        // extensions) share the literal's range.
        let mut shared = false;
        if let Some(parent) = parent_of(path) {
            let pspan = r
                .spans
                .get(&parent)
                .ok_or(format!("{path}: no parent entry"))?;
            if t.start < pspan.text.start || t.end > pspan.text.end {
                return Err(format!("{path}: {t:?} not inside parent {:?}", pspan.text));
            }
            shared = pspan.text == *t;
        }
        if r.spans.get(path) != Some(*span) {
            return Err(format!("{path}: get() disagrees with iter()"));
        }
        let decoded = it.span.end > 0;
        match (decoded, span.cbor) {
            (true, Some(s)) if s == it.span => {}
            (false, None) => {}
            (_, other) => {
                return Err(format!(
                    "{path}: cbor span {other:?}, item span {:?}",
                    it.span
                ));
            }
        }
        if shared {
            continue;
        }
        let snippet = &text[t.clone()];
        let reparsed = parse(snippet)
            .map_err(|e| format!("{path}: snippet {snippet:?} does not parse: {e:?}"))?;
        let want = match bytes {
            Some(b) if decoded => b[it.span.start..it.span.end].to_vec(),
            _ => encode(it, EncodeMode::Preserve).unwrap(),
        };
        let got_bytes = encode(&reparsed, EncodeMode::Preserve).unwrap();
        if got_bytes != want {
            return Err(format!(
                "{path}: snippet {snippet:?} encodes to {}, want {}",
                hex(&got_bytes),
                hex(&want)
            ));
        }
    }
    Ok(())
}

/// The parent of a non-root path.
pub fn parent_of(path: &Path) -> Option<Path> {
    let segs = path.segments();
    if segs.is_empty() {
        None
    } else {
        Some(Path(segs[..segs.len() - 1].to_vec()))
    }
}

/// Builds a path from segments.
pub fn p<const N: usize>(segs: [PathSegment; N]) -> Path {
    Path::from(segs)
}

/// Runs `f` on a thread with an 8 MiB stack (for deep nesting).
pub fn deep<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(8 << 20)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

/// Reads a vendored cbor-test-vectors file.
pub fn vector_file(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../testdata/cbor-test-vectors/tests/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}
