//! Items to EDN text.

use std::borrow::Cow;
use std::fmt;
use std::fmt::Write as _;
use std::ops::Range;

use tokenator_cbor::{
    EncodeMode, FloatWidth, Item, MAX_DEPTH, Span, Value, Width, decode_seq, encode,
};

use crate::annotate::Annotator;
use crate::datetime::{EpochValue, Instant};
use crate::ext::{Extensions, UNRESOLVED_EXTENSION_TAG, dt, ip, ip_text};
use crate::parse::{CANONICAL_NAN, LineIndex, fits, float_fits, height, push_children};
use crate::path::{Path, PathSegment};
use crate::spans::{NodeSpan, SpanMap};

/// Overall layout of the printed text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Layout {
    /// One line: `[1, {"a": 2}]`, with `, ` and `: ` separators.
    #[default]
    Compact,
    /// Every element of a non-empty array, map, embedded sequence, or
    /// streamstring on its own line, indented by `indent` spaces per level,
    /// closing delimiter on its own line, no trailing commas. A map entry is
    /// `key: value` on one line (a container value opens on that line). A tag
    /// is `N(` directly followed by its content and `)` after the content's
    /// last character. Empty containers stay `[]`, `{}`, `[_ ]`.
    Indented {
        /// Spaces per nesting level.
        indent: usize,
    },
}

/// When to emit encoding indicators (`_i`, `_0`..`_3`, `_`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EncodingIndicators {
    /// Only where the encoding differs from preferred serialization with
    /// definite lengths, so the output re-encodes to the original bytes.
    #[default]
    NonPreferred,
    /// On every item that has an argument width (`[_i 1_i]`, `1.5_1`).
    Always,
    /// Never: the data-model view. Indefinite containers print as definite
    /// and indefinite strings as one string.
    Never,
}

/// Which byte strings to show as embedded CBOR `<<…>>` (issue #15: no
/// guessing). Only definite-length byte strings qualify; chunks of
/// indefinite-length strings never do.
///
/// A qualifying byte string is shown as `<<…>>` only if that re-encodes
/// exactly; otherwise it stays `h'…'` (the printer never fails). An empty
/// byte string always stays `h''`. To decode a byte string the user picked
/// by hand, use [`decode_embedded`](crate::decode_embedded), which reports
/// trailing bytes instead of refusing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EmbeddedCbor<'a> {
    /// Byte strings at these paths, which the caller knows hold CBOR (COSE
    /// protected headers, payloads, SD-CWT disclosures, `kcwt`, …). The
    /// content is shown if it is a complete CBOR sequence of one or more
    /// items; the items get paths ending in
    /// [`PathSegment::Embedded(i)`](crate::PathSegment::Embedded). Paths
    /// below an embedded item go through its `Embedded(i)` segment, so nested
    /// embedded CBOR is listed explicitly too.
    pub paths: &'a [Path],
    /// Also the content of tag 24 ("encoded CBOR data item": shown if it is
    /// exactly one item) and tag 63 ("encoded CBOR sequence": one or more
    /// items). These tags are format knowledge too, so they need no path.
    /// Off by default, like the draft's basic output format (§1.3.3).
    pub tagged: bool,
}

impl<'a> EmbeddedCbor<'a> {
    /// No embedded CBOR: every byte string prints as `h'…'`.
    pub const OFF: EmbeddedCbor<'static> = EmbeddedCbor {
        paths: &[],
        tagged: false,
    };

    /// The byte strings at `paths`, plus tags 24 and 63.
    pub fn at(paths: &'a [Path]) -> EmbeddedCbor<'a> {
        EmbeddedCbor {
            paths,
            tagged: true,
        }
    }

    /// Only the contents of tags 24 and 63.
    pub fn tagged() -> EmbeddedCbor<'static> {
        EmbeddedCbor {
            paths: &[],
            tagged: true,
        }
    }
}

/// How to print byte strings that are not shown as embedded CBOR.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ByteStyle {
    /// `h'0102'` (lowercase hex).
    #[default]
    Hex,
    /// `b64'AQI'` (base64url, no padding).
    Base64,
}

/// How to print indefinite-length strings.
///
/// The default is [`IndefiniteStringStyle::AppExtension`], so that the
/// printer's default output parses without warnings (issue #14).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IndefiniteStringStyle {
    /// `ilts<<"a", "b">>` / `ilbs<<h'01'>>`; no chunks: `ilts<<>>` / `ilbs<<>>`.
    #[default]
    AppExtension,
    /// The deprecated streamstring syntax `(_ "a", "b")`; no chunks: `''_` /
    /// `""_`. Parsing it gives [`WarningKind::Streamstring`](crate::WarningKind::Streamstring).
    Streamstring,
}

/// Options for [`print()`]. [`Default`] is [`PrintOptions::new`].
#[derive(Clone, Copy)]
pub struct PrintOptions<'a> {
    /// Compact or indented.
    pub layout: Layout,
    /// When to emit encoding indicators.
    pub encoding_indicators: EncodingIndicators,
    /// When to render byte strings as `<<…>>`.
    pub embedded_cbor: EmbeddedCbor<'a>,
    /// How to render other byte strings.
    pub bytes: ByteStyle,
    /// How to render indefinite-length strings.
    pub indefinite_strings: IndefiniteStringStyle,
    /// Escape every non-ASCII character in text strings as `\uXXXX`
    /// (surrogate pairs above U+FFFF), lowercase hex.
    pub ascii: bool,
    /// Print tag 1 as `DT'…'` (whole seconds and fractions) where that
    /// re-encodes exactly; otherwise as a plain tag.
    pub dt_literals: bool,
    /// Print tags 52/54 holding an address or `[prefix-length, address]` as
    /// `IP'…'` where that re-encodes exactly.
    pub ip_literals: bool,
    /// Print `999([prefix, [args…]])` as `prefix'…'` / `prefix<<…>>` where
    /// that re-encodes exactly and the prefix is not a built-in extension.
    pub unresolved_as_prefixed: bool,
    /// Adds `/ comment /` in front of nodes.
    pub annotator: Option<&'a dyn Annotator>,
}

impl PrintOptions<'_> {
    /// The defaults: compact, indicators only where needed, `h''`,
    /// `ilbs<<…>>`/`ilts<<…>>` for indefinite strings, UTF-8 text, no `DT''`/`IP''`, opaque extensions
    /// printed as prefixed literals, no annotator.
    pub fn new() -> Self {
        PrintOptions {
            layout: Layout::Compact,
            encoding_indicators: EncodingIndicators::NonPreferred,
            embedded_cbor: EmbeddedCbor::OFF,
            bytes: ByteStyle::Hex,
            indefinite_strings: IndefiniteStringStyle::AppExtension,
            ascii: false,
            dt_literals: false,
            ip_literals: false,
            unresolved_as_prefixed: true,
            annotator: None,
        }
    }

    /// [`PrintOptions::new`] with [`Layout::Indented`].
    pub fn indented(indent: usize) -> Self {
        PrintOptions {
            layout: Layout::Indented { indent },
            ..PrintOptions::new()
        }
    }
}

impl Default for PrintOptions<'_> {
    fn default() -> Self {
        PrintOptions::new()
    }
}

impl fmt::Debug for PrintOptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrintOptions")
            .field("layout", &self.layout)
            .field("encoding_indicators", &self.encoding_indicators)
            .field("embedded_cbor", &self.embedded_cbor)
            .field("bytes", &self.bytes)
            .field("indefinite_strings", &self.indefinite_strings)
            .field("ascii", &self.ascii)
            .field("dt_literals", &self.dt_literals)
            .field("ip_literals", &self.ip_literals)
            .field("unresolved_as_prefixed", &self.unresolved_as_prefixed)
            .field("annotator", &self.annotator.is_some())
            .finish()
    }
}

/// Printed EDN and where each node ended up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    /// The EDN text.
    pub text: String,
    /// One entry per node of the item tree, plus embedded items that are
    /// shown as `<<…>>`, in pre-order. Chunks of an indefinite string get
    /// entries when printed as chunks. Nodes inside an item printed as a
    /// single prefixed literal (`DT'…'`, `IP'…'`, an unresolved extension)
    /// share that literal's text range.
    pub spans: SpanMap,
}

/// Prints `item` as EDN.
///
/// Map entries are printed in arrival order. With
/// [`EncodingIndicators::NonPreferred`] or [`EncodingIndicators::Always`],
/// `encode(&parse(&text)?, Preserve) == encode(item, Preserve)` for every
/// item (widths too narrow for their value count as the preferred width,
/// as in the encoder).
///
/// ```
/// use tokenator_cbor::decode;
/// use tokenator_edn::{print, PrintOptions};
///
/// let item = decode(&[0x82, 0x01, 0x63, b'a', b'b', b'c'])?;
/// assert_eq!(print(&item, &PrintOptions::new()).text, r#"[1, "abc"]"#);
/// # Ok::<(), tokenator_cbor::DecodeError>(())
/// ```
///
/// Indented output with registry-style annotations, embedded CBOR, and the
/// span map that ties each node to its text and bytes:
///
/// ```
/// use tokenator_cbor::{decode, Item};
/// use tokenator_edn::{print, EmbeddedCbor, Path, PathSegment, PrintOptions};
///
/// // {1: -7, 4: <<"kid">>}
/// let bytes = [0xa2, 0x01, 0x26, 0x04, 0x44, 0x63, b'k', b'i', b'd'];
/// let item = decode(&bytes)?;
/// let names = |path: &Path, _: &Item| match path.segments() {
///     [PathSegment::Key(0)] => Some("alg".to_string()),
///     _ => None,
/// };
/// let decoded = [Path::from([PathSegment::Value(1)])];
/// let options = PrintOptions {
///     embedded_cbor: EmbeddedCbor::at(&decoded),
///     annotator: Some(&names),
///     ..PrintOptions::indented(2)
/// };
/// let rendered = print(&item, &options);
/// assert_eq!(rendered.text, "{\n  / alg / 1: -7,\n  4: <<\n    \"kid\"\n  >>\n}");
///
/// let kid = Path::from([PathSegment::Value(1), PathSegment::Embedded(0)]);
/// let span = rendered.spans.get(&kid).unwrap();
/// assert_eq!(&rendered.text[span.text.clone()], "\"kid\"");
/// assert_eq!(span.lines, 3..4);
/// assert_eq!(span.cbor.map(|s| s.start..s.end), Some(5..9));
/// # Ok::<(), tokenator_cbor::DecodeError>(())
/// ```
pub fn print(item: &Item<'_>, options: &PrintOptions<'_>) -> Rendered {
    let mut p = Printer {
        opts: options,
        out: String::new(),
        entries: Vec::new(),
    };
    p.run(item);
    let lines = LineIndex::new(&p.out);
    let mut spans = SpanMap::new();
    for (path, text, cbor) in p.entries {
        spans.push(
            path,
            NodeSpan {
                lines: lines.lines(&text),
                text,
                cbor,
            },
        );
    }
    Rendered { text: p.out, spans }
}

/// A node being printed: borrowed from the caller's tree, or owned (decoded
/// from an embedded byte string) and taken apart as it is printed.
pub(crate) enum Node<'r> {
    Ref(&'r Item<'r>),
    Own(Item<'r>),
}

impl<'r> Node<'r> {
    pub(crate) fn item(&self) -> &Item<'r> {
        match self {
            Node::Ref(i) => i,
            Node::Own(i) => i,
        }
    }

    /// The children in document order: array elements, map keys and values,
    /// tag content, or chunks.
    pub(crate) fn into_children(self) -> Vec<(PathSegment, Node<'r>)> {
        let mut out = Vec::new();
        match self {
            Node::Ref(item) => match &item.value {
                Value::Array(items) => {
                    for (i, c) in items.iter().enumerate() {
                        out.push((PathSegment::Index(i), Node::Ref(c)));
                    }
                }
                Value::Map(entries) => {
                    for (i, (k, v)) in entries.iter().enumerate() {
                        out.push((PathSegment::Key(i), Node::Ref(k)));
                        out.push((PathSegment::Value(i), Node::Ref(v)));
                    }
                }
                Value::Tag(_, inner) => out.push((PathSegment::TagContent, Node::Ref(inner))),
                _ => {
                    for (i, c) in item.chunks.iter().enumerate() {
                        out.push((PathSegment::Chunk(i), Node::Ref(c)));
                    }
                }
            },
            Node::Own(item) => match item.value {
                Value::Array(items) => {
                    for (i, c) in items.into_iter().enumerate() {
                        out.push((PathSegment::Index(i), Node::Own(c)));
                    }
                }
                Value::Map(entries) => {
                    for (i, (k, v)) in entries.into_iter().enumerate() {
                        out.push((PathSegment::Key(i), Node::Own(k)));
                        out.push((PathSegment::Value(i), Node::Own(v)));
                    }
                }
                Value::Tag(_, inner) => out.push((PathSegment::TagContent, Node::Own(*inner))),
                _ => {
                    for (i, c) in item.chunks.into_iter().enumerate() {
                        out.push((PathSegment::Chunk(i), Node::Own(c)));
                    }
                }
            },
        }
        out
    }
}

/// The item embedded in a definite-length byte string, if `mode` shows it
/// as `<<…>>` here. `path` is the byte string's path and `depth` its
/// nesting depth; expansion stops where the text would nest deeper than
/// `MAX_DEPTH`.
pub(crate) fn embedded<'r>(
    node: &Node<'r>,
    path: &Path,
    parent_tag: Option<u64>,
    mode: EmbeddedCbor<'_>,
    depth: usize,
) -> Option<Vec<Item<'r>>> {
    if mode == EmbeddedCbor::OFF || node.item().width == Width::Indefinite {
        return None;
    }
    // Issue #15: only listed paths (a CBOR sequence) and, with `tagged`, the
    // content of tag 24 (exactly one item) or tag 63 (a sequence).
    let listed = mode.paths.contains(path);
    let tagged = mode.tagged && matches!(parent_tag, Some(24 | 63));
    if !listed && !tagged {
        return None;
    }
    let (items, content): (Vec<Item<'r>>, &[u8]) = match node {
        Node::Ref(item) => match &item.value {
            Value::Bytes(b) => (decode_seq(b.as_ref()).ok()?, b),
            _ => return None,
        },
        Node::Own(item) => match &item.value {
            Value::Bytes(Cow::Borrowed(b)) => (decode_seq(b).ok()?, b),
            Value::Bytes(Cow::Owned(b)) => (
                decode_seq(b)
                    .ok()?
                    .into_iter()
                    .map(Item::into_owned)
                    .collect(),
                b,
            ),
            _ => return None,
        },
    };
    if items.is_empty() || (!listed && parent_tag == Some(24) && items.len() != 1) {
        return None;
    }
    let deepest = items.iter().map(height).max().unwrap_or(0);
    if depth + 1 + deepest > MAX_DEPTH {
        return None;
    }
    // Shown only where the text re-encodes to exactly these bytes.
    let mut again = Vec::with_capacity(content.len());
    for item in &items {
        again.extend(encode(item, EncodeMode::Preserve).ok()?);
    }
    (again == content).then_some(items)
}

/// The CBOR span of `item` in the outermost bytes, given the offset its
/// spans are relative to.
pub(crate) fn abs_span(item: &Item<'_>, base: Option<usize>) -> Option<Span> {
    let b = base?;
    (item.span.end > 0).then_some(Span {
        start: item.span.start + b,
        end: item.span.end + b,
        head_len: item.span.head_len,
    })
}

/// The base offset for the items embedded in byte string `item`.
pub(crate) fn embedded_base(item: &Item<'_>, base: Option<usize>) -> Option<usize> {
    abs_span(item, base).map(|s| s.start + s.head_len)
}

/// What comes before a child.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Prefix {
    /// An element: separator and, in block layout, a new line.
    Element,
    /// A map value: `: `.
    Value,
    /// Tag content: nothing.
    Bare,
}

struct Child<'r> {
    node: Node<'r>,
    path: Path,
    /// Offset that the node's spans are relative to (`None`: no CBOR spans).
    base: Option<usize>,
    prefix: Prefix,
    /// Indentation level of the line the node starts on.
    level: usize,
    /// The number of the tag this node is the content of.
    parent_tag: Option<u64>,
    /// Whether the node is a chunk of an indefinite-length string.
    chunk: bool,
}

/// An open container.
struct Frame<'r> {
    children: std::vec::IntoIter<Child<'r>>,
    /// Elements on their own lines.
    block: bool,
    level: usize,
    elements: usize,
    closer: String,
    /// Span entries that end with the closer.
    entries: Vec<usize>,
}

struct Printer<'o> {
    opts: &'o PrintOptions<'o>,
    out: String,
    entries: Vec<(Path, Range<usize>, Option<Span>)>,
}

/// Indicator text for a width.
fn width_ind(w: Width) -> &'static str {
    match w {
        Width::Immediate => "_i",
        Width::U8 => "_0",
        Width::U16 => "_1",
        Width::U32 => "_2",
        Width::U64 => "_3",
        Width::Indefinite => "_",
    }
}

/// The width the encoder uses for `arg`.
pub(crate) fn effective(width: Width, arg: u64) -> Width {
    if fits(width, arg) {
        width
    } else {
        Width::preferred_for(arg)
    }
}

/// The width the encoder uses for `f`, and the shortest exact one.
fn float_widths(f: f64, width: FloatWidth) -> (FloatWidth, FloatWidth) {
    let shortest = match Item::float(f).value {
        Value::Float(_, w) => w,
        _ => FloatWidth::F64,
    };
    let eff = if float_fits(f, width) {
        width
    } else {
        shortest
    };
    (eff, shortest)
}

fn float_ind(w: FloatWidth) -> &'static str {
    match w {
        FloatWidth::F16 => "_1",
        FloatWidth::F32 => "_2",
        FloatWidth::F64 => "_3",
    }
}

fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Whether all chunks have the string's type and add up to its value (the
/// encoder's condition for using them).
fn chunks_match(item: &Item<'_>) -> bool {
    let (content, text): (&[u8], bool) = match &item.value {
        Value::Bytes(b) => (b, false),
        Value::Text(t) => (t.as_bytes(), true),
        _ => return false,
    };
    let mut rest = content;
    for chunk in &item.chunks {
        let bytes: &[u8] = match (&chunk.value, text) {
            (Value::Bytes(b), false) => b,
            (Value::Text(t), true) => t.as_bytes(),
            _ => return false,
        };
        match rest.strip_prefix(bytes) {
            Some(r) => rest = r,
            None => return false,
        }
    }
    rest.is_empty()
}

/// Lowercase hex.
pub(crate) fn hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | u32::from(b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            let idx = (n >> (18 - 6 * i)) & 0x3f;
            s.push(char::from(
                ALPHABET.get(idx as usize).copied().unwrap_or(b'A'),
            ));
        }
    }
    s
}

/// Float text: shortest round-trip digits, always with `.` or `e`.
pub(crate) fn float_text(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f < 0.0 { "-Infinity" } else { "Infinity" }.into();
    }
    let sign = if f.is_sign_negative() { "-" } else { "" };
    if f == 0.0 {
        return format!("{sign}0.0");
    }
    let abs = f.abs();
    let sci = format!("{abs:e}");
    let (mant, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i64 = exp.parse().unwrap_or(0);
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    if (1e-5..1e16).contains(&abs) {
        let point = exp + 1;
        let n = digits.len() as i64;
        if point <= 0 {
            format!("{sign}0.{}{digits}", "0".repeat((-point) as usize))
        } else if point >= n {
            format!("{sign}{digits}{}.0", "0".repeat((point - n) as usize))
        } else {
            let (a, b) = digits.split_at(point as usize);
            format!("{sign}{a}.{b}")
        }
    } else {
        let (first, rest) = digits.split_at(1);
        let rest = if rest.is_empty() { "0" } else { rest };
        let esign = if exp < 0 { '-' } else { '+' };
        format!("{sign}{first}.{rest}e{esign}{}", exp.abs())
    }
}

/// Appends `c` as `\uXXXX` (a surrogate pair above U+FFFF).
fn push_u_escape(out: &mut String, c: char) {
    let mut buf = [0u16; 2];
    for unit in c.encode_utf16(&mut buf) {
        let _ = write!(out, "\\u{unit:04x}");
    }
}

/// Appends string content with the escapes valid in both `"…"` and `'…'`,
/// escaping `quote`.
fn push_escaped(out: &mut String, s: &str, quote: char, ascii: bool) {
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if c < ' ' => push_u_escape(out, c),
            c if ascii && !c.is_ascii() => push_u_escape(out, c),
            c => out.push(c),
        }
    }
}

/// Whether `prefix` can be written as an app-extension prefix that the
/// built-in extensions leave unresolved.
fn opaque_prefix(prefix: &str) -> bool {
    let mut bytes = prefix.bytes();
    let first_ok = bytes.next().is_some_and(|c| c.is_ascii_alphabetic());
    let lower = prefix
        .bytes()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
    let upper = prefix
        .bytes()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'-');
    first_ok
        && (lower || upper)
        && !matches!(prefix, "true" | "false" | "null" | "undefined")
        && !Extensions::is_builtin_name(&prefix.to_ascii_lowercase())
}

/// Whether an item's head is in preferred, definite form.
fn preferred_head(item: &Item<'_>, arg: u64) -> bool {
    item.width != Width::Indefinite && effective(item.width, arg) == Width::preferred_for(arg)
}

/// `999([prefix, [args…]])` that can print as a prefixed literal: the
/// prefix, and the single text argument if the string form applies.
fn unresolved<'i>(item: &'i Item<'_>) -> Option<(&'i str, Option<&'i str>)> {
    let Value::Tag(UNRESOLVED_EXTENSION_TAG, content) = &item.value else {
        return None;
    };
    let Value::Array(parts) = &content.value else {
        return None;
    };
    let [prefix_item, args_item] = parts.as_slice() else {
        return None;
    };
    let (Value::Text(prefix), Value::Array(args)) = (&prefix_item.value, &args_item.value) else {
        return None;
    };
    let ok = preferred_head(item, UNRESOLVED_EXTENSION_TAG)
        && preferred_head(content, 2)
        && preferred_head(prefix_item, len_u64(prefix.len()))
        && preferred_head(args_item, len_u64(args.len()))
        && opaque_prefix(prefix);
    if !ok {
        return None;
    }
    let single = match args.as_slice() {
        [
            arg @ Item {
                value: Value::Text(t),
                ..
            },
        ] if preferred_head(arg, len_u64(t.len())) => Some(t.as_ref()),
        _ => None,
    };
    Some((prefix, single))
}

/// `DT'…'` text for a tag-1 item, if it re-encodes exactly.
fn dt_literal(item: &Item<'_>) -> Option<String> {
    let Value::Tag(1, inner) = &item.value else {
        return None;
    };
    let (epoch, float) = match inner.value {
        Value::Uint(n) => (EpochValue::Int(i64::try_from(n).ok()?), false),
        Value::Nint(n) => (EpochValue::Int(-1 - i64::try_from(n).ok()?), false),
        Value::Float(f, _) => (EpochValue::Float(f), true),
        _ => return None,
    };
    let mut text = Instant::from_epoch(epoch).ok()?.to_rfc3339().ok()?;
    if float && !text.contains('.') {
        text.insert_str(text.len() - 1, ".0");
    }
    let candidate = Item::tag(1, dt(&text).ok()?);
    let same = encode(&candidate, EncodeMode::Preserve).ok()?
        == encode(item, EncodeMode::Preserve).ok()?;
    same.then(|| format!("DT'{text}'"))
}

/// `IP'…'` text for a tag-52/54 item, if it re-encodes exactly.
fn ip_literal(item: &Item<'_>) -> Option<String> {
    let Value::Tag(tag @ (52 | 54), inner) = &item.value else {
        return None;
    };
    let full = if *tag == 52 { 4 } else { 16 };
    let text = match &inner.value {
        Value::Bytes(b) if b.len() == full => ip_text(b)?,
        Value::Array(parts) => match parts.as_slice() {
            [
                Item {
                    value: Value::Uint(len),
                    ..
                },
                Item {
                    value: Value::Bytes(b),
                    ..
                },
            ] if b.len() <= full => {
                let mut addr = b.to_vec();
                addr.resize(full, 0);
                format!("{}/{len}", ip_text(&addr)?)
            }
            _ => return None,
        },
        _ => return None,
    };
    let candidate = ip(&text, true).ok()?;
    let same = encode(&candidate, EncodeMode::Preserve).ok()?
        == encode(item, EncodeMode::Preserve).ok()?;
    same.then(|| format!("IP'{text}'"))
}

impl<'o> Printer<'o> {
    fn block(&self) -> bool {
        matches!(self.opts.layout, Layout::Indented { .. })
    }

    fn newline(&mut self, level: usize) {
        self.out.push('\n');
        if let Layout::Indented { indent } = self.opts.layout {
            self.out
                .extend(std::iter::repeat_n(' ', indent.saturating_mul(level)));
        }
    }

    fn int_ind(&self, width: Width, arg: u64) -> &'static str {
        let eff = effective(width, arg);
        match self.opts.encoding_indicators {
            EncodingIndicators::Never => "",
            EncodingIndicators::Always => width_ind(eff),
            EncodingIndicators::NonPreferred if eff != Width::preferred_for(arg) => width_ind(eff),
            EncodingIndicators::NonPreferred => "",
        }
    }

    /// The indicator after `[` or `{`, or of a string head.
    fn head_ind(&self, item: &Item<'_>, arg: u64) -> &'static str {
        if item.width == Width::Indefinite {
            if self.opts.encoding_indicators == EncodingIndicators::Never {
                ""
            } else {
                "_"
            }
        } else {
            self.int_ind(item.width, arg)
        }
    }

    fn float_ind(&self, eff: FloatWidth, shortest: FloatWidth) -> &'static str {
        match self.opts.encoding_indicators {
            EncodingIndicators::Never => "",
            EncodingIndicators::Always => float_ind(eff),
            EncodingIndicators::NonPreferred if eff != shortest => float_ind(eff),
            EncodingIndicators::NonPreferred => "",
        }
    }

    fn comment(&mut self, text: &str) {
        let clean: String = text
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        if clean.contains('/') {
            self.out.push_str("/* ");
            self.out.push_str(&clean.replace("*/", "* /"));
            self.out.push_str(" */ ");
        } else {
            self.out.push_str("/ ");
            self.out.push_str(&clean);
            self.out.push_str(" / ");
        }
    }

    fn entry(&mut self, path: Path, start: usize, cbor: Option<Span>) -> usize {
        self.entries.push((path, start..start, cbor));
        self.entries.len() - 1
    }

    fn end(&mut self, entry: usize) {
        let end = self.out.len();
        if let Some((_, r, _)) = self.entries.get_mut(entry) {
            r.end = end;
        }
    }

    /// Entries for the descendants of a node printed as one literal.
    fn shared_subtree(
        &mut self,
        path: &Path,
        item: &Item<'_>,
        base: Option<usize>,
        range: &Range<usize>,
    ) {
        let mut stack: Vec<(Path, &Item<'_>)> = Vec::new();
        push_children(&mut stack, path, item);
        while let Some((p, it)) = stack.pop() {
            push_children(&mut stack, &p, it);
            self.entries.push((p, range.clone(), abs_span(it, base)));
        }
    }

    fn run(&mut self, root: &Item<'_>) {
        let root = Child {
            node: Node::Ref(root),
            path: Path::root(),
            base: Some(0),
            prefix: Prefix::Bare,
            level: 0,
            parent_tag: None,
            chunk: false,
        };
        let mut stack: Vec<Frame<'_>> = Vec::new();
        if let Some(frame) = self.node(root) {
            stack.push(frame);
        }
        while let Some(top) = stack.last_mut() {
            match top.children.next() {
                Some(child) => {
                    match child.prefix {
                        Prefix::Element => {
                            let (block, level) = (top.block, top.level);
                            if top.elements > 0 {
                                self.out.push(',');
                                if !block {
                                    self.out.push(' ');
                                }
                            }
                            top.elements += 1;
                            if block {
                                self.newline(level + 1);
                            }
                        }
                        Prefix::Value => self.out.push_str(": "),
                        Prefix::Bare => {}
                    }
                    if let Some(frame) = self.node(child) {
                        stack.push(frame);
                    }
                }
                None => {
                    let Some(frame) = stack.pop() else { break };
                    if frame.block && frame.elements > 0 {
                        self.newline(frame.level);
                    }
                    self.out.push_str(&frame.closer);
                    for e in frame.entries {
                        self.end(e);
                    }
                }
            }
        }
    }

    /// Opens a frame for the children of `node`, which sits at `path` on a
    /// line of indentation `level`.
    #[allow(clippy::too_many_arguments)]
    fn frame<'r>(
        &mut self,
        node: Node<'r>,
        path: &Path,
        base: Option<usize>,
        level: usize,
        opener: &str,
        ind: &str,
        closer: &str,
        entry: usize,
    ) -> Option<Frame<'r>> {
        let tag = match &node.item().value {
            Value::Tag(n, _) => Some(*n),
            _ => None,
        };
        let is_string = matches!(node.item().value, Value::Bytes(_) | Value::Text(_));
        let kids: Vec<Child<'r>> = node
            .into_children()
            .into_iter()
            .map(|(seg, n)| Child {
                node: n,
                path: path.child(seg),
                base,
                prefix: match seg {
                    PathSegment::Value(_) => Prefix::Value,
                    PathSegment::TagContent => Prefix::Bare,
                    _ => Prefix::Element,
                },
                level: if tag.is_some() { level } else { level + 1 },
                parent_tag: tag,
                chunk: is_string,
            })
            .collect();
        let empty = if ind.is_empty() || closer == ">>" {
            closer.to_owned()
        } else {
            format!(" {closer}")
        };
        self.open(
            kids,
            opener,
            ind,
            closer.into(),
            &empty,
            vec![entry],
            level,
            tag.is_none(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn open<'r>(
        &mut self,
        kids: Vec<Child<'r>>,
        opener: &str,
        ind: &str,
        closer: String,
        empty: &str,
        entries: Vec<usize>,
        level: usize,
        may_block: bool,
    ) -> Option<Frame<'r>> {
        self.out.push_str(opener);
        self.out.push_str(ind);
        if kids.is_empty() {
            self.out.push_str(empty);
            for e in entries {
                self.end(e);
            }
            return None;
        }
        let block = may_block && self.block();
        if !block && !ind.is_empty() {
            self.out.push(' ');
        }
        Some(Frame {
            children: kids.into_iter(),
            block,
            level,
            elements: 0,
            closer,
            entries,
        })
    }

    /// Prints a node; returns a frame if it has children still to print.
    fn node<'r>(&mut self, child: Child<'r>) -> Option<Frame<'r>> {
        let opts = self.opts;
        if let Some(ann) = opts.annotator
            && let Some(text) = ann.comment(&child.path, child.node.item())
        {
            self.comment(&text);
        }
        let start = self.out.len();
        let item = child.node.item();
        let entry = self.entry(child.path.clone(), start, abs_span(item, child.base));
        match &item.value {
            Value::Tag(n, _) => {
                let n = *n;
                let literal = match n {
                    1 if opts.dt_literals => dt_literal(item),
                    52 | 54 if opts.ip_literals => ip_literal(item),
                    _ => None,
                };
                if let Some(text) = literal {
                    self.out.push_str(&text);
                    self.end(entry);
                    let range = start..self.out.len();
                    self.shared_subtree(&child.path, item, child.base, &range);
                    return None;
                }
                let opaque = if opts.unresolved_as_prefixed {
                    unresolved(item).map(|(p, single)| (p.to_owned(), single.map(str::to_owned)))
                } else {
                    None
                };
                if let Some((prefix, single)) = opaque {
                    return self.unresolved(child, entry, prefix, single);
                }
                let opener = format!("{n}{}(", self.int_ind(item.width, n));
                self.frame(
                    child.node,
                    &child.path,
                    child.base,
                    child.level,
                    &opener,
                    "",
                    ")",
                    entry,
                )
            }
            Value::Array(items) => {
                let ind = self.head_ind(item, len_u64(items.len()));
                self.frame(
                    child.node,
                    &child.path,
                    child.base,
                    child.level,
                    "[",
                    ind,
                    "]",
                    entry,
                )
            }
            Value::Map(entries) => {
                let ind = self.head_ind(item, len_u64(entries.len()));
                self.frame(
                    child.node,
                    &child.path,
                    child.base,
                    child.level,
                    "{",
                    ind,
                    "}",
                    entry,
                )
            }
            Value::Bytes(_) | Value::Text(_)
                if item.width == Width::Indefinite
                    && opts.encoding_indicators != EncodingIndicators::Never =>
            {
                self.indefinite_string(child, entry)
            }
            Value::Bytes(b) => {
                if !child.chunk
                    && let Some(inner) = embedded(
                        &child.node,
                        &child.path,
                        child.parent_tag,
                        opts.embedded_cbor,
                        child.path.depth(),
                    )
                {
                    let ind = self.int_ind(item.width, len_u64(b.len()));
                    let base = embedded_base(item, child.base);
                    let kids = inner
                        .into_iter()
                        .enumerate()
                        .map(|(i, it)| Child {
                            node: Node::Own(it),
                            path: child.path.child(PathSegment::Embedded(i)),
                            base,
                            prefix: Prefix::Element,
                            level: child.level + 1,
                            parent_tag: None,
                            chunk: false,
                        })
                        .collect();
                    return self.open(
                        kids,
                        "<<",
                        "",
                        format!(">>{ind}"),
                        ">>",
                        vec![entry],
                        child.level,
                        true,
                    );
                }
                let ind = if item.width == Width::Indefinite {
                    ""
                } else {
                    self.int_ind(item.width, len_u64(b.len()))
                };
                self.bytes(b);
                self.out.push_str(ind);
                self.end(entry);
                None
            }
            Value::Text(t) => {
                let ind = if item.width == Width::Indefinite {
                    ""
                } else {
                    self.int_ind(item.width, len_u64(t.len()))
                };
                self.text(t);
                self.out.push_str(ind);
                self.end(entry);
                None
            }
            Value::Uint(n) => {
                let ind = self.int_ind(item.width, *n);
                let _ = write!(self.out, "{n}{ind}");
                self.end(entry);
                None
            }
            Value::Nint(n) => {
                let ind = self.int_ind(item.width, *n);
                let _ = write!(self.out, "-{}{ind}", u128::from(*n) + 1);
                self.end(entry);
                None
            }
            Value::Float(f, w) => {
                self.float(*f, *w);
                self.end(entry);
                None
            }
            Value::Bool(b) => {
                self.out.push_str(if *b { "true" } else { "false" });
                self.end(entry);
                None
            }
            Value::Null => {
                self.out.push_str("null");
                self.end(entry);
                None
            }
            Value::Undefined => {
                self.out.push_str("undefined");
                self.end(entry);
                None
            }
            Value::Simple(n) => {
                let _ = write!(self.out, "simple({n})");
                self.end(entry);
                None
            }
        }
    }

    fn bytes(&mut self, b: &[u8]) {
        match self.opts.bytes {
            ByteStyle::Hex => {
                self.out.push_str("h'");
                self.out.push_str(&hex_string(b));
            }
            ByteStyle::Base64 => {
                self.out.push_str("b64'");
                self.out.push_str(&base64url(b));
            }
        }
        self.out.push('\'');
    }

    fn text(&mut self, t: &str) {
        self.out.push('"');
        push_escaped(&mut self.out, t, '"', self.opts.ascii);
        self.out.push('"');
    }

    fn float(&mut self, f: f64, width: FloatWidth) {
        let (eff, shortest) = float_widths(f, width);
        let ind = self.float_ind(eff, shortest);
        if f.is_nan() && f.to_bits() != CANONICAL_NAN {
            // A float always encodes.
            let bytes = encode(&Item::float(f), EncodeMode::Preserve).unwrap_or_default();
            self.out.push_str("float'");
            self.out
                .push_str(&hex_string(bytes.get(1..).unwrap_or_default()));
            self.out.push('\'');
        } else {
            self.out.push_str(&float_text(f));
        }
        self.out.push_str(ind);
    }

    /// An indefinite-length string as a streamstring or `ilbs`/`ilts`.
    fn indefinite_string<'r>(&mut self, child: Child<'r>, entry: usize) -> Option<Frame<'r>> {
        let item = child.node.item();
        let is_text = matches!(item.value, Value::Text(_));
        let app = self.opts.indefinite_strings == IndefiniteStringStyle::AppExtension;
        let (opener, closer) = match (app, is_text) {
            (true, true) => ("ilts<<", ">>"),
            (true, false) => ("ilbs<<", ">>"),
            (false, _) => ("(_", ")"),
        };
        if !chunks_match(item) {
            // The encoder writes the value as one chunk (none if empty).
            let value = item.value.clone();
            let chunks = match &value {
                Value::Bytes(b) if !b.is_empty() => vec![value.clone()],
                Value::Text(t) if !t.is_empty() => vec![value.clone()],
                _ => Vec::new(),
            };
            if chunks.is_empty() {
                self.empty_indefinite(app, is_text);
            } else {
                self.out.push_str(opener);
                if !app {
                    self.out.push(' ');
                }
                for v in &chunks {
                    match v {
                        Value::Bytes(b) => self.bytes(b),
                        Value::Text(t) => self.text(t),
                        _ => {}
                    }
                }
                self.out.push_str(closer);
            }
            self.end(entry);
            return None;
        }
        if item.chunks.is_empty() {
            self.empty_indefinite(app, is_text);
            self.end(entry);
            return None;
        }
        let ind = if app { "" } else { "_" };
        let opener = opener.trim_end_matches('_');
        self.frame(
            child.node,
            &child.path,
            child.base,
            child.level,
            opener,
            ind,
            closer,
            entry,
        )
    }

    fn empty_indefinite(&mut self, app: bool, is_text: bool) {
        self.out.push_str(match (app, is_text) {
            (true, true) => "ilts<<>>",
            (true, false) => "ilbs<<>>",
            (false, true) => "\"\"_",
            (false, false) => "''_",
        });
    }

    /// `999([prefix, [args…]])` as `prefix'…'` or `prefix<<…>>`.
    fn unresolved<'r>(
        &mut self,
        child: Child<'r>,
        entry: usize,
        prefix: String,
        single: Option<String>,
    ) -> Option<Frame<'r>> {
        let start = self.out.len();
        let item = child.node.item();
        let content_path = child.path.child(PathSegment::TagContent);
        let args_path = content_path.child(PathSegment::Index(1));
        if let Some(text) = single {
            self.out.push_str(&prefix);
            self.out.push('\'');
            push_escaped(&mut self.out, &text, '\'', self.opts.ascii);
            self.out.push('\'');
            self.end(entry);
            let range = start..self.out.len();
            self.shared_subtree(&child.path, item, child.base, &range);
            return None;
        }
        // Entries for the tag content, the prefix, and the argument array.
        let mut entries = vec![entry];
        if let Value::Tag(_, content) = &item.value {
            let parts: Vec<&Item<'_>> = match &content.value {
                Value::Array(parts) => parts.iter().collect(),
                _ => Vec::new(),
            };
            entries.push(self.entry(content_path.clone(), start, abs_span(content, child.base)));
            for (i, part) in parts.iter().enumerate() {
                let e = self.entry(
                    content_path.child(PathSegment::Index(i)),
                    start,
                    abs_span(part, child.base),
                );
                entries.push(e);
            }
        }
        // All four share the literal's range and end with the closer.
        self.out.push_str(&prefix);
        self.out.push_str("<<");
        let args = take_unresolved_args(child.node);
        let kids: Vec<Child<'r>> = args
            .into_iter()
            .enumerate()
            .map(|(i, n)| Child {
                node: n,
                path: args_path.child(PathSegment::Index(i)),
                base: child.base,
                prefix: Prefix::Element,
                level: child.level + 1,
                parent_tag: None,
                chunk: false,
            })
            .collect();
        self.open(kids, "", "", ">>".into(), ">>", entries, child.level, true)
    }
}

/// The argument nodes of an unresolved-extension tag.
fn take_unresolved_args(node: Node<'_>) -> Vec<Node<'_>> {
    let Some((_, content)) = node.into_children().into_iter().next() else {
        return Vec::new();
    };
    let Some((_, args)) = content.into_children().into_iter().nth(1) else {
        return Vec::new();
    };
    args.into_children().into_iter().map(|(_, n)| n).collect()
}
