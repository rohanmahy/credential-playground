//! Annotated hex rows (like cbor.me's right pane).

use std::fmt;
use std::ops::Range;

use tokenator_cbor::{Item, Value, Width};

use crate::annotate::Annotator;
use crate::path::{Path, PathSegment};
use crate::print::{EmbeddedCbor, Node, abs_span, embedded, embedded_base};

/// What a [`HexRow`] stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HexRowKind {
    /// A data item (or a chunk of an indefinite-length string).
    Item,
    /// The `0xff` break that ends an indefinite-length item. Its path is the
    /// path of that item.
    Break,
}

/// One row of the annotated hex view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HexRow {
    /// Item or break.
    pub kind: HexRowKind,
    /// The node this row belongs to.
    pub path: Path,
    /// Nesting depth for indentation: the number of segments in `path`. A
    /// break row has the depth of the item it closes.
    pub depth: usize,
    /// Byte range of the head (initial byte and argument bytes; the whole
    /// item for ints, floats, and simple values; the `0xff` for a break).
    pub head: Range<usize>,
    /// Byte range of a definite string's content (empty range at
    /// `head.end` for everything else, and for a byte string whose content
    /// follows as rows of embedded items).
    pub payload: Range<usize>,
    /// What the head says: `unsigned(1)`, `negative(0)`, `bytes(4)`,
    /// `text(5)`, `array(3)`, `map(2)`, `tag(1)`, `simple(16)`, `false`,
    /// `true`, `null`, `undefined`, `float16`, `float32`, `float64`; `(*)`
    /// instead of the count for indefinite length (`array(*)`); `break`.
    pub description: String,
    /// The annotator's comment for this node (item rows only).
    pub comment: Option<String>,
}

/// The rows for one encoded item, in byte order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HexRows {
    /// All rows.
    pub rows: Vec<HexRow>,
}

/// Options for [`annotated_hex`].
#[derive(Clone, Copy, Default)]
pub struct HexOptions<'a> {
    /// Which byte strings get rows for their embedded items (same rule as
    /// the printer's option, so rows line up with the EDN pane).
    pub embedded_cbor: EmbeddedCbor<'a>,
    /// Fills [`HexRow::comment`].
    pub annotator: Option<&'a dyn Annotator>,
}

impl fmt::Debug for HexOptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HexOptions")
            .field("embedded_cbor", &self.embedded_cbor)
            .field("annotator", &self.annotator.is_some())
            .finish()
    }
}

/// One row per data item of `item`, which must have been decoded from
/// `bytes` (its spans index into `bytes`). Rows for embedded items carry
/// absolute offsets into `bytes`.
///
/// Items without spans (built, not decoded) or spans outside `bytes`
/// produce no rows for those items; this never panics.
///
/// ```
/// use tokenator_cbor::decode;
/// use tokenator_edn::{annotated_hex, HexOptions};
///
/// let bytes = [0x82, 0x01, 0x61, b'a']; // [1, "a"]
/// let rows = annotated_hex(&decode(&bytes)?, &bytes, &HexOptions::default()).rows;
/// let described: Vec<_> = rows.iter().map(|r| r.description.as_str()).collect();
/// assert_eq!(described, ["array(2)", "unsigned(1)", "text(1)"]);
/// assert_eq!(rows[2].payload, 3..4);
/// # Ok::<(), tokenator_cbor::DecodeError>(())
/// ```
///
/// Embedded CBOR gets rows of its own, with absolute offsets and paths that
/// match the printer's [`SpanMap`](crate::SpanMap):
///
/// ```
/// use tokenator_cbor::decode;
/// use tokenator_edn::{annotated_hex, EmbeddedCbor, HexOptions, HexRowKind, Path, PathSegment};
///
/// let bytes = [0xd8, 0x18, 0x42, 0x81, 0x07]; // 24(<<[7]>>)
/// let options = HexOptions { embedded_cbor: EmbeddedCbor::tagged(), ..HexOptions::default() };
/// let rows = annotated_hex(&decode(&bytes)?, &bytes, &options).rows;
/// let seven = rows.last().unwrap();
/// assert_eq!(seven.description, "unsigned(7)");
/// assert_eq!(seven.head, 4..5);
/// assert_eq!(
///     seven.path,
///     Path::from([PathSegment::TagContent, PathSegment::Embedded(0), PathSegment::Index(0)])
/// );
/// assert!(rows.iter().all(|r| r.kind == HexRowKind::Item));
/// # Ok::<(), tokenator_cbor::DecodeError>(())
/// ```
pub fn annotated_hex(item: &Item<'_>, bytes: &[u8], options: &HexOptions<'_>) -> HexRows {
    let mut rows = Vec::new();
    let mut stack = vec![Task::Node {
        node: Node::Ref(item),
        path: Path::root(),
        base: Some(0),
        parent_tag: None,
        chunk: false,
    }];
    while let Some(task) = stack.pop() {
        let (node, path, base, parent_tag, chunk) = match task {
            Task::Break { path, end } => {
                if (1..=bytes.len()).contains(&end) {
                    rows.push(HexRow {
                        kind: HexRowKind::Break,
                        depth: path.depth(),
                        path,
                        head: end - 1..end,
                        payload: end..end,
                        description: "break".into(),
                        comment: None,
                    });
                }
                continue;
            }
            Task::Node {
                node,
                path,
                base,
                parent_tag,
                chunk,
            } => (node, path, base, parent_tag, chunk),
        };
        let it = node.item();
        let Some(span) = abs_span(it, base).filter(|s| s.end <= bytes.len()) else {
            continue;
        };
        let head = span.start..span.start + span.head_len;
        let indefinite = it.width == Width::Indefinite
            && matches!(
                it.value,
                Value::Bytes(_) | Value::Text(_) | Value::Array(_) | Value::Map(_)
            );
        let inner = if chunk || indefinite {
            None
        } else {
            embedded(
                &node,
                &path,
                parent_tag,
                options.embedded_cbor,
                path.depth(),
            )
        };
        let payload = match it.value {
            Value::Bytes(_) | Value::Text(_) if !indefinite && inner.is_none() => {
                head.end..span.end
            }
            _ => head.end..head.end,
        };
        let comment = options
            .annotator
            .and_then(|a| a.comment(&path, it))
            .map(|c| c.into_owned());
        rows.push(HexRow {
            kind: HexRowKind::Item,
            path: path.clone(),
            depth: path.depth(),
            head,
            payload,
            description: describe(it, span.head_len),
            comment,
        });
        if indefinite {
            stack.push(Task::Break {
                path: path.clone(),
                end: span.end,
            });
        }
        if let Some(inner) = inner {
            let inner_base = embedded_base(it, base);
            for (i, item) in inner.into_iter().enumerate().rev() {
                stack.push(Task::Node {
                    node: Node::Own(item),
                    path: path.child(PathSegment::Embedded(i)),
                    base: inner_base,
                    parent_tag: None,
                    chunk: false,
                });
            }
            continue;
        }
        let tag = match it.value {
            Value::Tag(n, _) => Some(n),
            _ => None,
        };
        let is_string = matches!(it.value, Value::Bytes(_) | Value::Text(_));
        let kids = node.into_children();
        for (seg, kid) in kids.into_iter().rev() {
            stack.push(Task::Node {
                node: kid,
                path: path.child(seg),
                base,
                parent_tag: tag,
                chunk: is_string,
            });
        }
    }
    HexRows { rows }
}

enum Task<'r> {
    Node {
        node: Node<'r>,
        path: Path,
        base: Option<usize>,
        parent_tag: Option<u64>,
        chunk: bool,
    },
    Break {
        path: Path,
        end: usize,
    },
}

/// What a head says, as in cbor.me.
fn describe(item: &Item<'_>, head_len: usize) -> String {
    let count = |n: usize| {
        if item.width == Width::Indefinite {
            "*".to_string()
        } else {
            n.to_string()
        }
    };
    match &item.value {
        Value::Uint(n) => format!("unsigned({n})"),
        Value::Nint(n) => format!("negative({n})"),
        Value::Bytes(b) => format!("bytes({})", count(b.len())),
        Value::Text(t) => format!("text({})", count(t.len())),
        Value::Array(a) => format!("array({})", count(a.len())),
        Value::Map(m) => format!("map({})", count(m.len())),
        Value::Tag(n, _) => format!("tag({n})"),
        Value::Bool(false) => "false".into(),
        Value::Bool(true) => "true".into(),
        Value::Null => "null".into(),
        Value::Undefined => "undefined".into(),
        Value::Simple(n) => format!("simple({n})"),
        Value::Float(..) => match head_len {
            3 => "float16".into(),
            5 => "float32".into(),
            _ => "float64".into(),
        },
    }
}
