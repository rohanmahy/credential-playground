//! Mapping from tree nodes to text and byte ranges.

use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::ops::Range;

use tokenator_cbor::Span;

use crate::path::Path;

/// Where one node appears.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeSpan {
    /// Byte range of the node's text, including its encoding indicator and,
    /// for containers and tags, everything up to the closing delimiter.
    /// Annotator comments in front of the node are not included.
    pub text: Range<usize>,
    /// 0-based lines that `text` touches, as a half-open range (a node on
    /// line 0 only has `0..1`).
    pub lines: Range<usize>,
    /// The item's CBOR span, when the item was decoded (`span.end > 0`).
    /// Inside embedded CBOR, offsets are absolute in the outer bytes.
    pub cbor: Option<Span>,
}

/// Node spans keyed by [`Path`], in pre-order (document order).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpanMap {
    entries: Vec<(Path, NodeSpan)>,
    /// Hash of each path to the index of its first entry, for [`SpanMap::get`].
    index: BTreeMap<u64, usize>,
}

fn path_hash(path: &Path) -> u64 {
    let mut h = DefaultHasher::new();
    path.hash(&mut h);
    h.finish()
}

impl SpanMap {
    /// An empty map.
    pub fn new() -> SpanMap {
        SpanMap::default()
    }

    /// Appends an entry. Callers add nodes in pre-order.
    pub fn push(&mut self, path: Path, span: NodeSpan) {
        self.index
            .entry(path_hash(&path))
            .or_insert(self.entries.len());
        self.entries.push((path, span));
    }

    /// The span of the node at `path`.
    pub fn get(&self, path: &Path) -> Option<&NodeSpan> {
        let (p, span) = self.entries.get(*self.index.get(&path_hash(path))?)?;
        if p == path {
            return Some(span);
        }
        // A hash collision: fall back to a scan.
        self.entries.iter().find(|(p, _)| p == path).map(|(_, s)| s)
    }

    /// All entries in pre-order.
    pub fn iter(&self) -> impl Iterator<Item = (&Path, &NodeSpan)> {
        self.entries.iter().map(|(p, s)| (p, s))
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The deepest node whose text range contains `offset`.
    pub fn innermost_at(&self, offset: usize) -> Option<&Path> {
        let mut best: Option<&Path> = None;
        for (path, span) in &self.entries {
            if span.text.contains(&offset) && best.is_none_or(|b| path.depth() >= b.depth()) {
                best = Some(path);
            }
        }
        best
    }
}
