//! Structural paths to nodes of an item tree.

use std::fmt;
use std::str::FromStr;

/// One step from a node to one of its children.
///
/// Indexes are positions in arrival order, never sorted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PathSegment {
    /// The n-th element of an array.
    Index(usize),
    /// The key of the n-th map entry.
    Key(usize),
    /// The value of the n-th map entry.
    Value(usize),
    /// The content of a tag.
    TagContent,
    /// The n-th item of the CBOR sequence embedded in a byte string
    /// (shown as `<<…>>`).
    Embedded(usize),
    /// The n-th chunk of an indefinite-length string.
    Chunk(usize),
}

/// A path from the root item to a node. The root is the empty path.
///
/// Displays as segments joined by `/`: `3` (index), `k3` (map key), `v3`
/// (map value), `t` (tag content), `e3` (embedded item), `c3` (chunk); the
/// root displays as the empty string. [`FromStr`] parses that form back.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Path(pub Vec<PathSegment>);

impl Path {
    /// The root path.
    pub fn root() -> Path {
        Path(Vec::new())
    }

    /// This path extended by one segment.
    pub fn child(&self, segment: PathSegment) -> Path {
        let mut segments = self.0.clone();
        segments.push(segment);
        Path(segments)
    }

    /// The segments, outermost first.
    pub fn segments(&self) -> &[PathSegment] {
        &self.0
    }

    /// Number of segments (0 for the root).
    pub fn depth(&self) -> usize {
        self.0.len()
    }

    /// Whether `self` is `other` or one of its ancestors.
    pub fn is_prefix_of(&self, other: &Path) -> bool {
        other.0.starts_with(&self.0)
    }
}

impl<const N: usize> From<[PathSegment; N]> for Path {
    fn from(segments: [PathSegment; N]) -> Path {
        Path(segments.to_vec())
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unimplemented!()
    }
}

/// Error from parsing a [`Path`] string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathParseError;

impl fmt::Display for PathParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid path")
    }
}

impl std::error::Error for PathParseError {}

impl FromStr for Path {
    type Err = PathParseError;

    fn from_str(s: &str) -> Result<Path, PathParseError> {
        unimplemented!()
    }
}
