//! Annotated hex rows (like cbor.me's right pane).

use std::fmt;
use std::ops::Range;

use tokenator_cbor::Item;

use crate::annotate::Annotator;
use crate::path::Path;
use crate::print::EmbeddedCbor;

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
    pub embedded_cbor: EmbeddedCbor,
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
pub fn annotated_hex(item: &Item<'_>, bytes: &[u8], options: &HexOptions<'_>) -> HexRows {
    unimplemented!()
}
