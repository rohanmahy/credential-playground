//! Checks for non-preferred and non-deterministic encodings.

use crate::{Item, Span};

/// One place where the encoding is not preferred (or not deterministic).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodingFinding {
    /// The exact input bytes that `preferred_bytes` would replace.
    ///
    /// - `NonPreferredArgument`: only the head of the item (for a string,
    ///   array, map, or tag the content is not included).
    /// - `NonPreferredFloat`: the whole float item.
    /// - `IndefiniteLength` and `MapKeyOrder`: the whole item, including
    ///   content and break byte.
    pub span: Span,
    /// What is wrong.
    pub kind: FindingKind,
    /// Replacement bytes for `span`.
    ///
    /// For `NonPreferredArgument` and `NonPreferredFloat` only the head
    /// changes. For `IndefiniteLength` it is the whole item in preferred
    /// serialization; for `MapKeyOrder` the whole map in deterministic
    /// encoding. Nested problems are still reported separately, so findings
    /// may overlap.
    pub preferred_bytes: Vec<u8>,
}

/// Kinds of [`EncodingFinding`]. The declaration order is the tie-break
/// order for findings that start at the same offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingKind {
    /// An integer, length, or tag number with a longer argument than needed.
    /// Also reported for the chunks of an indefinite-length string.
    NonPreferredArgument,
    /// A float that a shorter width represents exactly (NaN payload
    /// included).
    NonPreferredFloat,
    /// An indefinite-length string, array, or map.
    IndefiniteLength,
    /// A map whose keys are not in RFC 8949 §4.2.1 order (bytewise
    /// lexicographic order of the deterministically encoded keys). Equal
    /// (duplicate) keys are not an order violation. Only reported by
    /// [`deterministic_findings`].
    MapKeyOrder,
}

/// Every non-preferred encoding (RFC 8949 §4.1) in `item`, sorted by
/// `span.start` and then by [`FindingKind`] declaration order.
pub fn preferred_findings(item: &Item) -> Vec<EncodingFinding> {
    let _ = item;
    unimplemented!()
}

/// [`preferred_findings`] plus map key order violations (RFC 8949 §4.2.1),
/// sorted the same way.
pub fn deterministic_findings(item: &Item) -> Vec<EncodingFinding> {
    let _ = item;
    unimplemented!()
}
