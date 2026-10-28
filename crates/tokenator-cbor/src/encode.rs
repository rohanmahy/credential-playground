//! Encoding, either preserving recorded encoding details or deterministic.

use crate::Item;

/// How [`encode`] chooses among the encodings RFC 8949 allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeMode {
    /// Reproduce the recorded argument widths, float widths, indefinite
    /// lengths, string chunks, and map arrival order. Encoding a decoded item
    /// gives back the input bytes exactly.
    Preserve,
    /// RFC 8949 §4.2.1 core deterministic encoding: preferred serialization
    /// (shortest arguments, shortest exact floats with NaN payloads kept),
    /// definite lengths only, and map entries sorted by the bytewise
    /// lexicographic order of their deterministically encoded keys. Duplicate
    /// keys are kept (adjacent, in arrival order). Tags, including bignums,
    /// are not rewritten.
    Deterministic,
}

/// Encodes an item.
///
/// Does not validate: a `Value::Simple` in 24..=31 is emitted as
/// `0xf8 nn`, which is not well-formed.
pub fn encode(item: &Item, mode: EncodeMode) -> Vec<u8> {
    let _ = (item, mode);
    unimplemented!()
}
