//! The Engine error type.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::common::NodeId;

/// Why an Engine call failed. Never a panic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct EngineError {
    /// Stable machine-readable code.
    pub code: ErrorCode,
    /// Human-readable text.
    pub message: String,
    /// The node concerned, if any.
    pub node_id: Option<NodeId>,
}

impl EngineError {
    /// An error without a node.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> EngineError {
        EngineError {
            code,
            message: message.into(),
            node_id: None,
        }
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for EngineError {}

/// Error codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The input cannot be read as the given kind.
    Parse,
    /// Embedded CBOR could not be decoded.
    Decode,
    /// The operation does not apply to this kind.
    UnsupportedKind,
    /// The operation is not supported (yet) for this family.
    Unsupported,
    /// A candidate does not match the input.
    InvalidCandidate,
    /// Malformed request field.
    InvalidInput,
    /// A key could not be imported or converted.
    Key,
    /// A private key is needed.
    NoPrivateKey,
    /// The algorithm is unknown or does not fit the key.
    UnsupportedAlg,
    /// Signing failed.
    Crypto,
    /// Randomness is missing or not 32 bytes.
    Randomness,
    /// No node with that id.
    NodeNotFound,
    /// The node is not a byte string.
    NotBytes,
    /// Redact without anything marked.
    NothingToRedact,
    /// A disclosure index is out of range.
    DisclosureIndex,
    /// A date/time value is invalid or out of range.
    DateTime,
    /// Registry data could not be parsed.
    Registry,
}
