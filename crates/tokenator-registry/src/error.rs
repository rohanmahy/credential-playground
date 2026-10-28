//! Registry errors.

use std::fmt;

use crate::RegistryId;

/// Errors from parsing IANA XML, snapshots, or local additions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryError {
    /// The IANA XML is malformed or not a registry document.
    Xml {
        /// The registry being parsed.
        registry: RegistryId,
        /// What went wrong.
        message: String,
    },
    /// The XML is a registry, but not the one requested.
    WrongRegistry {
        /// The registry the caller asked for.
        expected: RegistryId,
        /// The root `<registry id=…>` found in the document.
        found: String,
    },
    /// The snapshot bytes are malformed or of an unsupported format version.
    Snapshot(String),
    /// The local-additions file is malformed.
    LocalAdditions(String),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xml { registry, message } => {
                write!(f, "malformed {} registry XML: {message}", registry.xml_id())
            }
            Self::WrongRegistry { expected, found } => write!(
                f,
                "expected the {} registry, found {found:?}",
                expected.xml_id()
            ),
            Self::Snapshot(m) => write!(f, "malformed registry snapshot: {m}"),
            Self::LocalAdditions(m) => write!(f, "malformed local additions: {m}"),
        }
    }
}

impl std::error::Error for RegistryError {}
