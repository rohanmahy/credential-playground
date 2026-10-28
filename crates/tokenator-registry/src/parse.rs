//! IANA XML and local-additions parsing.

use crate::{Entry, RegistryError, RegistryId};

/// The entries parsed from one IANA registry XML document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedRegistry {
    /// Which registry this is.
    pub which: RegistryId,
    /// The root `<updated>` date (`YYYY-MM-DD`), if present.
    pub updated: Option<String>,
    /// Entries, all with [`crate::Source::Iana`], in document order. Ranges,
    /// `Unassigned`, `Reserved…`, and `delegated…` records are skipped.
    pub entries: Vec<Entry>,
}

/// Parses one IANA registry XML document (e.g. `cose.xml`).
///
/// Returns [`RegistryError::WrongRegistry`] if the root `<registry id>` isn't
/// `which.xml_id()`, and [`RegistryError::Xml`] if the document is malformed.
/// Never panics on bad input.
pub fn parse_iana(xml: &[u8], which: RegistryId) -> Result<ParsedRegistry, RegistryError> {
    let _ = (xml, which);
    unimplemented!()
}

/// The contents of `data/local-additions.json`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalAdditions {
    /// The SD-CWT draft revision the codepoints come from, e.g.
    /// `draft-ietf-spice-sd-cwt-08`.
    pub sd_cwt_revision: String,
    /// Entries, all with [`crate::Source::Local`].
    pub entries: Vec<Entry>,
}

impl LocalAdditions {
    /// The local-additions file shipped with this crate.
    pub const BUNDLED: &'static str = include_str!("../data/local-additions.json");

    /// Parses a local-additions document.
    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        let _ = text;
        unimplemented!()
    }

    /// Parses [`Self::BUNDLED`].
    pub fn bundled() -> Result<Self, RegistryError> {
        Self::parse(Self::BUNDLED)
    }
}
