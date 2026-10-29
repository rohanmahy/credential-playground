//! Registry lookups and refresh.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::common::Bytes;
use super::document::SpecLink;

/// Input of [`Engine::registry_lookup`](crate::Engine::registry_lookup).
/// All given fields must match; an empty query matches nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
#[serde(default)]
pub struct RegistryQuery {
    /// Entry kind.
    pub kind: Option<RegistryKind>,
    /// Exact label (needs `kind`).
    pub label: Option<RegistryLabel>,
    /// Exact name (needs `kind`).
    pub name: Option<String>,
    /// Name prefix (autocomplete).
    pub prefix: Option<String>,
}

/// `tokenator_registry::EntryKind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum RegistryKind {
    /// JOSE header parameter.
    JoseHeader,
    /// JOSE algorithm.
    JoseAlg,
    /// JWK `kty`.
    JwkKty,
    /// JWK `crv`.
    JwkCrv,
    /// JWK parameter.
    JwkParam,
    /// JWT claim.
    JwtClaim,
    /// JWT `cnf` method.
    JwtCnfMethod,
    /// COSE header label.
    CoseHeader,
    /// COSE algorithm-specific header label.
    CoseHeaderAlgParam,
    /// COSE algorithm.
    CoseAlg,
    /// COSE_Key common parameter.
    CoseKeyParam,
    /// COSE_Key type-specific parameter.
    CoseKeyTypeParam,
    /// COSE key type.
    CoseKty,
    /// COSE curve.
    CoseCrv,
    /// CWT claim.
    CwtClaim,
    /// CWT `cnf` method.
    CwtCnfMethod,
    /// CBOR tag.
    CborTag,
    /// CBOR simple value.
    CborSimple,
}

/// An integer or text label.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(untagged)]
pub enum RegistryLabel {
    /// Integer label.
    Int(i64),
    /// Text label.
    Text(String),
}

/// One registry entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct RegistryEntry {
    /// Kind.
    pub kind: RegistryKind,
    /// Label.
    pub label: RegistryLabel,
    /// Name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Value type.
    pub value_type: Option<String>,
    /// References (`display_text()`).
    pub spec: Vec<SpecLink>,
    /// Origin.
    pub source: RegistrySource,
    /// TEMPORARY registration.
    pub temporary: bool,
    /// JWT claim name of a CWT claim.
    pub jwt_name: Option<String>,
}

/// Where an entry came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum RegistrySource {
    /// Bundled IANA snapshot.
    Iana,
    /// Local additions.
    Local,
    /// Merged refresh.
    Refreshed,
}

/// The four refreshable IANA registries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum RegistryId {
    /// CWT.
    Cwt,
    /// COSE.
    Cose,
    /// JWT.
    Jwt,
    /// JOSE.
    Jose,
}

/// Input of [`Engine::registry_merge`](crate::Engine::registry_merge).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
pub struct RegistryMergeRequest {
    /// Snapshot to merge into; the engine's current registry when absent.
    #[serde(default)]
    pub base_snapshot: Option<Bytes>,
    /// The fetched IANA XML.
    pub xml: Bytes,
    /// Which registry it is.
    pub which: RegistryId,
}

/// The merged snapshot (cache it, then build an engine from it) and stats.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct RegistryMergeResult {
    /// For [`Engine::with_registry_snapshot`](crate::Engine::with_registry_snapshot).
    pub snapshot: Bytes,
    /// What changed.
    pub stats: RegistryStats,
}

/// `tokenator_registry::RegistryStats`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct RegistryStats {
    /// New entries.
    pub added: u32,
    /// Changed entries.
    pub updated: u32,
    /// Identical entries.
    pub unchanged: u32,
    /// Entries no longer listed.
    pub removed: u32,
    /// Local entries now shadowed.
    pub superseded_local: u32,
    /// The registry's last-updated date.
    pub iana_updated: Option<String>,
}

/// Engine and data versions for the About box.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct EngineInfo {
    /// `tokenator-core` version.
    pub version: String,
    /// Targeted SD-CWT draft revision (`draft-ietf-spice-sd-cwt-08`).
    pub sd_cwt_revision: String,
    /// IANA last-updated date per registry (`cwt`, `cose`, `jwt`, `jose`).
    pub registry_updated: BTreeMap<String, String>,
}
