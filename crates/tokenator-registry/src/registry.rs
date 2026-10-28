//! The [`Registry`]: lookups, snapshot (de)serialization, and IANA merging.

use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::{
    Entry, EntryKind, Label, LocalAdditions, RegistryError, RegistryId, Source, parse_iana,
};

/// The snapshot format version written by [`Registry::to_snapshot`].
const FORMAT: u32 = 1;

/// What identifies an entry: kind, kty (for COSE key type parameters only),
/// and label.
pub(crate) type Identity = (EntryKind, Option<Label>, Label);

/// The identity of `e`.
pub(crate) fn identity(e: &Entry) -> Identity {
    let key_type = match e.kind {
        EntryKind::CoseKeyTypeParam => e.key_type.clone(),
        _ => None,
    };
    (e.kind, key_type, e.label.clone())
}

/// Precedence order within one identity: lower wins.
fn rank(source: Source) -> u8 {
    match source {
        Source::Refreshed => 0,
        Source::Iana => 1,
        Source::Local => 2,
    }
}

/// Equal apart from [`Entry::source`].
fn same_content(a: &Entry, b: &Entry) -> bool {
    a.kind == b.kind
        && a.label == b.label
        && a.name == b.name
        && a.description == b.description
        && a.value_type == b.value_type
        && a.reference == b.reference
        && a.temporary == b.temporary
        && a.key_type == b.key_type
        && a.jwt_name == b.jwt_name
}

fn to_json<T: Serialize + ?Sized>(value: &T) -> Result<String, RegistryError> {
    serde_json::to_string(value).map_err(|e| RegistryError::Snapshot(e.to_string()))
}

#[derive(Deserialize)]
struct SnapshotRepr {
    format: u32,
    sd_cwt_revision: String,
    iana_updated: BTreeMap<RegistryId, String>,
    entries: Vec<Entry>,
}

/// Metadata carried by a snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotInfo {
    /// Snapshot format version.
    pub format: u32,
    /// The SD-CWT draft revision the local codepoints come from.
    pub sd_cwt_revision: String,
    /// The `<updated>` date of each IANA registry the entries came from.
    pub iana_updated: BTreeMap<RegistryId, String>,
}

/// What [`Registry::merge_iana`] changed, relative to the registry before the merge.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegistryStats {
    /// Codepoints not previously present.
    pub added: usize,
    /// Codepoints present before (from IANA) whose content changed.
    pub updated: usize,
    /// Codepoints present before (from IANA) with identical content.
    pub unchanged: usize,
    /// IANA codepoints of the merged kinds that the refresh no longer lists.
    pub removed: usize,
    /// Local additions replaced because IANA now registers the same codepoint.
    pub superseded_local: usize,
    /// The refreshed registry's `<updated>` date, if present.
    pub iana_updated: Option<String>,
}

/// Claims and headers registry. Cheap to query; build once and share.
///
/// Entries are identified by `(kind, label)`, plus the kty for
/// [`EntryKind::CoseKeyTypeParam`]. When several entries share an identity
/// only the one with the highest precedence (`Refreshed` > `Iana` > `Local`)
/// is visible; the others are kept, so a local addition comes back if IANA
/// later drops the codepoint.
///
/// # Examples
///
/// Look up names in the bundled registry:
///
/// ```
/// use tokenator_registry::Registry;
///
/// let reg = Registry::shared()?;
/// assert_eq!(reg.cose_alg(-7).unwrap().name, "ES256");
/// assert_eq!(reg.cwt_claim(1).unwrap().name, "iss");
/// assert_eq!(reg.jose_header("typ").unwrap().description, "Type");
/// assert_eq!(reg.cwt_to_jwt(7), Some("jti"));
/// # Ok::<(), tokenator_registry::RegistryError>(())
/// ```
///
/// Refresh a registry from a newer IANA fetch, then cache the result:
///
/// ```
/// use tokenator_registry::{Registry, RegistryId, Source};
///
/// let mut reg = Registry::bundled()?;
/// // In the app, `Platform` fetches RegistryId::Cose.url(); here a tiny stand-in.
/// let fetched = br#"<registry id="cose"><updated>2027-01-01</updated>
///   <registry id="algorithms">
///     <record><name>ES256</name><value>-7</value>
///       <description>ECDSA w/ SHA-256</description></record>
///   </registry></registry>"#;
/// let stats = reg.merge_iana(fetched, RegistryId::Cose)?;
/// assert_eq!(stats.iana_updated.as_deref(), Some("2027-01-01"));
/// assert!(stats.removed > 0); // COSE codepoints missing from the fetch are dropped
/// assert_eq!(reg.cose_alg(-7).unwrap().source, Source::Refreshed);
/// assert!(reg.cose_alg(-8).is_none());
/// // CWT, JOSE, JWT, and local entries are untouched.
/// assert_eq!(reg.cwt_claim(1).unwrap().source, Source::Iana);
///
/// let cached: Vec<u8> = reg.to_snapshot()?;
/// let restored = Registry::from_snapshot(&cached)?;
/// assert_eq!(restored.len(), reg.len());
/// # Ok::<(), tokenator_registry::RegistryError>(())
/// ```
#[derive(Clone, Debug)]
pub struct Registry {
    /// All entries, including shadowed ones, sorted by identity then precedence.
    entries: Vec<Entry>,
    /// The visible entry for each identity (an index into `entries`).
    index: BTreeMap<Identity, usize>,
    info: SnapshotInfo,
}

impl Registry {
    /// The snapshot embedded at build time (generated by `tools/registry-gen`).
    pub const BUNDLED_SNAPSHOT: &'static [u8] = include_bytes!("../data/snapshot.json");

    /// Loads [`Self::BUNDLED_SNAPSHOT`] into a new registry.
    pub fn bundled() -> Result<Self, RegistryError> {
        Self::from_snapshot(Self::BUNDLED_SNAPSHOT)
    }

    /// The bundled registry, parsed once on first use and shared afterwards.
    /// Use [`Self::bundled`] for a copy that can be merged into.
    pub fn shared() -> Result<&'static Self, RegistryError> {
        static SHARED: OnceLock<Result<Registry, RegistryError>> = OnceLock::new();
        SHARED
            .get_or_init(Self::bundled)
            .as_ref()
            .map_err(Clone::clone)
    }

    fn from_parts(mut entries: Vec<Entry>, info: SnapshotInfo) -> Self {
        entries.sort_by_cached_key(|e| (identity(e), rank(e.source)));
        let mut index = BTreeMap::new();
        for (i, e) in entries.iter().enumerate() {
            index.entry(identity(e)).or_insert(i);
        }
        Self {
            entries,
            index,
            info,
        }
    }

    /// Loads a snapshot produced by [`Self::to_snapshot`] (bundled or cached).
    pub fn from_snapshot(bytes: &[u8]) -> Result<Self, RegistryError> {
        let repr: SnapshotRepr =
            serde_json::from_slice(bytes).map_err(|e| RegistryError::Snapshot(e.to_string()))?;
        if repr.format != FORMAT {
            return Err(RegistryError::Snapshot(format!(
                "unsupported format {} (expected {FORMAT})",
                repr.format
            )));
        }
        let info = SnapshotInfo {
            format: repr.format,
            sd_cwt_revision: repr.sd_cwt_revision,
            iana_updated: repr.iana_updated,
        };
        Ok(Self::from_parts(repr.entries, info))
    }

    /// Serializes the registry, including sources. Deterministic: the same
    /// registry always yields the same bytes.
    ///
    /// The format is JSON, `{"format":1, "sd_cwt_revision", "iana_updated",
    /// "entries"}`, with one entry per line so that diffs stay readable.
    pub fn to_snapshot(&self) -> Result<Vec<u8>, RegistryError> {
        let mut out = format!(
            "{{\"format\":{FORMAT},\"sd_cwt_revision\":{},\"iana_updated\":{},\"entries\":[\n",
            to_json(&self.info.sd_cwt_revision)?,
            to_json(&self.info.iana_updated)?,
        );
        for (i, e) in self.entries.iter().enumerate() {
            if i > 0 {
                out.push_str(",\n");
            }
            out.push_str(&to_json(e)?);
        }
        out.push_str("\n]}\n");
        Ok(out.into_bytes())
    }

    /// Builds a registry from IANA XML documents plus local additions. IANA
    /// entries shadow local ones with the same identity (the shadowed local
    /// entries are kept, including in the snapshot). Used by the generator.
    pub fn build(
        iana: &[(RegistryId, &[u8])],
        local: LocalAdditions,
    ) -> Result<Self, RegistryError> {
        let mut entries: Vec<Entry> = local
            .entries
            .into_iter()
            .map(|e| Entry {
                source: Source::Local,
                ..e
            })
            .collect();
        let mut iana_updated = BTreeMap::new();
        for &(which, xml) in iana {
            let parsed = parse_iana(xml, which)?;
            if let Some(updated) = parsed.updated {
                iana_updated.insert(which, updated);
            }
            entries.extend(parsed.entries);
        }
        let info = SnapshotInfo {
            format: FORMAT,
            sd_cwt_revision: local.sd_cwt_revision,
            iana_updated,
        };
        Ok(Self::from_parts(entries, info))
    }

    /// Snapshot metadata.
    pub fn info(&self) -> &SnapshotInfo {
        &self.info
    }

    /// The pinned SD-CWT draft revision, e.g. `draft-ietf-spice-sd-cwt-08`.
    pub fn sd_cwt_revision(&self) -> &str {
        &self.info.sd_cwt_revision
    }

    /// Number of visible entries (shadowed local entries are not counted).
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// True if the registry holds no entries.
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    fn lookup(&self, id: &Identity) -> Option<&Entry> {
        self.index.get(id).and_then(|&i| self.entries.get(i))
    }

    /// Visible entries in identity order.
    fn visible(&self) -> impl Iterator<Item = &Entry> {
        self.index.values().filter_map(|&i| self.entries.get(i))
    }

    /// Visible entries of `kind`, ordered by (kty, label).
    fn of_kind(&self, kind: EntryKind) -> impl Iterator<Item = &Entry> {
        self.index
            .range((kind, None, Label::Int(i64::MIN))..)
            .take_while(move |((k, _, _), _)| *k == kind)
            .filter_map(|(_, &i)| self.entries.get(i))
    }

    /// Looks up an entry by kind and label. For [`EntryKind::CoseKeyTypeParam`]
    /// use [`Self::cose_key_param`] instead, since labels repeat per kty.
    pub fn get(&self, kind: EntryKind, label: impl Into<Label>) -> Option<&Entry> {
        self.lookup(&(kind, None, label.into()))
    }

    /// Looks up an entry by its name (exact match), e.g. `(CoseAlg, "ES256")`.
    pub fn by_name(&self, kind: EntryKind, name: &str) -> Option<&Entry> {
        self.of_kind(kind).find(|e| e.name == name)
    }

    /// All entries of a kind, ordered by label.
    pub fn entries(&self, kind: EntryKind) -> Vec<&Entry> {
        self.of_kind(kind).collect()
    }

    /// Entries whose name starts with `prefix` (ASCII case-insensitive),
    /// optionally restricted to one kind. For Live-edit autocomplete.
    pub fn search(&self, kind: Option<EntryKind>, prefix: &str) -> Vec<&Entry> {
        let matches = |e: &&Entry| {
            e.name
                .get(..prefix.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
        };
        match kind {
            Some(k) => self.of_kind(k).filter(matches).collect(),
            None => self.visible().filter(matches).collect(),
        }
    }

    /// JOSE header parameter by name (`"alg"`, `"x5c"`, …).
    pub fn jose_header(&self, name: &str) -> Option<&Entry> {
        self.get(EntryKind::JoseHeader, name)
    }

    /// JOSE algorithm by name (`"ES256"`).
    pub fn jose_alg(&self, name: &str) -> Option<&Entry> {
        self.get(EntryKind::JoseAlg, name)
    }

    /// JWK key type (`"EC"`, `"AKP"`).
    pub fn jwk_kty(&self, name: &str) -> Option<&Entry> {
        self.get(EntryKind::JwkKty, name)
    }

    /// JWK curve (`"P-256"`).
    pub fn jwk_crv(&self, name: &str) -> Option<&Entry> {
        self.get(EntryKind::JwkCrv, name)
    }

    /// JWK member (`"kty"`, `"x"`).
    pub fn jwk_param(&self, name: &str) -> Option<&Entry> {
        self.get(EntryKind::JwkParam, name)
    }

    /// JWT claim by name (`"iss"`, `"_sd"`).
    pub fn jwt_claim(&self, name: &str) -> Option<&Entry> {
        self.get(EntryKind::JwtClaim, name)
    }

    /// JWT confirmation method (`"jwk"`, `"jkt"`).
    pub fn jwt_cnf_method(&self, name: &str) -> Option<&Entry> {
        self.get(EntryKind::JwtCnfMethod, name)
    }

    /// COSE header parameter by label (`4`, or a text label).
    pub fn cose_header(&self, label: impl Into<Label>) -> Option<&Entry> {
        self.get(EntryKind::CoseHeader, label)
    }

    /// COSE algorithm by value (`-7`).
    pub fn cose_alg(&self, value: i64) -> Option<&Entry> {
        self.get(EntryKind::CoseAlg, value)
    }

    /// COSE key type by value (`2` → EC2).
    pub fn cose_kty(&self, value: i64) -> Option<&Entry> {
        self.get(EntryKind::CoseKty, value)
    }

    /// COSE elliptic curve by value (`1` → P-256).
    pub fn cose_crv(&self, value: i64) -> Option<&Entry> {
        self.get(EntryKind::CoseCrv, value)
    }

    /// COSE_Key parameter. Checks the type-specific parameters of `kty` first
    /// (if given), then the common parameters.
    pub fn cose_key_param(&self, kty: Option<i64>, label: i64) -> Option<&Entry> {
        kty.and_then(|kty| {
            self.lookup(&(
                EntryKind::CoseKeyTypeParam,
                Some(Label::Int(kty)),
                Label::Int(label),
            ))
        })
        .or_else(|| self.get(EntryKind::CoseKeyParam, label))
    }

    /// CWT claim by key (`1` → iss).
    pub fn cwt_claim(&self, key: impl Into<Label>) -> Option<&Entry> {
        self.get(EntryKind::CwtClaim, key)
    }

    /// CWT confirmation method by key (`1` → COSE_Key).
    pub fn cwt_cnf_method(&self, key: i64) -> Option<&Entry> {
        self.get(EntryKind::CwtCnfMethod, key)
    }

    /// CBOR tag relevant to tokens (`61` → CWT, `58` → to-be-redacted).
    pub fn cbor_tag(&self, tag: u64) -> Option<&Entry> {
        i64::try_from(tag)
            .ok()
            .and_then(|t| self.get(EntryKind::CborTag, t))
    }

    /// CBOR simple value relevant to tokens (`59` → redacted claim keys).
    pub fn cbor_simple(&self, value: u8) -> Option<&Entry> {
        self.get(EntryKind::CborSimple, i64::from(value))
    }

    /// The CWT claim key for a JWT claim name (`"jti"` → `7`), from the JWT
    /// column of the CWT claims registry.
    pub fn jwt_to_cwt(&self, jwt_claim: &str) -> Option<&Label> {
        self.of_kind(EntryKind::CwtClaim)
            .find(|e| e.jwt_name.as_deref() == Some(jwt_claim))
            .map(|e| &e.label)
    }

    /// The JWT claim name for a CWT claim key (`7` → `"jti"`).
    pub fn cwt_to_jwt(&self, key: impl Into<Label>) -> Option<&str> {
        self.cwt_claim(key)?.jwt_name.as_deref()
    }

    /// Merges a refreshed IANA fetch over the registry.
    ///
    /// Entries from `xml` get [`crate::Source::Refreshed`] and replace any
    /// entry with the same identity. Iana/Refreshed entries of `which.kinds()`
    /// that the refresh no longer lists are removed. Local entries are never
    /// discarded: a superseded one is shadowed, and becomes visible again if
    /// IANA later drops the codepoint (e.g. an expired TEMPORARY
    /// registration). On error the registry is unchanged.
    pub fn merge_iana(
        &mut self,
        xml: &[u8],
        which: RegistryId,
    ) -> Result<RegistryStats, RegistryError> {
        let parsed = parse_iana(xml, which)?;
        let kinds = which.kinds();
        let mut stats = RegistryStats {
            iana_updated: parsed.updated.clone(),
            ..RegistryStats::default()
        };
        let mut fresh = HashSet::with_capacity(parsed.entries.len());
        for e in &parsed.entries {
            let id = identity(e);
            match self.lookup(&id) {
                Some(old) if old.source == Source::Local => stats.superseded_local += 1,
                Some(old) if same_content(old, e) => stats.unchanged += 1,
                Some(_) => stats.updated += 1,
                None => stats.added += 1,
            }
            fresh.insert(id);
        }
        let owned = |e: &Entry| kinds.contains(&e.kind) && e.source != Source::Local;
        stats.removed = self
            .entries
            .iter()
            .filter(|e| owned(e) && !fresh.contains(&identity(e)))
            .count();

        let mut entries: Vec<Entry> = std::mem::take(&mut self.entries)
            .into_iter()
            .filter(|e| !owned(e))
            .collect();
        entries.extend(parsed.entries.into_iter().map(|e| Entry {
            source: Source::Refreshed,
            ..e
        }));
        let mut info = self.info.clone();
        if let Some(updated) = parsed.updated {
            info.iana_updated.insert(which, updated);
        }
        *self = Self::from_parts(entries, info);
        Ok(stats)
    }
}
