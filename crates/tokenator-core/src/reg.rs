//! Registry lookups, refresh, and version info.

use std::collections::BTreeMap;

use tokenator_registry::{Entry, EntryKind, Label, Registry, RegistryId as Rid, Source};

use crate::annotate::spec_links;
use crate::dto::common::Bytes;
use crate::dto::error::{EngineError, ErrorCode};
use crate::dto::registry::{
    EngineInfo, RegistryEntry, RegistryId, RegistryKind, RegistryLabel, RegistryMergeRequest,
    RegistryMergeResult, RegistryQuery, RegistrySource, RegistryStats,
};
use crate::util::u32_of;

pub(crate) fn registry_error(e: &tokenator_registry::RegistryError) -> EngineError {
    EngineError::new(ErrorCode::Registry, e.to_string())
}

fn kind_tk(k: RegistryKind) -> EntryKind {
    match k {
        RegistryKind::JoseHeader => EntryKind::JoseHeader,
        RegistryKind::JoseAlg => EntryKind::JoseAlg,
        RegistryKind::JwkKty => EntryKind::JwkKty,
        RegistryKind::JwkCrv => EntryKind::JwkCrv,
        RegistryKind::JwkParam => EntryKind::JwkParam,
        RegistryKind::JwtClaim => EntryKind::JwtClaim,
        RegistryKind::JwtCnfMethod => EntryKind::JwtCnfMethod,
        RegistryKind::CoseHeader => EntryKind::CoseHeader,
        RegistryKind::CoseHeaderAlgParam => EntryKind::CoseHeaderAlgParam,
        RegistryKind::CoseAlg => EntryKind::CoseAlg,
        RegistryKind::CoseKeyParam => EntryKind::CoseKeyParam,
        RegistryKind::CoseKeyTypeParam => EntryKind::CoseKeyTypeParam,
        RegistryKind::CoseKty => EntryKind::CoseKty,
        RegistryKind::CoseCrv => EntryKind::CoseCrv,
        RegistryKind::CwtClaim => EntryKind::CwtClaim,
        RegistryKind::CwtCnfMethod => EntryKind::CwtCnfMethod,
        RegistryKind::CborTag => EntryKind::CborTag,
        RegistryKind::CborSimple => EntryKind::CborSimple,
    }
}

fn kind_dto(k: EntryKind) -> RegistryKind {
    match k {
        EntryKind::JoseHeader => RegistryKind::JoseHeader,
        EntryKind::JoseAlg => RegistryKind::JoseAlg,
        EntryKind::JwkKty => RegistryKind::JwkKty,
        EntryKind::JwkCrv => RegistryKind::JwkCrv,
        EntryKind::JwkParam => RegistryKind::JwkParam,
        EntryKind::JwtClaim => RegistryKind::JwtClaim,
        EntryKind::JwtCnfMethod => RegistryKind::JwtCnfMethod,
        EntryKind::CoseHeader => RegistryKind::CoseHeader,
        EntryKind::CoseHeaderAlgParam => RegistryKind::CoseHeaderAlgParam,
        EntryKind::CoseAlg => RegistryKind::CoseAlg,
        EntryKind::CoseKeyParam => RegistryKind::CoseKeyParam,
        EntryKind::CoseKeyTypeParam => RegistryKind::CoseKeyTypeParam,
        EntryKind::CoseKty => RegistryKind::CoseKty,
        EntryKind::CoseCrv => RegistryKind::CoseCrv,
        EntryKind::CwtClaim => RegistryKind::CwtClaim,
        EntryKind::CwtCnfMethod => RegistryKind::CwtCnfMethod,
        EntryKind::CborTag => RegistryKind::CborTag,
        EntryKind::CborSimple => RegistryKind::CborSimple,
    }
}

fn label_tk(l: &RegistryLabel) -> Label {
    match l {
        RegistryLabel::Int(n) => Label::Int(*n),
        RegistryLabel::Text(t) => Label::Text(t.clone()),
    }
}

fn entry_dto(e: &Entry) -> RegistryEntry {
    RegistryEntry {
        kind: kind_dto(e.kind),
        label: match &e.label {
            Label::Int(n) => RegistryLabel::Int(*n),
            Label::Text(t) => RegistryLabel::Text(t.clone()),
        },
        name: e.name.clone(),
        description: e.description.clone(),
        value_type: e.value_type.clone(),
        spec: spec_links(e),
        source: match e.source {
            Source::Iana => RegistrySource::Iana,
            Source::Local => RegistrySource::Local,
            Source::Refreshed => RegistrySource::Refreshed,
        },
        temporary: e.temporary,
        jwt_name: e.jwt_name.clone(),
    }
}

/// Entries matching every given field of `q` (none for an empty query).
pub(crate) fn lookup(registry: &Registry, q: &RegistryQuery) -> Vec<RegistryEntry> {
    let kind = q.kind.map(kind_tk);
    let found: Vec<&Entry> = match (kind, &q.label, &q.name, &q.prefix) {
        (_, None, None, None) => Vec::new(),
        (Some(k), Some(label), _, _) => registry.get(k, label_tk(label)).into_iter().collect(),
        (Some(k), None, Some(name), _) => registry.by_name(k, name).into_iter().collect(),
        (kind, None, None, Some(prefix)) => registry.search(kind, prefix),
        (None, _, _, _) => Vec::new(),
    };
    found
        .into_iter()
        .filter(|e| q.name.as_ref().is_none_or(|n| &e.name == n))
        .filter(|e| {
            q.prefix
                .as_ref()
                .is_none_or(|p| e.name.starts_with(p.as_str()))
        })
        .filter(|e| kind.is_none_or(|k| e.kind == k))
        .map(entry_dto)
        .collect()
}

fn rid(r: RegistryId) -> Rid {
    match r {
        RegistryId::Cwt => Rid::Cwt,
        RegistryId::Cose => Rid::Cose,
        RegistryId::Jwt => Rid::Jwt,
        RegistryId::Jose => Rid::Jose,
    }
}

pub(crate) fn merge(
    registry: &Registry,
    req: &RegistryMergeRequest,
) -> Result<RegistryMergeResult, EngineError> {
    let mut base = match &req.base_snapshot {
        Some(snapshot) => Registry::from_snapshot(snapshot).map_err(|e| registry_error(&e))?,
        None => registry.clone(),
    };
    let stats = base
        .merge_iana(&req.xml, rid(req.which))
        .map_err(|e| registry_error(&e))?;
    let snapshot = base.to_snapshot().map_err(|e| registry_error(&e))?;
    Ok(RegistryMergeResult {
        snapshot: Bytes(snapshot),
        stats: RegistryStats {
            added: u32_of(stats.added),
            updated: u32_of(stats.updated),
            unchanged: u32_of(stats.unchanged),
            removed: u32_of(stats.removed),
            superseded_local: u32_of(stats.superseded_local),
            iana_updated: stats.iana_updated,
        },
    })
}

pub(crate) fn info(registry: &Registry) -> EngineInfo {
    let registry_updated: BTreeMap<String, String> = registry
        .info()
        .iana_updated
        .iter()
        .map(|(id, date)| (id.xml_id().to_owned(), date.clone()))
        .collect();
    EngineInfo {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        sd_cwt_revision: registry.sd_cwt_revision().to_owned(),
        registry_updated,
    }
}
