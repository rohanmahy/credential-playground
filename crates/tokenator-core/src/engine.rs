//! The Engine facade. Every method is a pure function of the engine's
//! registry and its arguments.
use tokenator_registry::Registry;

use crate::dto::common::Bytes;
use crate::dto::detect::Kind;
use crate::{actions, datetime, detect, edit, keyring, manipulate, reg, validate, view};

use crate::dto::actions::{
    DecodeEmbeddedRequest, DiscloseRequest, EditDisclosuresRequest, EditRequest, EditResult,
    IssueRequest, LintRequest, ManualDecode, PresentRequest, ReencodeRequest, Reencoded,
    RenderRequest, ResignRequest, TamperRequest, ValidateRequest,
};
use crate::dto::datetime::{DateTimeForms, DateTimeRequest};
use crate::dto::detect::Candidate;
use crate::dto::document::{Document, ViewOptions};
use crate::dto::error::EngineError;
use crate::dto::keys::{
    AssignKidRequest, KeyConvertRequest, KeyExport, KeyExportRequest, KeyGenRequest,
    KeyImportRequest, KeyInfo, KeyRef, Thumbprint, ThumbprintRequest,
};
use crate::dto::registry::{
    EngineInfo, RegistryEntry, RegistryMergeRequest, RegistryMergeResult, RegistryQuery,
};
use crate::dto::report::{CheckItem, ValidationReport};

/// The stateless Engine. It holds only the claims/headers registry used for
/// annotations; documents, keys, time, and randomness are always passed in.
#[derive(Clone, Debug)]
pub struct Engine {
    registry: Registry,
}

impl Engine {
    /// An engine with the bundled registry snapshot.
    pub fn new() -> Result<Engine, EngineError> {
        Registry::bundled()
            .map(|registry| Engine { registry })
            .map_err(|e| reg::registry_error(&e))
    }

    /// An engine with a registry snapshot from
    /// [`Engine::registry_merge`] (the cached refresh).
    pub fn with_registry_snapshot(snapshot: &[u8]) -> Result<Engine, EngineError> {
        Registry::from_snapshot(snapshot)
            .map(|registry| Engine { registry })
            .map_err(|e| reg::registry_error(&e))
    }

    /// Versions for the About box.
    pub fn info(&self) -> EngineInfo {
        reg::info(&self.registry)
    }

    /// Ranked readings of `input`. EDN candidates are confirmed by parsing
    /// (and dropped if they do not parse). Never panics.
    pub fn detect(&self, input: &[u8]) -> Vec<Candidate> {
        detect::detect(input)
    }

    /// Opens `input` as `candidate` (one of [`Engine::detect`]'s results).
    /// Signed and unsigned documents open alike; parse problems in parts
    /// become diagnostics. Key kinds fail with `unsupported_kind` (use
    /// [`Engine::key_import`]).
    pub fn open(
        &self,
        input: &[u8],
        candidate: &Candidate,
        view: &ViewOptions,
    ) -> Result<Document, EngineError> {
        detect::open(&self.registry, input, candidate, view)
    }

    /// Re-renders a document (new view options, after an action).
    pub fn render(&self, req: &RenderRequest) -> Result<Document, EngineError> {
        view::document(&self.registry, &req.doc.kind, &req.doc.bytes, req.layers.clone(), &req.view)
    }

    /// Live edit: parses the main pane text and rebuilds the bytes, keeping
    /// unedited regions byte for byte. Never fails; problems are
    /// diagnostics.
    pub fn parse_edit(&self, req: &EditRequest) -> EditResult {
        edit::parse_edit(&self.registry, req)
    }

    /// Issues a JWT/CWT, or an SD-JWT/SD-CWT when claims are marked.
    pub fn issue(&self, req: &IssueRequest) -> Result<Document, EngineError> {
        actions::issue(&self.registry, req)
    }

    /// Like [`Engine::issue`], but fails with `nothing_to_redact` when no
    /// claim is marked (no `sd.marks`, no tags 58/62).
    pub fn redact(&self, req: &IssueRequest) -> Result<Document, EngineError> {
        actions::redact(&self.registry, req)
    }

    /// Keeps a subset of disclosures (no key binding).
    pub fn disclose(&self, req: &DiscloseRequest) -> Result<Document, EngineError> {
        actions::disclose(&self.registry, req)
    }

    /// Presents with key binding: SD-JWT+KB, or an SD-KBT around an SD-CWT
    /// or a plain CWT.
    pub fn present(&self, req: &PresentRequest) -> Result<Document, EngineError> {
        actions::present(&self.registry, req)
    }

    /// The validation checklist (SPEC §6).
    pub fn validate(&self, req: &ValidateRequest) -> Result<ValidationReport, EngineError> {
        validate::validate(&self.registry, req)
    }

    /// The conformance lint items alone (the same ones `validate` reports).
    pub fn lint(&self, req: &LintRequest) -> Result<Vec<CheckItem>, EngineError> {
        validate::lint(&self.registry, req)
    }

    /// Signs the document's current content again.
    pub fn resign(&self, req: &ResignRequest) -> Result<Document, EngineError> {
        manipulate::resign(&self.registry, req)
    }

    /// Breaks the document on purpose, without re-signing.
    pub fn tamper(&self, req: &TamperRequest) -> Result<Document, EngineError> {
        manipulate::tamper(&self.registry, req)
    }

    /// Changes outer layers, COSE tags, CBOR serialization, or JOSE
    /// serialization.
    pub fn reencode(&self, req: &ReencodeRequest) -> Result<Reencoded, EngineError> {
        manipulate::reencode(&self.registry, req)
    }

    /// Adds, removes, reorders, or forges disclosures and decoys.
    pub fn edit_disclosures(&self, req: &EditDisclosuresRequest) -> Result<Document, EngineError> {
        manipulate::edit_disclosures(&self.registry, req)
    }

    /// Decodes one byte string node as CBOR on request (SPEC §4.1).
    pub fn decode_embedded(
        &self,
        req: &DecodeEmbeddedRequest,
    ) -> Result<ManualDecode, EngineError> {
        manipulate::decode_embedded(&self.registry, req)
    }

    /// Imports keys (a set gives several).
    pub fn key_import(&self, req: &KeyImportRequest) -> Result<Vec<KeyInfo>, EngineError> {
        keyring::key_import(req)
    }

    /// Exports a key.
    pub fn key_export(&self, req: &KeyExportRequest) -> Result<KeyExport, EngineError> {
        keyring::key_export(req)
    }

    /// The public key of a key, as a new card.
    pub fn key_public(&self, key: &KeyRef) -> Result<KeyInfo, EngineError> {
        keyring::key_public(key)
    }

    /// Generates a key from a seed or from platform entropy.
    pub fn key_generate(&self, req: &KeyGenRequest) -> Result<KeyInfo, EngineError> {
        keyring::key_generate(req)
    }

    /// A JWK or COSE thumbprint.
    pub fn key_thumbprint(&self, req: &ThumbprintRequest) -> Result<Thumbprint, EngineError> {
        keyring::key_thumbprint(req)
    }

    /// Sets the kid.
    pub fn key_assign_kid(&self, req: &AssignKidRequest) -> Result<KeyInfo, EngineError> {
        keyring::key_assign_kid(req)
    }

    /// The key as JWK JSON text.
    pub fn key_to_jwk(&self, req: &KeyConvertRequest) -> Result<String, EngineError> {
        keyring::key_to_jwk(req)
    }

    /// The key as a COSE_Key document (EDN and hex views).
    pub fn key_to_cwk(&self, req: &KeyConvertRequest) -> Result<Document, EngineError> {
        let bytes = keyring::key_to_cwk_bytes(req)?;
        view::document(&self.registry, &Kind::CoseKey, &bytes, Vec::new(), &crate::ViewOptions::default())
            .map(|mut d| {
                d.bytes = Bytes(bytes);
                d
            })
    }

    /// Date/time conversions for the chit.
    pub fn datetime(&self, req: &DateTimeRequest) -> Result<DateTimeForms, EngineError> {
        datetime::convert(req)
    }

    /// Registry entries matching a query.
    pub fn registry_lookup(&self, query: &RegistryQuery) -> Vec<RegistryEntry> {
        reg::lookup(&self.registry, query)
    }

    /// Merges a fetched IANA registry into a snapshot and returns the new
    /// snapshot. The engine itself is unchanged.
    pub fn registry_merge(
        &self,
        req: &RegistryMergeRequest,
    ) -> Result<RegistryMergeResult, EngineError> {
        reg::merge(&self.registry, req)
    }
}
