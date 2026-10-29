//! The desktop Engine: one command per `tokenator_core::Engine` method.
//! Each is a thin serde wrapper with no logic of its own: it calls the
//! same-named method on the current engine and returns the DTO or the core
//! `EngineError` unchanged. Commands are async so long calls (RSA or
//! ML-DSA keygen) run off the main thread; Tauri requires async commands
//! that borrow `State` to return `Result`, hence `Ok(..)` around the
//! infallible methods.
//!
//! Requests carry private keys (`KeyRef`); they pass through memory only.
//! Never log or `{:?}`-format a request (tests/hygiene.rs).
use std::sync::{Arc, RwLock};

use tauri::State;
use tokenator_core::{
    AssignKidRequest, Bytes, Candidate, CheckItem, DateTimeForms, DateTimeRequest,
    DecodeEmbeddedRequest, DiscloseRequest, Document, EditDisclosuresRequest, EditRequest,
    EditResult, Engine, EngineError, EngineInfo, IssueRequest, KeyConvertRequest, KeyExport,
    KeyExportRequest, KeyGenRequest, KeyImportRequest, KeyInfo, KeyRef, LintRequest, ManualDecode,
    PresentRequest, ReencodeRequest, Reencoded, RegistryEntry, RegistryMergeRequest,
    RegistryMergeResult, RegistryQuery, RenderRequest, ResignRequest, TamperRequest, Thumbprint,
    ThumbprintRequest, ValidateRequest, ValidationReport, ViewOptions,
};

/// The engine the commands use. `engine_init` replaces it (registry
/// snapshot after "Update registries").
pub struct EngineState {
    engine: RwLock<Arc<Engine>>,
}

impl EngineState {
    /// State with the bundled registry snapshot (`Engine::new`).
    pub fn bundled() -> Result<EngineState, EngineError> {
        unimplemented!("EngineState::bundled")
    }

    /// The current engine (cheap clone; the lock is not held during calls).
    pub fn current(&self) -> Arc<Engine> {
        let _ = &self.engine;
        unimplemented!("EngineState::current")
    }
}

/// Replaces the engine: `Engine::with_registry_snapshot(snapshot)`, or
/// `Engine::new()` for `null`. On error the previous engine stays.
#[tauri::command(rename_all = "snake_case")]
pub async fn engine_init(
    state: State<'_, EngineState>,
    snapshot: Option<Bytes>,
) -> Result<(), EngineError> {
    let _ = (state, snapshot);
    unimplemented!("engine_init")
}

/// `Engine::info`.
#[tauri::command(rename_all = "snake_case")]
pub async fn engine_info(state: State<'_, EngineState>) -> Result<EngineInfo, EngineError> {
    let _ = state;
    unimplemented!("engine_info")
}

/// `Engine::detect`; `input` is the raw input as base64url.
#[tauri::command(rename_all = "snake_case")]
pub async fn engine_detect(
    state: State<'_, EngineState>,
    input: Bytes,
) -> Result<Vec<Candidate>, EngineError> {
    let _ = (state, input);
    unimplemented!("engine_detect")
}

/// `Engine::open`; `input` is the raw input as base64url.
#[tauri::command(rename_all = "snake_case")]
pub async fn engine_open(
    state: State<'_, EngineState>,
    input: Bytes,
    candidate: Candidate,
    view: ViewOptions,
) -> Result<Document, EngineError> {
    let _ = (state, input, candidate, view);
    unimplemented!("engine_open")
}

/// `engine_x => x(Req) -> Res`: a command taking `req` that calls
/// `Engine::x(&req)`.
macro_rules! req_command {
    ($(#[$doc:meta] $name:ident => $method:ident($req:ty) -> $res:ty;)*) => {$(
        #[$doc]
        #[tauri::command(rename_all = "snake_case")]
        pub async fn $name(state: State<'_, EngineState>, req: $req) -> Result<$res, EngineError> {
            let _ = (state, req, stringify!($method));
            unimplemented!(stringify!($name))
        }
    )*};
}

req_command! {
    /// `Engine::render`.
    engine_render => render(RenderRequest) -> Document;
    /// `Engine::issue`.
    engine_issue => issue(IssueRequest) -> Document;
    /// `Engine::redact`.
    engine_redact => redact(IssueRequest) -> Document;
    /// `Engine::disclose`.
    engine_disclose => disclose(DiscloseRequest) -> Document;
    /// `Engine::present`.
    engine_present => present(PresentRequest) -> Document;
    /// `Engine::validate`.
    engine_validate => validate(ValidateRequest) -> ValidationReport;
    /// `Engine::lint`.
    engine_lint => lint(LintRequest) -> Vec<CheckItem>;
    /// `Engine::resign`.
    engine_resign => resign(ResignRequest) -> Document;
    /// `Engine::tamper`.
    engine_tamper => tamper(TamperRequest) -> Document;
    /// `Engine::reencode`.
    engine_reencode => reencode(ReencodeRequest) -> Reencoded;
    /// `Engine::edit_disclosures`.
    engine_edit_disclosures => edit_disclosures(EditDisclosuresRequest) -> Document;
    /// `Engine::decode_embedded`.
    engine_decode_embedded => decode_embedded(DecodeEmbeddedRequest) -> ManualDecode;
    /// `Engine::key_import`.
    engine_key_import => key_import(KeyImportRequest) -> Vec<KeyInfo>;
    /// `Engine::key_export`.
    engine_key_export => key_export(KeyExportRequest) -> KeyExport;
    /// `Engine::key_generate`.
    engine_key_generate => key_generate(KeyGenRequest) -> KeyInfo;
    /// `Engine::key_thumbprint`.
    engine_key_thumbprint => key_thumbprint(ThumbprintRequest) -> Thumbprint;
    /// `Engine::key_assign_kid`.
    engine_key_assign_kid => key_assign_kid(AssignKidRequest) -> KeyInfo;
    /// `Engine::key_to_jwk`.
    engine_key_to_jwk => key_to_jwk(KeyConvertRequest) -> String;
    /// `Engine::key_to_cwk`.
    engine_key_to_cwk => key_to_cwk(KeyConvertRequest) -> Document;
    /// `Engine::datetime`.
    engine_datetime => datetime(DateTimeRequest) -> DateTimeForms;
    /// `Engine::registry_merge`.
    engine_registry_merge => registry_merge(RegistryMergeRequest) -> RegistryMergeResult;
}

/// `Engine::parse_edit` (infallible in core).
#[tauri::command(rename_all = "snake_case")]
pub async fn engine_parse_edit(
    state: State<'_, EngineState>,
    req: EditRequest,
) -> Result<EditResult, EngineError> {
    let _ = (state, req);
    unimplemented!("engine_parse_edit")
}

/// `Engine::key_public`.
#[tauri::command(rename_all = "snake_case")]
pub async fn engine_key_public(
    state: State<'_, EngineState>,
    key: KeyRef,
) -> Result<KeyInfo, EngineError> {
    let _ = (state, key);
    unimplemented!("engine_key_public")
}

/// `Engine::registry_lookup`.
#[tauri::command(rename_all = "snake_case")]
pub async fn engine_registry_lookup(
    state: State<'_, EngineState>,
    query: RegistryQuery,
) -> Result<Vec<RegistryEntry>, EngineError> {
    let _ = (state, query);
    unimplemented!("engine_registry_lookup")
}
