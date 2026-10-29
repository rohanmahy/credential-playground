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
    AssignKidRequest, Bytes, Candidate, CheckItem, ConvertClaimsRequest, ConvertClaimsResult,
    DateTimeForms, DateTimeRequest, DecodeEmbeddedRequest, DiscloseRequest, Document,
    EditDisclosuresRequest, EditRequest, EditResult, Engine, EngineError, EngineInfo, IssueRequest,
    KeyConvertRequest, KeyExport, KeyExportRequest, KeyGenRequest, KeyImportRequest, KeyInfo,
    KeyRef, LintRequest, ManualDecode, PresentRequest, ReencodeRequest, Reencoded, RegistryEntry,
    RegistryMergeRequest, RegistryMergeResult, RegistryQuery, RenderRequest, ResignRequest,
    TamperRequest, Thumbprint, ThumbprintRequest, ValidateRequest, ValidationReport, ViewOptions,
};

/// The engine the commands use. `engine_init` replaces it (registry
/// snapshot after "Update registries").
pub struct EngineState {
    engine: RwLock<Arc<Engine>>,
}

impl EngineState {
    /// State with the bundled registry snapshot (`Engine::new`).
    pub fn bundled() -> Result<EngineState, EngineError> {
        Ok(EngineState {
            engine: RwLock::new(Arc::new(Engine::new()?)),
        })
    }

    /// The current engine (cheap clone; the lock is not held during calls).
    pub fn current(&self) -> Arc<Engine> {
        // A poisoned lock still holds a whole `Arc`: the writer only swaps it.
        match self.engine.read() {
            Ok(engine) => Arc::clone(&engine),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Makes `engine` the current engine.
    fn replace(&self, engine: Engine) {
        let engine = Arc::new(engine);
        match self.engine.write() {
            Ok(mut current) => *current = engine,
            Err(poisoned) => *poisoned.into_inner() = engine,
        }
    }
}

/// Replaces the engine: `Engine::with_registry_snapshot(snapshot)`, or
/// `Engine::new()` for `null`. On error the previous engine stays.
#[tauri::command(rename_all = "snake_case")]
pub async fn engine_init(
    state: State<'_, EngineState>,
    snapshot: Option<Bytes>,
) -> Result<(), EngineError> {
    let engine = match snapshot {
        Some(snapshot) => Engine::with_registry_snapshot(&snapshot)?,
        None => Engine::new()?,
    };
    state.replace(engine);
    Ok(())
}

/// `Engine::info`.
#[tauri::command(rename_all = "snake_case")]
pub async fn engine_info(state: State<'_, EngineState>) -> Result<EngineInfo, EngineError> {
    Ok(state.current().info())
}

/// `Engine::detect`; `input` is the raw input as base64url.
#[tauri::command(rename_all = "snake_case")]
pub async fn engine_detect(
    state: State<'_, EngineState>,
    input: Bytes,
) -> Result<Vec<Candidate>, EngineError> {
    Ok(state.current().detect(&input))
}

/// `Engine::open`; `input` is the raw input as base64url.
#[tauri::command(rename_all = "snake_case")]
pub async fn engine_open(
    state: State<'_, EngineState>,
    input: Bytes,
    candidate: Candidate,
    view: ViewOptions,
) -> Result<Document, EngineError> {
    state.current().open(&input, &candidate, &view)
}

/// `engine_x => x(Req) -> Res`: a command taking `req` that calls
/// `Engine::x(&req)`.
macro_rules! req_command {
    ($(#[$doc:meta] $name:ident => $method:ident($req:ty) -> $res:ty;)*) => {$(
        #[$doc]
        #[tauri::command(rename_all = "snake_case")]
        pub async fn $name(state: State<'_, EngineState>, req: $req) -> Result<$res, EngineError> {
            state.current().$method(&req)
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
    Ok(state.current().parse_edit(&req))
}

/// `Engine::convert_claims` (infallible in core, #44).
#[tauri::command(rename_all = "snake_case")]
pub async fn engine_convert_claims(
    state: State<'_, EngineState>,
    req: ConvertClaimsRequest,
) -> Result<ConvertClaimsResult, EngineError> {
    Ok(state.current().convert_claims(&req))
}

/// `Engine::key_public`.
#[tauri::command(rename_all = "snake_case")]
pub async fn engine_key_public(
    state: State<'_, EngineState>,
    key: KeyRef,
) -> Result<KeyInfo, EngineError> {
    state.current().key_public(&key)
}

/// `Engine::registry_lookup`.
#[tauri::command(rename_all = "snake_case")]
pub async fn engine_registry_lookup(
    state: State<'_, EngineState>,
    query: RegistryQuery,
) -> Result<Vec<RegistryEntry>, EngineError> {
    Ok(state.current().registry_lookup(&query))
}
