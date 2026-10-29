//! The Tokenator desktop shell: `tokenator-core` as Tauri commands (the
//! desktop `Engine`) plus the desktop `Platform` side effects (fetch, files,
//! clipboard, registry cache). See `TEST-PLAN.md` for the contract.
//!
//! [`register`] adds the commands to any `tauri::Builder` and [`manage`]
//! adds their state, so the tests run the same command layer on Tauri's
//! mock runtime with fake dialogs and clipboard.
use tauri::{Builder, Manager, Runtime};

pub mod cache;
pub mod clipboard;
pub mod engine;
pub mod error;
pub mod fetch;
pub mod files;

pub use cache::RegistryCacheFile;
pub use clipboard::{Clipboard, ClipboardState, TauriClipboard};
pub use engine::EngineState;
pub use error::{PlatformError, PlatformErrorKind};
pub use fetch::{FetchPolicy, FetchResponse, Fetcher};
pub use files::{FileDialog, Files, OpenedFile, TauriFileDialog};

/// Every command, in `generate_handler!` order. `build.rs` and
/// `capabilities/main.json` must list the same set (tests/config.rs).
pub const COMMANDS: &[&str] = &[
    "engine_init",
    "engine_info",
    "engine_detect",
    "engine_open",
    "engine_render",
    "engine_parse_edit",
    "engine_issue",
    "engine_redact",
    "engine_disclose",
    "engine_present",
    "engine_validate",
    "engine_lint",
    "engine_resign",
    "engine_tamper",
    "engine_reencode",
    "engine_edit_disclosures",
    "engine_decode_embedded",
    "engine_key_import",
    "engine_key_export",
    "engine_key_public",
    "engine_key_generate",
    "engine_key_thumbprint",
    "engine_key_assign_kid",
    "engine_key_to_jwk",
    "engine_key_to_cwk",
    "engine_datetime",
    "engine_registry_lookup",
    "engine_registry_merge",
    "fetch_url",
    "open_file",
    "save_file",
    "read_clipboard",
    "write_clipboard",
    "registry_cache_get",
    "registry_cache_put",
    "registry_cache_clear",
];

/// The platform services behind the non-engine commands.
pub struct Services {
    /// `fetch_url`.
    pub fetcher: Fetcher,
    /// `open_file` / `save_file`.
    pub files: Files,
    /// `read_clipboard` / `write_clipboard`.
    pub clipboard: ClipboardState,
    /// `registry_cache_*`.
    pub cache: RegistryCacheFile,
}

/// Adds every command in [`COMMANDS`] to `builder`.
pub fn register<R: Runtime>(builder: Builder<R>) -> Builder<R> {
    builder.invoke_handler(tauri::generate_handler![
        engine::engine_init,
        engine::engine_info,
        engine::engine_detect,
        engine::engine_open,
        engine::engine_render,
        engine::engine_parse_edit,
        engine::engine_issue,
        engine::engine_redact,
        engine::engine_disclose,
        engine::engine_present,
        engine::engine_validate,
        engine::engine_lint,
        engine::engine_resign,
        engine::engine_tamper,
        engine::engine_reencode,
        engine::engine_edit_disclosures,
        engine::engine_decode_embedded,
        engine::engine_key_import,
        engine::engine_key_export,
        engine::engine_key_public,
        engine::engine_key_generate,
        engine::engine_key_thumbprint,
        engine::engine_key_assign_kid,
        engine::engine_key_to_jwk,
        engine::engine_key_to_cwk,
        engine::engine_datetime,
        engine::engine_registry_lookup,
        engine::engine_registry_merge,
        fetch::fetch_url,
        files::open_file,
        files::save_file,
        clipboard::read_clipboard,
        clipboard::write_clipboard,
        cache::registry_cache_get,
        cache::registry_cache_put,
        cache::registry_cache_clear,
    ])
}

/// Adds the commands' state to the app.
pub fn manage<R: Runtime, M: Manager<R>>(manager: &M, engine: EngineState, services: Services) {
    let _ = (manager, engine, services);
    unimplemented!("manage")
}

/// Runs the desktop app: the dialog and clipboard plugins, the commands,
/// and their state (registry cache in the app data dir, the default
/// [`FetchPolicy`]).
pub fn run() {
    unimplemented!("run")
}
