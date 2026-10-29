//! `open_file` / `save_file`. The webview never names a path: the native
//! dialog runs from Rust, and only the picked file is read or written, so
//! no fs plugin or fs scope exists.
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Runtime, State};
use tokenator_core::Bytes;

use crate::error::PlatformError;

/// The native open/save dialogs (a trait so tests can pick temp files).
pub trait FileDialog: Send + Sync {
    /// Asks for a file to open, offering `extensions` (without dots) as a
    /// filter when non-empty. `None` when cancelled.
    fn pick_open(&self, extensions: &[String]) -> Result<Option<PathBuf>, PlatformError>;
    /// Asks where to save, suggesting `suggested_name`. `None` when cancelled.
    fn pick_save(&self, suggested_name: &str) -> Result<Option<PathBuf>, PlatformError>;
}

/// [`FileDialog`] over `tauri-plugin-dialog`.
pub struct TauriFileDialog<R: Runtime> {
    app: AppHandle<R>,
}

impl<R: Runtime> TauriFileDialog<R> {
    /// Dialogs parented to the app.
    pub fn new(app: AppHandle<R>) -> TauriFileDialog<R> {
        TauriFileDialog { app }
    }
}

impl<R: Runtime> FileDialog for TauriFileDialog<R> {
    fn pick_open(&self, extensions: &[String]) -> Result<Option<PathBuf>, PlatformError> {
        let _ = (&self.app, extensions);
        unimplemented!("TauriFileDialog::pick_open")
    }

    fn pick_save(&self, suggested_name: &str) -> Result<Option<PathBuf>, PlatformError> {
        let _ = suggested_name;
        unimplemented!("TauriFileDialog::pick_save")
    }
}

/// State of the file commands.
pub struct Files {
    dialog: Box<dyn FileDialog>,
    max_bytes: u64,
}

impl Files {
    /// 16 MiB: far above any credential or key file.
    pub const DEFAULT_MAX_BYTES: u64 = 16 * 1024 * 1024;

    /// Files opened through `dialog`, refusing files over `max_bytes`.
    pub fn new(dialog: Box<dyn FileDialog>, max_bytes: u64) -> Files {
        Files { dialog, max_bytes }
    }
}

/// `<input accept>` values → dialog extension filters: `.pem` → `pem`;
/// media types (`application/jwt`) are dropped; order kept, no duplicates.
pub fn extension_filters(accept: &[String]) -> Vec<String> {
    let _ = accept;
    unimplemented!("extension_filters")
}

/// A file the user picked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenedFile {
    /// The file name (no directory).
    pub name: String,
    /// The contents.
    pub bytes: Bytes,
}

/// Asks for a file and reads it; `null` when cancelled. Files over the cap
/// are `invalid_argument`.
#[tauri::command(rename_all = "snake_case")]
pub async fn open_file(
    state: State<'_, Files>,
    accept: Option<Vec<String>>,
) -> Result<Option<OpenedFile>, PlatformError> {
    let _ = (&state.dialog, state.max_bytes, accept);
    unimplemented!("open_file")
}

/// Asks where to save and writes `data` there; `false` when cancelled.
#[tauri::command(rename_all = "snake_case")]
pub async fn save_file(
    state: State<'_, Files>,
    suggested_name: String,
    data: Bytes,
) -> Result<bool, PlatformError> {
    let _ = (state, suggested_name, data);
    unimplemented!("save_file")
}
