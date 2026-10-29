//! `open_file` / `save_file`. The webview never names a path: the native
//! dialog runs from Rust, and only the picked file is read or written, so
//! no fs plugin or fs scope exists.
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Runtime, State};
use tauri_plugin_dialog::{DialogExt, FilePath};
use tokenator_core::Bytes;

use crate::error::{PlatformError, PlatformErrorKind};

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
        let mut builder = self.app.dialog().file();
        if !extensions.is_empty() {
            let extensions: Vec<&str> = extensions.iter().map(String::as_str).collect();
            builder = builder.add_filter("Supported files", &extensions);
        }
        builder.blocking_pick_file().map(local_path).transpose()
    }

    fn pick_save(&self, suggested_name: &str) -> Result<Option<PathBuf>, PlatformError> {
        self.app
            .dialog()
            .file()
            .set_file_name(suggested_name)
            .blocking_save_file()
            .map(local_path)
            .transpose()
    }
}

/// The dialog's pick as a local path (macOS dialogs never return URLs).
fn local_path(picked: FilePath) -> Result<PathBuf, PlatformError> {
    picked
        .into_path()
        .map_err(|e| PlatformError::new(PlatformErrorKind::Dialog, e.to_string()))
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
    let mut out: Vec<String> = Vec::new();
    for value in accept {
        let value = value.trim();
        if value.contains('/') {
            continue; // a media type
        }
        let ext = value.strip_prefix('.').unwrap_or(value);
        if !ext.is_empty() && !out.iter().any(|e| e == ext) {
            out.push(ext.to_owned());
        }
    }
    out
}

/// Reads `path`, refusing files over `max_bytes` (also if one grows while
/// being read).
fn read_capped(path: &Path, max_bytes: u64) -> Result<Vec<u8>, PlatformError> {
    let too_big = || {
        PlatformError::new(
            PlatformErrorKind::InvalidArgument,
            format!("the file is larger than {max_bytes} bytes"),
        )
    };
    let file = std::fs::File::open(path).map_err(|e| io_error("opening the file", &e))?;
    let len = file
        .metadata()
        .map_err(|e| io_error("reading the file", &e))?
        .len();
    if len > max_bytes {
        return Err(too_big());
    }
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| io_error("reading the file", &e))?;
    if bytes.len() as u64 > max_bytes {
        return Err(too_big());
    }
    Ok(bytes)
}

fn io_error(what: &str, e: &std::io::Error) -> PlatformError {
    PlatformError::new(PlatformErrorKind::Io, format!("{what}: {e}"))
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
    let extensions = extension_filters(accept.as_deref().unwrap_or_default());
    let Some(path) = state.dialog.pick_open(&extensions)? else {
        return Ok(None);
    };
    let bytes = read_capped(&path, state.max_bytes)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(Some(OpenedFile {
        name,
        bytes: Bytes(bytes),
    }))
}

/// Asks where to save and writes `data` there; `false` when cancelled.
#[tauri::command(rename_all = "snake_case")]
pub async fn save_file(
    state: State<'_, Files>,
    suggested_name: String,
    data: Bytes,
) -> Result<bool, PlatformError> {
    let Some(path) = state.dialog.pick_save(&suggested_name)? else {
        return Ok(false);
    };
    std::fs::write(&path, &data.0).map_err(|e| io_error("writing the file", &e))?;
    Ok(true)
}
