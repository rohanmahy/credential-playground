//! `read_clipboard` / `write_clipboard`, through the clipboard plugin from
//! Rust (the webview has no clipboard permission).
use tauri::{AppHandle, Runtime, State};
use tauri_plugin_clipboard_manager::ClipboardExt;

use crate::error::{PlatformError, PlatformErrorKind};

/// The system clipboard (a trait so tests can use a fake).
pub trait Clipboard: Send + Sync {
    /// The clipboard text.
    fn read_text(&self) -> Result<String, PlatformError>;
    /// Replaces the clipboard text. `sensitive` marks private key material
    /// (no expiry yet; see the clarification issue).
    fn write_text(&self, text: &str, sensitive: bool) -> Result<(), PlatformError>;
}

/// [`Clipboard`] over `tauri-plugin-clipboard-manager`.
pub struct TauriClipboard<R: Runtime> {
    app: AppHandle<R>,
}

impl<R: Runtime> TauriClipboard<R> {
    /// The app's clipboard.
    pub fn new(app: AppHandle<R>) -> TauriClipboard<R> {
        TauriClipboard { app }
    }
}

impl<R: Runtime> Clipboard for TauriClipboard<R> {
    fn read_text(&self) -> Result<String, PlatformError> {
        self.app.clipboard().read_text().map_err(clipboard_error)
    }

    fn write_text(&self, text: &str, sensitive: bool) -> Result<(), PlatformError> {
        // `sensitive` has no effect yet: no clipboard expiry (#36).
        let _ = sensitive;
        self.app
            .clipboard()
            .write_text(text)
            .map_err(clipboard_error)
    }
}

fn clipboard_error(e: tauri_plugin_clipboard_manager::Error) -> PlatformError {
    PlatformError::new(PlatformErrorKind::Clipboard, e.to_string())
}

/// State of the clipboard commands.
pub struct ClipboardState(pub Box<dyn Clipboard>);

/// The clipboard text.
#[tauri::command(rename_all = "snake_case")]
pub async fn read_clipboard(state: State<'_, ClipboardState>) -> Result<String, PlatformError> {
    state.0.read_text()
}

/// Copies `text`; `sensitive` for private key material.
#[tauri::command(rename_all = "snake_case")]
pub async fn write_clipboard(
    state: State<'_, ClipboardState>,
    text: String,
    sensitive: bool,
) -> Result<(), PlatformError> {
    state.0.write_text(&text, sensitive)
}
