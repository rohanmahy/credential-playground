//! `read_clipboard` / `write_clipboard`, through the clipboard plugin from
//! Rust (the webview has no clipboard permission).
use tauri::{AppHandle, Runtime, State};

use crate::error::PlatformError;

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
        let _ = &self.app;
        unimplemented!("TauriClipboard::read_text")
    }

    fn write_text(&self, text: &str, sensitive: bool) -> Result<(), PlatformError> {
        let _ = (text, sensitive);
        unimplemented!("TauriClipboard::write_text")
    }
}

/// State of the clipboard commands.
pub struct ClipboardState(pub Box<dyn Clipboard>);

/// The clipboard text.
#[tauri::command(rename_all = "snake_case")]
pub async fn read_clipboard(state: State<'_, ClipboardState>) -> Result<String, PlatformError> {
    let _ = &state.0;
    unimplemented!("read_clipboard")
}

/// Copies `text`; `sensitive` for private key material.
#[tauri::command(rename_all = "snake_case")]
pub async fn write_clipboard(
    state: State<'_, ClipboardState>,
    text: String,
    sensitive: bool,
) -> Result<(), PlatformError> {
    let _ = (state, text, sensitive);
    unimplemented!("write_clipboard")
}
