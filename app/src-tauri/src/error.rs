//! The wire error of every platform (non-engine) command.
use serde::{Deserialize, Serialize};

/// A failed platform command. `TauriPlatform` turns the fetch kinds into
/// `FetchError` and the rest into `Error`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformError {
    /// What went wrong.
    pub kind: PlatformErrorKind,
    /// Human-readable text. Never contains request or file contents.
    pub message: String,
    /// The URL concerned (fetch only).
    pub url: Option<String>,
    /// The HTTP status (kind `http` only).
    pub status: Option<u16>,
}

/// Error kinds. `blocked`, `network`, and `http` are the TS
/// `FetchErrorKind`s the desktop can produce (it has no CORS).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformErrorKind {
    /// Refused by policy before or while fetching: not https, a redirect
    /// to a non-https URL, or a body over the size cap.
    Blocked,
    /// DNS, TLS, connection, or timeout.
    Network,
    /// A response with a non-2xx status.
    Http,
    /// Reading or writing a file (picked file or registry cache).
    Io,
    /// The native dialog failed.
    Dialog,
    /// The clipboard failed.
    Clipboard,
    /// An argument out of range (e.g. a file over the size cap).
    InvalidArgument,
}

impl PlatformError {
    /// An error without URL or status.
    pub fn new(kind: PlatformErrorKind, message: impl Into<String>) -> PlatformError {
        PlatformError {
            kind,
            message: message.into(),
            url: None,
            status: None,
        }
    }
}
