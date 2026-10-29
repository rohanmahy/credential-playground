//! `fetch_url`: user-confirmed fetches of key URLs, issuer metadata, and
//! IANA registries (SPEC §4.2, §7). Native, so no CORS; the policy below
//! replaces what the browser and the web CSP enforce.
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::State;
use tokenator_core::Bytes;

use crate::error::PlatformError;

/// What a fetch may do. `Default` is what the app uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchPolicy {
    /// Total time for the request, redirects, and body.
    pub timeout: Duration,
    /// Time to establish a connection.
    pub connect_timeout: Duration,
    /// Largest body accepted (by `Content-Length` and while reading).
    pub max_bytes: u64,
    /// Redirects followed; each target must pass the scheme check.
    pub max_redirects: usize,
    /// Also admit `http://127.0.0.1` and `http://[::1]` (tests only; never
    /// set by `run()`).
    pub allow_loopback_http: bool,
}

impl FetchPolicy {
    /// 8 MiB: the IANA registry XML files are under 100 KiB.
    pub const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024;
}

impl Default for FetchPolicy {
    /// https only, 30 s total, 10 s to connect, 8 MiB, 5 redirects.
    fn default() -> FetchPolicy {
        FetchPolicy {
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            max_bytes: FetchPolicy::DEFAULT_MAX_BYTES,
            max_redirects: 5,
            allow_loopback_http: false,
        }
    }
}

/// A successful fetch, as `TauriPlatform.fetchUrl` returns it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchResponse {
    /// The final URL after redirects.
    pub url: String,
    /// The HTTP status (2xx).
    pub status: u16,
    /// The `Content-Type` header, if any.
    pub content_type: Option<String>,
    /// The body.
    pub bytes: Bytes,
}

/// A reqwest client built for a [`FetchPolicy`]: rustls with the platform
/// verifier, no cookie store, no referrer, redirects checked by the policy.
pub struct Fetcher {
    client: reqwest::Client,
    policy: FetchPolicy,
}

impl Fetcher {
    /// Builds the client.
    pub fn new(policy: FetchPolicy) -> Result<Fetcher, PlatformError> {
        let _ = policy;
        unimplemented!("Fetcher::new")
    }

    /// The policy in force.
    pub fn policy(&self) -> &FetchPolicy {
        &self.policy
    }

    /// Parses `url` and applies the scheme rule, without connecting.
    /// Errors are kind `blocked`.
    pub fn check_url(&self, url: &str) -> Result<reqwest::Url, PlatformError> {
        let _ = url;
        unimplemented!("Fetcher::check_url")
    }

    /// GETs `url` under the policy. Non-2xx is kind `http` (with the
    /// status), timeouts and connection failures `network`, policy refusals
    /// `blocked`.
    pub async fn fetch(&self, url: &str) -> Result<FetchResponse, PlatformError> {
        let _ = (&self.client, url);
        unimplemented!("Fetcher::fetch")
    }
}

/// Fetches a URL the user confirmed in the UI.
#[tauri::command(rename_all = "snake_case")]
pub async fn fetch_url(
    state: State<'_, Fetcher>,
    url: String,
) -> Result<FetchResponse, PlatformError> {
    let _ = (state, url);
    unimplemented!("fetch_url")
}
