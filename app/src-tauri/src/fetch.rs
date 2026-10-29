//! `fetch_url`: user-confirmed fetches of key URLs, issuer metadata, and
//! IANA registries (SPEC §4.2, §7). Native, so no CORS; the policy below
//! replaces what the browser and the web CSP enforce.
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::State;
use tokenator_core::Bytes;

use crate::error::{PlatformError, PlatformErrorKind};

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
        let redirect_policy = policy.clone();
        let redirects = reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() > redirect_policy.max_redirects {
                let max = redirect_policy.max_redirects;
                return attempt.error(format!("more than {max} redirects"));
            }
            match scheme_check(&redirect_policy, attempt.url()) {
                Ok(()) => attempt.follow(),
                Err(reason) => attempt.error(format!("redirect refused: {reason}")),
            }
        });
        let client = reqwest::Client::builder()
            .user_agent(concat!("the-tokenator/", env!("CARGO_PKG_VERSION")))
            .redirect(redirects)
            .referer(false)
            .timeout(policy.timeout)
            .connect_timeout(policy.connect_timeout)
            .build()
            .map_err(|e| PlatformError::new(PlatformErrorKind::Network, e.to_string()))?;
        Ok(Fetcher { client, policy })
    }

    /// The policy in force.
    pub fn policy(&self) -> &FetchPolicy {
        &self.policy
    }

    /// Parses `url` and applies the scheme rule, without connecting.
    /// Errors are kind `blocked`.
    pub fn check_url(&self, url: &str) -> Result<reqwest::Url, PlatformError> {
        let blocked = |reason: &str| PlatformError {
            url: Some(url.to_owned()),
            ..PlatformError::new(PlatformErrorKind::Blocked, reason)
        };
        let parsed = reqwest::Url::parse(url).map_err(|e| blocked(&format!("invalid URL: {e}")))?;
        scheme_check(&self.policy, &parsed).map_err(blocked)?;
        Ok(parsed)
    }

    /// GETs `url` under the policy. Non-2xx is kind `http` (with the
    /// status), timeouts and connection failures `network`, policy refusals
    /// `blocked`.
    pub async fn fetch(&self, url: &str) -> Result<FetchResponse, PlatformError> {
        let parsed = self.check_url(url)?;
        let failed = |kind, message: String| PlatformError {
            url: Some(url.to_owned()),
            ..PlatformError::new(kind, message)
        };
        let mut response = self
            .client
            .get(parsed)
            .send()
            .await
            .map_err(|e| failed(request_error_kind(&e), e.to_string()))?;
        let status = response.status();
        // reqwest hands back, unfollowed, a redirect to a scheme it cannot
        // fetch (file:, data:, ...) without asking the redirect policy.
        if status.is_redirection() && response.headers().contains_key(reqwest::header::LOCATION) {
            return Err(failed(
                PlatformErrorKind::Blocked,
                "redirect refused: only https URLs can be fetched".to_owned(),
            ));
        }
        if !status.is_success() {
            return Err(PlatformError {
                status: Some(status.as_u16()),
                ..failed(PlatformErrorKind::Http, format!("HTTP status {status}"))
            });
        }
        let max = self.policy.max_bytes;
        let too_big = || {
            failed(
                PlatformErrorKind::Blocked,
                format!("the response is larger than {}", size_text(max)),
            )
        };
        if response.content_length().is_some_and(|len| len > max) {
            return Err(too_big());
        }
        let final_url = response.url().to_string();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| failed(request_error_kind(&e), e.to_string()))?
        {
            if (body.len() + chunk.len()) as u64 > max {
                return Err(too_big());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(FetchResponse {
            url: final_url,
            status: status.as_u16(),
            content_type,
            bytes: Bytes(body),
        })
    }
}

/// The scheme rule: https (or loopback http when the policy admits it), no
/// credentials in the URL.
fn scheme_check(policy: &FetchPolicy, url: &reqwest::Url) -> Result<(), &'static str> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err("credentials in the URL are not allowed");
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" if policy.allow_loopback_http && is_loopback_ip(url) => Ok(()),
        _ => Err("only https URLs can be fetched"),
    }
}

fn is_loopback_ip(url: &reqwest::Url) -> bool {
    // The parser normalizes IP literals, so these are the only spellings.
    matches!(url.host_str(), Some("127.0.0.1" | "[::1]"))
}

/// Redirect refusals are policy (`blocked`); everything else that fails
/// before a status arrives is `network`.
fn request_error_kind(e: &reqwest::Error) -> PlatformErrorKind {
    if e.is_redirect() {
        PlatformErrorKind::Blocked
    } else {
        PlatformErrorKind::Network
    }
}

/// `8 MiB`, or bytes below 1 MiB.
fn size_text(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    if bytes >= MIB && bytes.is_multiple_of(MIB) {
        format!("{} MiB", bytes / MIB)
    } else {
        format!("{bytes} bytes")
    }
}

/// Fetches a URL the user confirmed in the UI.
#[tauri::command(rename_all = "snake_case")]
pub async fn fetch_url(
    state: State<'_, Fetcher>,
    url: String,
) -> Result<FetchResponse, PlatformError> {
    state.fetch(&url).await
}
