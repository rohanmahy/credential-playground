//! `fetch_url` policy: https only (also after redirects), size cap, timeout,
//! status mapping, no cookies, no referrer. Runs against a local plain-HTTP
//! server with `allow_loopback_http` (TEST-PLAN.md, "Real TLS").
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::time::{Duration, Instant};

use common::*;
use serde_json::json;
use tauri::async_runtime::block_on;
use tokenator_desktop::{FetchPolicy, Fetcher, PlatformError, PlatformErrorKind};

fn fetcher() -> Fetcher {
    Fetcher::new(test_policy()).unwrap()
}

fn fetch(url: &str) -> Result<tokenator_desktop::FetchResponse, PlatformError> {
    block_on(fetcher().fetch(url))
}

fn kind(result: Result<tokenator_desktop::FetchResponse, PlatformError>) -> PlatformErrorKind {
    result.expect_err("expected an error").kind
}

#[test]
fn default_policy() {
    let p = FetchPolicy::default();
    assert_eq!(p.timeout, Duration::from_secs(30));
    assert_eq!(p.connect_timeout, Duration::from_secs(10));
    assert_eq!(p.max_bytes, 8 * 1024 * 1024);
    assert_eq!(p.max_redirects, 5);
    assert!(!p.allow_loopback_http);
}

#[test]
fn default_policy_is_https_only() {
    let f = Fetcher::new(FetchPolicy::default()).unwrap();
    assert!(
        f.check_url("https://issuer.example/.well-known/jwt-vc-issuer")
            .is_ok()
    );
    for url in [
        "http://issuer.example/jwks.json",
        "http://127.0.0.1:1/jwks.json",
        "http://[::1]:1/",
        "file:///etc/passwd",
        "data:application/json,{}",
        "ftp://example.com/x",
        "ws://example.com/",
        "tauri://localhost/index.html",
        "not a url",
        "",
        "//example.com/no-scheme",
    ] {
        let err = f.check_url(url).expect_err(url);
        assert_eq!(err.kind, PlatformErrorKind::Blocked, "{url}");
        assert_eq!(err.url.as_deref(), Some(url), "{url}");
    }
}

#[test]
fn loopback_http_admits_only_loopback() {
    let f = fetcher();
    assert!(f.check_url("http://127.0.0.1:8080/x").is_ok());
    assert!(f.check_url("http://[::1]:8080/x").is_ok());
    for url in [
        "http://localhost:8080/x",
        "http://10.0.0.1/x",
        "http://example.com/x",
        "file:///tmp/x",
    ] {
        assert_eq!(
            f.check_url(url).unwrap_err().kind,
            PlatformErrorKind::Blocked,
            "{url}"
        );
    }
}

#[test]
fn blocked_urls_never_connect() {
    // A server on loopback, addressed by a non-admitted scheme or host.
    let server = TestServer::start(|_| Reply::ok("text/plain", "hi"));
    let f = Fetcher::new(FetchPolicy::default()).unwrap();
    assert_eq!(
        block_on(f.fetch(&server.url("/"))).unwrap_err().kind,
        PlatformErrorKind::Blocked
    );
    assert!(server.requests().is_empty());
}

#[test]
fn success_reports_url_status_type_and_bytes() {
    let body = br#"{"keys":[]}"#.to_vec();
    let expected = body.clone();
    let server = TestServer::start(move |_| Reply::ok("application/jwk-set+json", body.clone()));
    let r = fetch(&server.url("/jwks.json")).unwrap();
    assert_eq!(r.url, server.url("/jwks.json"));
    assert_eq!(r.status, 200);
    assert_eq!(r.content_type.as_deref(), Some("application/jwk-set+json"));
    assert_eq!(r.bytes.0, expected);
}

#[test]
fn binary_bodies_are_byte_exact() {
    let body: Vec<u8> = (0..=255).collect();
    let expected = body.clone();
    let server = TestServer::start(move |_| Reply::ok("application/cose-key-set", body.clone()));
    assert_eq!(fetch(&server.url("/k")).unwrap().bytes.0, expected);
}

#[test]
fn no_content_type_is_null() {
    let server = TestServer::start(|_| Reply::Full {
        status: 200,
        headers: Vec::new(),
        body: b"x".to_vec(),
    });
    assert_eq!(fetch(&server.url("/")).unwrap().content_type, None);
}

#[test]
fn redirects_are_followed_and_the_final_url_reported() {
    let server = TestServer::start(|path| match path {
        "/old" => Reply::redirect("/new"),
        _ => Reply::ok("text/plain", "moved"),
    });
    let r = fetch(&server.url("/old")).unwrap();
    assert_eq!(r.url, server.url("/new"));
    assert_eq!(r.bytes.0, b"moved");
}

#[test]
fn redirect_to_a_blocked_url_is_blocked() {
    let server = TestServer::start(|path| match path {
        "/to-http" => Reply::redirect("http://example.com/jwks.json"),
        "/to-file" => Reply::redirect("file:///etc/passwd"),
        _ => Reply::ok("text/plain", "x"),
    });
    for path in ["/to-http", "/to-file"] {
        let err = fetch(&server.url(path)).unwrap_err();
        assert_eq!(err.kind, PlatformErrorKind::Blocked, "{path}: {err:?}");
    }
}

#[test]
fn too_many_redirects() {
    let server = TestServer::start(|path| {
        let n: u32 = path.trim_start_matches('/').parse().unwrap_or(0);
        Reply::redirect(&format!("/{}", n + 1))
    });
    let err = fetch(&server.url("/0")).unwrap_err();
    assert_eq!(err.kind, PlatformErrorKind::Blocked, "{err:?}");
    assert!(
        server.requests().len() <= 6,
        "{} requests",
        server.requests().len()
    );
}

#[test]
fn non_2xx_is_http_with_status() {
    let server = TestServer::start(|path| match path {
        "/404" => Reply::status(404),
        "/500" => Reply::status(500),
        _ => Reply::status(304),
    });
    for (path, status) in [("/404", 404), ("/500", 500), ("/304", 304)] {
        let err = fetch(&server.url(path)).unwrap_err();
        assert_eq!(err.kind, PlatformErrorKind::Http, "{path}");
        assert_eq!(err.status, Some(status), "{path}");
        assert_eq!(err.url.as_deref(), Some(server.url(path).as_str()));
    }
}

#[test]
fn size_cap_by_content_length() {
    let cap = test_policy().max_bytes as usize;
    let server = TestServer::start(move |path| match path {
        "/at-cap" => Reply::ok("application/octet-stream", vec![1u8; cap]),
        _ => Reply::ok("application/octet-stream", vec![1u8; cap + 1]),
    });
    assert_eq!(fetch(&server.url("/at-cap")).unwrap().bytes.0.len(), cap);
    let err = fetch(&server.url("/over")).unwrap_err();
    assert_eq!(err.kind, PlatformErrorKind::Blocked, "{err:?}");
}

#[test]
fn size_cap_while_streaming() {
    // No Content-Length: the cap is enforced as the body arrives, and the
    // fetch stops reading (it does not wait for the whole 10× body).
    let cap = test_policy().max_bytes as usize;
    let server = TestServer::start(move |_| Reply::Stream {
        chunks: vec![vec![0u8; cap / 4]; 40],
    });
    let err = fetch(&server.url("/stream")).unwrap_err();
    assert_eq!(err.kind, PlatformErrorKind::Blocked, "{err:?}");
    let ok = TestServer::start(move |_| Reply::Stream {
        chunks: vec![vec![0u8; cap / 4]; 2],
    });
    assert_eq!(fetch(&ok.url("/")).unwrap().bytes.0.len(), cap / 2);
}

#[test]
fn timeout_is_network() {
    let server = TestServer::start(|_| {
        Reply::Delay(
            Duration::from_secs(10),
            Box::new(Reply::ok("text/plain", "late")),
        )
    });
    let start = Instant::now();
    let err = fetch(&server.url("/slow")).unwrap_err();
    assert_eq!(err.kind, PlatformErrorKind::Network, "{err:?}");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "took {:?}",
        start.elapsed()
    );
}

#[test]
fn connection_refused_is_network() {
    // Bind and drop to get a free port nobody listens on.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    assert_eq!(
        kind(fetch(&format!("http://127.0.0.1:{port}/"))),
        PlatformErrorKind::Network
    );
}

#[test]
fn no_cookies_even_after_set_cookie() {
    let server = TestServer::start(|path| match path {
        "/login" => Reply::redirect("/next").with_header("Set-Cookie", "session=abc; Path=/"),
        _ => Reply::ok("text/plain", "x").with_header("Set-Cookie", "other=1; Path=/"),
    });
    let f = fetcher();
    block_on(f.fetch(&server.url("/login"))).unwrap();
    block_on(f.fetch(&server.url("/again"))).unwrap();
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    for head in requests {
        assert!(!head.to_ascii_lowercase().contains("\ncookie:"), "{head}");
    }
}

#[test]
fn no_referrer_or_credentials() {
    let server = TestServer::start(|path| match path {
        "/a" => Reply::redirect("/b"),
        _ => Reply::ok("text/plain", "x"),
    });
    fetch(&server.url("/a")).unwrap();
    for head in server.requests() {
        let lower = head.to_ascii_lowercase();
        assert!(!lower.contains("\nreferer:"), "{head}");
        assert!(!lower.contains("\nauthorization:"), "{head}");
        assert!(head.starts_with("GET "), "{head}");
    }
}

#[test]
fn user_agent_names_the_app() {
    let server = TestServer::start(|_| Reply::ok("text/plain", "x"));
    fetch(&server.url("/")).unwrap();
    let head = server.requests().remove(0).to_ascii_lowercase();
    assert!(
        head.contains(&format!(
            "\nuser-agent: the-tokenator/{}",
            env!("CARGO_PKG_VERSION")
        )),
        "{head}"
    );
}

#[test]
fn credentials_in_the_url_are_blocked() {
    // https://user:pass@host would send Authorization; refuse instead.
    let f = Fetcher::new(FetchPolicy::default()).unwrap();
    assert_eq!(
        f.check_url("https://user:pass@example.com/")
            .unwrap_err()
            .kind,
        PlatformErrorKind::Blocked
    );
}

// --- through the command ------------------------------------------------

#[test]
fn command_returns_the_wire_shape() {
    let server = TestServer::start(|_| Reply::ok("application/json", "{}"));
    let h = Harness::new();
    let r = h
        .call("fetch_url", json!({ "url": server.url("/x") }))
        .unwrap();
    assert_eq!(
        r,
        json!({ "url": server.url("/x"), "status": 200, "content_type": "application/json", "bytes": b64u(b"{}") })
    );
}

#[test]
fn command_errors_are_platform_errors() {
    let server = TestServer::start(|_| Reply::status(403));
    let h = Harness::new();
    let err = h
        .call("fetch_url", json!({ "url": server.url("/x") }))
        .unwrap_err();
    assert_eq!(err["kind"], "http");
    assert_eq!(err["status"], 403);
    assert_eq!(err["url"], server.url("/x"));
    assert!(err["message"].is_string());
    let err = h
        .call("fetch_url", json!({ "url": "http://example.com/" }))
        .unwrap_err();
    assert_eq!(err["kind"], "blocked");
    assert_eq!(err["status"], serde_json::Value::Null);
}
