//! tauri.conf.json, capabilities/, and build.rs pinned exactly: the
//! minimum permissions, no remote content, the CSP, and the bundle.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::collections::BTreeSet;

use common::*;
use serde_json::{Value, json};

fn conf() -> Value {
    serde_json::from_str(&std::fs::read_to_string(crate_dir().join("tauri.conf.json")).unwrap())
        .unwrap()
}

fn capability_files() -> Vec<String> {
    files_under(&crate_dir().join("capabilities"))
}

fn capability() -> Value {
    let text = std::fs::read_to_string(crate_dir().join("capabilities/main.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn kebab(cmd: &str) -> String {
    cmd.replace('_', "-")
}

#[test]
fn product_and_identifier() {
    let c = conf();
    assert_eq!(c["productName"], "The Tokenator");
    assert_eq!(c["mainBinaryName"], "tokenator");
    // The default until the owner decides (clarification issue).
    assert_eq!(c["identifier"], "io.github.rohanmahy.tokenator");
    assert_eq!(c.get("version"), None, "the version comes from Cargo.toml");
}

#[test]
fn build_uses_the_vite_app() {
    let b = &conf()["build"];
    assert_eq!(b["frontendDist"], "../dist");
    assert_eq!(b["devUrl"], "http://localhost:5173");
    assert_eq!(b["beforeDevCommand"], "pnpm dev");
    assert_eq!(b["beforeBuildCommand"], "pnpm build");
}

#[test]
fn one_local_incognito_window_and_no_global_tauri() {
    let app = &conf()["app"];
    assert_eq!(app["withGlobalTauri"], false);
    let windows = app["windows"].as_array().unwrap();
    assert_eq!(windows.len(), 1);
    let w = &windows[0];
    assert_eq!(w["label"], "main");
    assert_eq!(w["title"], "The Tokenator");
    assert_eq!(w["url"], "index.html", "local content only");
    assert_eq!(w["incognito"], true, "WKWebView non-persistent data store");
    assert_eq!(app.get("macOSPrivateApi"), None);
}

#[test]
fn security_settings() {
    let s = &conf()["app"]["security"];
    assert_eq!(s["capabilities"], json!(["main"]));
    assert_eq!(s.get("dangerousDisableAssetCspModification"), None);
    assert_eq!(
        s.get("assetProtocol"),
        None,
        "no asset protocol (no fs access from the webview)"
    );
    assert_eq!(s.get("headers"), None);
    assert_eq!(s.get("pattern"), None, "the default brownfield pattern");
    assert_eq!(
        s["devCsp"],
        Value::Null,
        "like the web dev server: no CSP in dev"
    );
}

#[test]
fn csp_directives() {
    let csp = conf()["app"]["security"]["csp"].clone();
    assert_eq!(
        csp,
        json!({
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'", "'unsafe-inline'"],
            "img-src": ["'self'", "data:"],
            "font-src": ["'self'"],
            "connect-src": ["ipc:", "http://ipc.localhost"],
            "worker-src": ["'self'"],
            "object-src": ["'none'"],
            "base-uri": ["'none'"],
            "form-action": ["'none'"],
            "frame-ancestors": ["'none'"]
        })
    );
    // Nothing that would let the webview reach the network or eval.
    let text = csp.to_string();
    for banned in [
        "https:",
        "'unsafe-eval'",
        "'wasm-unsafe-eval'",
        "*",
        "asset:",
    ] {
        assert!(!text.contains(banned), "{banned} in {text}");
    }
}

#[test]
fn bundle_is_an_unsigned_app() {
    let b = &conf()["bundle"];
    assert_eq!(b["active"], true);
    assert_eq!(b["targets"], json!(["app"]));
    assert_eq!(b.get("createUpdaterArtifacts"), None);
    let macos = b.get("macOS").cloned().unwrap_or(json!({}));
    assert_eq!(
        macos.get("signingIdentity"),
        None,
        "unsigned for now (SPEC §10)"
    );
    for icon in b["icon"].as_array().unwrap() {
        assert!(crate_dir().join(icon.as_str().unwrap()).exists(), "{icon}");
    }
    assert!(
        b["icon"]
            .as_array()
            .unwrap()
            .contains(&json!("icons/icon.icns"))
    );
}

#[test]
fn no_plugin_config() {
    // No updater, shell, fs, http, or deep-link configuration.
    assert_eq!(
        conf().get("plugins").cloned().unwrap_or(json!({})),
        json!({})
    );
}

#[test]
fn exactly_one_capability() {
    assert_eq!(capability_files(), vec!["main.json".to_string()]);
}

#[test]
fn capability_is_main_window_local_only() {
    let c = capability();
    assert_eq!(c["identifier"], "main");
    assert_eq!(c["windows"], json!(["main"]));
    assert_eq!(c["local"], true);
    assert_eq!(c.get("remote"), None, "no remote URLs may use IPC");
    assert_eq!(c.get("webviews"), None);
    assert_eq!(c.get("platforms"), None);
}

#[test]
fn capability_permissions_are_exactly_our_commands() {
    let granted: Vec<String> = capability()["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().expect("plain identifiers, no scopes").to_owned())
        .collect();
    let expected: Vec<String> = tokenator_desktop::COMMANDS
        .iter()
        .map(|c| format!("allow-{}", kebab(c)))
        .collect();
    assert_eq!(granted, expected);
    for p in &granted {
        assert!(!p.contains(':'), "no plugin or core permissions: {p}");
    }
}

#[test]
fn build_manifest_lists_the_same_commands() {
    let src = std::fs::read_to_string(crate_dir().join("build.rs")).unwrap();
    let start = src.find("const COMMANDS").unwrap();
    let list = &src[start..src[start..].find("];").unwrap() + start];
    let in_build: Vec<&str> = list.split('"').skip(1).step_by(2).collect();
    assert_eq!(in_build, tokenator_desktop::COMMANDS);
}

#[test]
fn generate_handler_lists_the_same_commands() {
    let src = std::fs::read_to_string(crate_dir().join("src/lib.rs")).unwrap();
    let start = src.find("generate_handler![").unwrap();
    let list = &src[start..src[start..].find("])").unwrap() + start];
    let names: Vec<&str> = list
        .lines()
        .skip(1)
        .filter_map(|l| l.trim().trim_end_matches(',').rsplit("::").next())
        .filter(|n| !n.is_empty())
        .collect();
    assert_eq!(names, tokenator_desktop::COMMANDS);
}

#[test]
fn commands_are_unique() {
    let set: BTreeSet<_> = tokenator_desktop::COMMANDS.iter().collect();
    assert_eq!(set.len(), tokenator_desktop::COMMANDS.len());
    assert_eq!(
        tokenator_desktop::COMMANDS
            .iter()
            .filter(|c| c.starts_with("engine_"))
            .count(),
        28
    );
}
