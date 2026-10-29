//! The real ACL (tauri.conf.json + capabilities/ + the build.rs app
//! manifest, via `generate_context!`) on the mock runtime: the `main`
//! window with local content may call every command; other windows and
//! remote origins may call none.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use common::*;
use serde_json::{Value, json};
use tauri::test::mock_builder;
use tauri::{WebviewUrl, WebviewWindowBuilder};
use tokenator_desktop::{ClipboardState, EngineState, Fetcher, Files, RegistryCacheFile, Services};

struct NoDialog;

impl tokenator_desktop::FileDialog for NoDialog {
    fn pick_open(
        &self,
        _: &[String],
    ) -> Result<Option<std::path::PathBuf>, tokenator_desktop::PlatformError> {
        Ok(None)
    }
    fn pick_save(
        &self,
        _: &str,
    ) -> Result<Option<std::path::PathBuf>, tokenator_desktop::PlatformError> {
        Ok(None)
    }
}

/// The `main` window: created from tauri.conf.json at build, or here.
fn main_window(
    app: &tauri::App<tauri::test::MockRuntime>,
) -> tauri::WebviewWindow<tauri::test::MockRuntime> {
    use tauri::Manager;
    app.get_webview_window("main").unwrap_or_else(|| {
        WebviewWindowBuilder::new(app, "main", WebviewUrl::default())
            .build()
            .unwrap()
    })
}

struct NoClipboard;

impl tokenator_desktop::Clipboard for NoClipboard {
    fn read_text(&self) -> Result<String, tokenator_desktop::PlatformError> {
        Ok(String::new())
    }
    fn write_text(&self, _: &str, _: bool) -> Result<(), tokenator_desktop::PlatformError> {
        Ok(())
    }
}

fn real_acl_app() -> (tauri::App<tauri::test::MockRuntime>, tempfile::TempDir) {
    let app = tokenator_desktop::register(mock_builder())
        .build(tauri::generate_context!())
        .expect("app with the real context");
    let dir = tempfile::tempdir().unwrap();
    tokenator_desktop::manage(
        &app,
        EngineState::bundled().unwrap(),
        Services {
            fetcher: Fetcher::new(test_policy()).unwrap(),
            files: Files::new(Box::new(NoDialog), Files::DEFAULT_MAX_BYTES),
            clipboard: ClipboardState(Box::new(NoClipboard)),
            cache: RegistryCacheFile::in_dir(dir.path()),
        },
    );
    (app, dir)
}

fn denied(result: &Result<String, Value>) -> bool {
    matches!(result, Err(Value::String(s)) if s.contains("not allowed"))
}

#[test]
fn main_window_may_call_every_command() {
    let (app, _dir) = real_acl_app();
    let main = main_window(&app);
    for cmd in tokenator_desktop::COMMANDS {
        let r = invoke_in(&main, cmd, json!({}));
        assert!(!denied(&r), "{cmd}: {r:?}");
    }
    assert!(invoke_in(&main, "engine_info", json!({})).is_ok());
}

#[test]
fn other_windows_may_call_nothing() {
    let (app, _dir) = real_acl_app();
    let other = WebviewWindowBuilder::new(&app, "other", WebviewUrl::default())
        .build()
        .unwrap();
    for cmd in tokenator_desktop::COMMANDS {
        let r = invoke_in(&other, cmd, json!({}));
        assert!(denied(&r), "{cmd}: {r:?}");
    }
}

#[test]
fn remote_origins_may_call_nothing() {
    let (app, _dir) = real_acl_app();
    let main = main_window(&app);
    for origin in [
        "https://evil.example",
        "http://127.0.0.1",
        "https://tauri.localhost.evil.example",
    ] {
        for cmd in [
            "engine_info",
            "fetch_url",
            "registry_cache_put",
            "read_clipboard",
        ] {
            let r = invoke_from(&main, cmd, json!({}), origin);
            assert!(denied(&r), "{origin} {cmd}: {r:?}");
        }
    }
}

#[test]
fn plugin_commands_are_not_reachable() {
    // No dialog/clipboard/fs/shell/http permissions: their plugin commands
    // are denied even if the plugin were registered.
    let (app, _dir) = real_acl_app();
    let main = main_window(&app);
    for cmd in [
        "plugin:dialog|open",
        "plugin:dialog|save",
        "plugin:clipboard-manager|read_text",
        "plugin:clipboard-manager|write_text",
        "plugin:fs|read_file",
        "plugin:shell|open",
        "plugin:http|fetch",
        "plugin:app|version",
        "plugin:path|resolve_directory",
        "plugin:event|emit",
        "plugin:window|close",
        "plugin:webview|create_webview_window",
    ] {
        let r = invoke_in(&main, cmd, json!({}));
        assert!(r.is_err(), "{cmd}: {r:?}");
    }
}
