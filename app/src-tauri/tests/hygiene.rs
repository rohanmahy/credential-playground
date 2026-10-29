//! Static checks on the shell: no logging of requests (private keys cross
//! IPC in memory only), no dependency that logs, persists, or widens the
//! webview's reach, and disk writes confined to two modules.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use common::*;

fn sources() -> Vec<(String, String)> {
    let dir = crate_dir().join("src");
    let mut out: Vec<_> = files_under(&dir)
        .into_iter()
        .filter(|f| f.ends_with(".rs"))
        .map(|f| {
            let text = std::fs::read_to_string(dir.join(&f)).unwrap();
            (f, text)
        })
        .collect();
    out.push((
        "build.rs".into(),
        std::fs::read_to_string(crate_dir().join("build.rs")).unwrap(),
    ));
    out
}

/// Source lines without `//` comments.
fn code(text: &str) -> String {
    text.lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether `token` occurs in `code` not preceded by an identifier character
/// (so `log::` does not match `FileDialog::`).
fn has_token(code: &str, token: &str) -> bool {
    code.match_indices(token).any(|(i, _)| {
        !code[..i]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

fn manifest() -> String {
    std::fs::read_to_string(crate_dir().join("Cargo.toml")).unwrap()
}

#[test]
fn no_logging_in_the_command_layer() {
    let banned = [
        "println!",
        "eprintln!",
        "print!",
        "eprint!",
        "dbg!",
        "log::",
        "tracing::",
        "info!(",
        "debug!(",
        "warn!(",
        "error!(",
        "trace!(",
        "{:?}",
        "{:#?}",
        ":?}",
    ];
    for (file, text) in sources() {
        if file == "build.rs" {
            continue; // build output, not runtime
        }
        let code = code(&text);
        for b in banned {
            assert!(!has_token(&code, b), "src/{file} contains {b}");
        }
    }
}

#[test]
fn requests_are_not_debug_formatted_into_errors() {
    // `format!("{req:?}")`-style leaks: no `?}` and no Debug of a request
    // inside messages.
    for (file, text) in sources() {
        let code = code(&text);
        assert!(
            !code.contains("?}\""),
            "src/{file}: Debug formatting in a string"
        );
    }
}

#[test]
fn no_logging_or_tracing_dependencies() {
    let m = manifest();
    for dep in [
        "log",
        "tracing",
        "tauri-plugin-log",
        "env_logger",
        "simplelog",
        "fern",
    ] {
        let line_start = format!("\n{dep} =");
        assert!(!m.contains(&line_start), "Cargo.toml depends on {dep}");
    }
    assert!(
        !m.contains("\"tracing\""),
        "tauri's tracing feature logs IPC"
    );
}

#[test]
fn no_plugins_that_widen_the_webview() {
    let m = manifest();
    for plugin in [
        "tauri-plugin-fs",
        "tauri-plugin-shell",
        "tauri-plugin-http",
        "tauri-plugin-store",
        "tauri-plugin-sql",
        "tauri-plugin-updater",
        "tauri-plugin-opener",
        "tauri-plugin-window-state",
        "tauri-plugin-persisted-scope",
        "tauri-plugin-stronghold",
    ] {
        assert!(!m.contains(plugin), "Cargo.toml has {plugin}");
    }
    assert!(m.contains("tauri-plugin-dialog"));
    assert!(m.contains("tauri-plugin-clipboard-manager"));
}

#[test]
fn reqwest_is_rustls_without_cookies() {
    let m = manifest();
    let line = m
        .lines()
        .find(|l| l.starts_with("reqwest"))
        .expect("reqwest dependency");
    assert!(line.contains("default-features = false"), "{line}");
    assert!(line.contains("\"rustls\""), "{line}");
    for banned in ["cookies", "native-tls", "default-tls", "blocking"] {
        assert!(!line.contains(banned), "{line}");
    }
}

#[test]
fn tauri_features_are_minimal() {
    let m = manifest();
    let deps = m.split("[dev-dependencies]").next().unwrap();
    let line = deps
        .lines()
        .find(|l| l.starts_with("tauri ="))
        .expect("tauri dependency");
    for banned in [
        "tracing",
        "devtools",
        "protocol-asset",
        "macos-private-api",
        "unstable",
        "test",
    ] {
        assert!(!line.contains(banned), "{line}");
    }
}

#[test]
fn disk_access_only_in_files_and_cache() {
    for (file, text) in sources() {
        if file == "files.rs" || file == "cache.rs" || file == "build.rs" {
            continue;
        }
        let code = code(&text);
        for b in ["std::fs", "fs::", "File::", "OpenOptions", "tempfile"] {
            assert!(
                !has_token(&code, b),
                "src/{file} touches the file system ({b})"
            );
        }
    }
}

#[test]
fn no_unsafe_or_env_reads() {
    for (file, text) in sources() {
        let code = code(&text);
        assert!(!code.contains("unsafe"), "src/{file}");
        assert!(
            !code.contains("std::env::var"),
            "src/{file}: configuration comes from tauri.conf.json"
        );
    }
}
