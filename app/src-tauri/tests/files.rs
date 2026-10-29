//! `open_file` / `save_file`: the native dialog picks the path (here a
//! fake), the command reads or writes exactly that file, and the webview
//! can never name a path.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use common::*;
use serde_json::{Value, json};
use tokenator_desktop::files::extension_filters;

#[test]
fn open_reads_exactly_the_picked_file() {
    let h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let picked = dir.path().join("token.jwt");
    std::fs::write(&picked, b"eyJhbGciOiJub25lIn0.e30.").unwrap();
    std::fs::write(dir.path().join("other.jwt"), b"not this one").unwrap();
    *h.dialog.open_pick.lock().unwrap() = Some(picked);
    let r = h.call("open_file", json!({ "accept": null })).unwrap();
    assert_eq!(
        r,
        json!({ "name": "token.jwt", "bytes": b64u(b"eyJhbGciOiJub25lIn0.e30.") })
    );
}

#[test]
fn open_binary_file_is_byte_exact() {
    let h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let picked = dir.path().join("cwt.cbor");
    std::fs::write(&picked, read_testdata("tokens/rfc8392-a3-signed-cwt.cbor")).unwrap();
    *h.dialog.open_pick.lock().unwrap() = Some(picked);
    let r = h.call("open_file", json!({})).unwrap();
    assert_eq!(
        from_b64u(&r["bytes"]),
        read_testdata("tokens/rfc8392-a3-signed-cwt.cbor")
    );
}

#[test]
fn open_cancelled_is_null() {
    let h = Harness::new();
    assert_eq!(
        h.call("open_file", json!({ "accept": [".pem"] })).unwrap(),
        Value::Null
    );
}

#[test]
fn open_passes_extension_filters_to_the_dialog() {
    let h = Harness::new();
    h.call(
        "open_file",
        json!({ "accept": [".jwt", "application/jwt", ".PEM", "cbor", ".jwt"] }),
    )
    .unwrap();
    h.call("open_file", json!({ "accept": null })).unwrap();
    assert_eq!(
        *h.dialog.calls.lock().unwrap(),
        vec![
            DialogCall::Open(vec!["jwt".into(), "PEM".into(), "cbor".into()]),
            DialogCall::Open(Vec::new())
        ]
    );
}

#[test]
fn extension_filters_rules() {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    assert_eq!(
        extension_filters(&s(&[".pem", ".json"])),
        s(&["pem", "json"])
    );
    assert_eq!(
        extension_filters(&s(&["application/jwt", "text/*", "*/*"])),
        s(&[])
    );
    assert_eq!(
        extension_filters(&s(&["cbor", ".cbor", " .edn "])),
        s(&["cbor", "edn"])
    );
    assert_eq!(extension_filters(&s(&["", "."])), s(&[]));
}

#[test]
fn open_over_the_cap_is_refused() {
    let h = Harness::with(test_policy(), 16);
    let dir = tempfile::tempdir().unwrap();
    let picked = dir.path().join("big.bin");
    std::fs::write(&picked, [0u8; 17]).unwrap();
    *h.dialog.open_pick.lock().unwrap() = Some(picked.clone());
    let err = h.call("open_file", json!({})).unwrap_err();
    assert_eq!(err["kind"], "invalid_argument");
    std::fs::write(&picked, [0u8; 16]).unwrap();
    assert!(h.call("open_file", json!({})).is_ok());
}

#[test]
fn open_unreadable_file_is_io() {
    let h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    *h.dialog.open_pick.lock().unwrap() = Some(dir.path().join("vanished.jwt"));
    let err = h.call("open_file", json!({})).unwrap_err();
    assert_eq!(err["kind"], "io");
    // The message names the problem, not the contents.
    assert!(err["message"].is_string());
}

#[test]
fn save_writes_exactly_the_picked_file() {
    let h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let picked = dir.path().join("key.jwk");
    *h.dialog.save_pick.lock().unwrap() = Some(picked.clone());
    let data = br#"{"kty":"OKP"}"#;
    let r = h
        .call(
            "save_file",
            json!({ "suggested_name": "issuer.jwk", "data": b64u(data) }),
        )
        .unwrap();
    assert_eq!(r, json!(true));
    assert_eq!(std::fs::read(&picked).unwrap(), data);
    assert_eq!(files_under(dir.path()), vec!["key.jwk".to_string()]);
    assert_eq!(
        *h.dialog.calls.lock().unwrap(),
        vec![DialogCall::Save("issuer.jwk".into())]
    );
}

#[test]
fn save_replaces_an_existing_file() {
    let h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let picked = dir.path().join("out.cbor");
    std::fs::write(&picked, [9u8; 100]).unwrap();
    *h.dialog.save_pick.lock().unwrap() = Some(picked.clone());
    h.call(
        "save_file",
        json!({ "suggested_name": "out.cbor", "data": b64u(&[1, 2, 3]) }),
    )
    .unwrap();
    assert_eq!(std::fs::read(&picked).unwrap(), [1, 2, 3]);
}

#[test]
fn save_cancelled_is_false_and_writes_nothing() {
    let h = Harness::new();
    let r = h
        .call(
            "save_file",
            json!({ "suggested_name": "x.txt", "data": b64u(b"secret") }),
        )
        .unwrap();
    assert_eq!(r, json!(false));
    assert_eq!(files_under(h.data_dir.path()), Vec::<String>::new());
}

#[test]
fn save_to_unwritable_path_is_io() {
    let h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    *h.dialog.save_pick.lock().unwrap() = Some(dir.path().join("no/such/dir/x.txt"));
    let err = h
        .call(
            "save_file",
            json!({ "suggested_name": "x.txt", "data": b64u(b"x") }),
        )
        .unwrap_err();
    assert_eq!(err["kind"], "io");
}

#[test]
fn the_webview_cannot_name_a_path() {
    // Extra keys are ignored: the dialog's pick is the only path used.
    let h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.txt");
    std::fs::write(&target, b"untouched").unwrap();
    let path = target.to_string_lossy().into_owned();
    // Cancelled dialog + a path argument: nothing is read or written.
    assert_eq!(
        h.call("open_file", json!({ "path": path, "accept": null }))
            .unwrap(),
        Value::Null
    );
    let r = h
        .call(
            "save_file",
            json!({ "path": path, "suggested_name": path, "data": b64u(b"pwned") }),
        )
        .unwrap();
    assert_eq!(r, json!(false));
    assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
}

#[test]
fn no_command_has_a_path_parameter() {
    // Static check on the command signatures in src/.
    for file in [
        "engine.rs",
        "fetch.rs",
        "files.rs",
        "clipboard.rs",
        "cache.rs",
    ] {
        let src = std::fs::read_to_string(crate_dir().join("src").join(file)).unwrap();
        for sig in command_signatures(&src) {
            for banned in ["Path", "PathBuf", "path:", "dir:", "file:"] {
                assert!(
                    !sig.contains(banned),
                    "{file}: command signature takes a path: {sig}"
                );
            }
        }
    }
}

/// The text from each `#[tauri::command...]` to the opening `{` of the fn.
fn command_signatures(src: &str) -> Vec<String> {
    src.match_indices("#[tauri::command")
        .map(|(i, _)| {
            let rest = &src[i..];
            let body = rest.find('{').unwrap_or(rest.len());
            rest[..body].to_string()
        })
        .collect()
}
