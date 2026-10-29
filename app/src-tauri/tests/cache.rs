//! The registry cache is one file in the app data dir, and it is the only
//! thing the app writes there (SPEC §1, §7).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use common::*;
use serde_json::{Value, json};
use tokenator_core::{Engine, RegistryId, RegistryMergeRequest};
use tokenator_desktop::RegistryCacheFile;

#[test]
fn location_is_registry_snapshot_bin_in_the_dir() {
    let dir = tempfile::tempdir().unwrap();
    let cache = RegistryCacheFile::in_dir(dir.path());
    assert_eq!(RegistryCacheFile::FILE_NAME, "registry-snapshot.bin");
    assert_eq!(cache.path(), dir.path().join("registry-snapshot.bin"));
}

#[test]
fn empty_get_is_none_and_nothing_is_created() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let cache = RegistryCacheFile::in_dir(&data);
    assert_eq!(cache.get().unwrap(), None);
    cache.clear().unwrap();
    assert!(!data.exists(), "get/clear must not create the dir");
}

#[test]
fn put_get_round_trip_creating_the_dir() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("io.github.rohanmahy.tokenator");
    let cache = RegistryCacheFile::in_dir(&data);
    cache.put(b"snapshot-1").unwrap();
    assert_eq!(cache.get().unwrap().as_deref(), Some(&b"snapshot-1"[..]));
    cache.put(b"snapshot-2, longer").unwrap();
    assert_eq!(
        cache.get().unwrap().as_deref(),
        Some(&b"snapshot-2, longer"[..])
    );
    // Atomic replace leaves no temp file behind.
    assert_eq!(
        files_under(&data),
        vec!["registry-snapshot.bin".to_string()]
    );
}

#[test]
fn clear_removes_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let cache = RegistryCacheFile::in_dir(dir.path());
    cache.put(b"x").unwrap();
    cache.clear().unwrap();
    assert_eq!(cache.get().unwrap(), None);
    assert_eq!(files_under(dir.path()), Vec::<String>::new());
}

#[test]
fn commands_round_trip_base64url() {
    let h = Harness::new();
    let snapshot = Engine::new()
        .unwrap()
        .registry_merge(&RegistryMergeRequest {
            base_snapshot: None,
            xml: tokenator_core::Bytes(read_testdata("iana/cwt.xml")),
            which: RegistryId::Cwt,
        })
        .unwrap()
        .snapshot
        .0;
    assert_eq!(
        h.call("registry_cache_get", json!({})).unwrap(),
        Value::Null
    );
    assert_eq!(
        h.call("registry_cache_put", json!({ "snapshot": b64u(&snapshot) }))
            .unwrap(),
        Value::Null
    );
    assert_eq!(
        h.call("registry_cache_get", json!({})).unwrap(),
        b64u(&snapshot)
    );
    assert_eq!(
        std::fs::read(h.data_dir.path().join("registry-snapshot.bin")).unwrap(),
        snapshot,
        "the file holds the raw snapshot bytes"
    );
    h.call("registry_cache_clear", json!({})).unwrap();
    assert_eq!(
        h.call("registry_cache_get", json!({})).unwrap(),
        Value::Null
    );
}

#[test]
fn put_failure_is_io() {
    let dir = tempfile::tempdir().unwrap();
    // A file where the data dir should be.
    let blocker = dir.path().join("data");
    std::fs::write(&blocker, b"").unwrap();
    let err = RegistryCacheFile::in_dir(&blocker).put(b"x").unwrap_err();
    assert_eq!(err.kind, tokenator_desktop::PlatformErrorKind::Io);
}

#[test]
fn a_full_session_writes_only_the_cache() {
    // Every command except fetch, with private keys and documents flowing
    // through; afterwards the data dir holds only the cache file, and the
    // picked save location only the saved file.
    let (h, fx) = (Harness::new(), Fx::new());
    let saves = tempfile::tempdir().unwrap();
    let key = serde_json::to_value(&fx.issuer.key).unwrap();
    for (cmd, args) in [
        ("engine_info", json!({})),
        ("engine_detect", json!({ "input": b64u(&fx.jwt) })),
        (
            "engine_key_generate",
            json!({ "req": { "spec": { "type": "ed25519" }, "seed": { "type": "well_known" } } }),
        ),
        (
            "engine_key_export",
            json!({ "req": { "key": key, "format": { "type": "jwk" }, "visibility": "private" } }),
        ),
        (
            "engine_issue",
            json!({ "req": serde_json::to_value(Fx::issue_request(&fx.issuer, &fx.holder, &fx.engine)).unwrap() }),
        ),
        (
            "write_clipboard",
            json!({ "text": "private key", "sensitive": true }),
        ),
        ("read_clipboard", json!({})),
        ("registry_cache_put", json!({ "snapshot": b64u(b"snap") })),
        ("registry_cache_get", json!({})),
    ] {
        h.invoke(cmd, args).unwrap_or_else(|e| panic!("{cmd}: {e}"));
    }
    *h.dialog.save_pick.lock().unwrap() = Some(saves.path().join("export.jwk"));
    h.invoke(
        "save_file",
        json!({ "suggested_name": "export.jwk", "data": b64u(b"{}") }),
    )
    .unwrap();
    h.invoke("open_file", json!({})).unwrap();

    assert_eq!(
        files_under(h.data_dir.path()),
        vec!["registry-snapshot.bin".to_string()]
    );
    assert_eq!(files_under(saves.path()), vec!["export.jwk".to_string()]);
}
