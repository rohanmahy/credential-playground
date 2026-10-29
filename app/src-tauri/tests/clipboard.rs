//! `read_clipboard` / `write_clipboard` through the `Clipboard` backend.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use common::*;
use serde_json::{Value, json};

#[test]
fn read_returns_the_clipboard_text() {
    let h = Harness::new();
    *h.clipboard.text.lock().unwrap() = "Bearer eyJ…".into();
    assert_eq!(
        h.call("read_clipboard", json!({})).unwrap(),
        json!("Bearer eyJ…")
    );
}

#[test]
fn write_sets_the_text_and_passes_sensitive() {
    let h = Harness::new();
    assert_eq!(
        h.call(
            "write_clipboard",
            json!({ "text": "public", "sensitive": false })
        )
        .unwrap(),
        Value::Null
    );
    h.call(
        "write_clipboard",
        json!({ "text": "{\"d\":\"…\"}", "sensitive": true }),
    )
    .unwrap();
    assert_eq!(
        *h.clipboard.writes.lock().unwrap(),
        vec![
            ("public".to_string(), false),
            ("{\"d\":\"…\"}".to_string(), true)
        ]
    );
    assert_eq!(
        h.call("read_clipboard", json!({})).unwrap(),
        json!("{\"d\":\"…\"}")
    );
}

#[test]
fn write_requires_sensitive() {
    // The flag is explicit on the wire, so a private-key copy cannot lose it.
    let h = Harness::new();
    assert!(h.call("write_clipboard", json!({ "text": "x" })).is_err());
    assert!(h.clipboard.writes.lock().unwrap().is_empty());
}
