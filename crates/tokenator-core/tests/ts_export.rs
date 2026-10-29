//! TypeScript declarations (feature `ts`).
#![cfg(feature = "ts")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::HashSet;

use tokenator_core::ts::bindings;

fn decl(name: &str) -> String {
    bindings()
        .into_iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("no binding for {name}"))
        .1
}

#[test]
fn every_dto_has_one_declaration() {
    let all = bindings();
    let names: HashSet<_> = all.iter().map(|(n, _)| n.clone()).collect();
    assert_eq!(names.len(), all.len(), "duplicate names");
    for name in [
        "Document",
        "Node",
        "NodeId",
        "Bytes",
        "Kind",
        "Layer",
        "Candidate",
        "ValidationReport",
        "CheckItem",
        "KeyRef",
        "KeyInfo",
        "IssueRequest",
        "PresentRequest",
        "ValidateRequest",
        "TamperOp",
        "ReencodeRequest",
        "DisclosureOp",
        "DateTimeForms",
        "RegistryEntry",
        "EngineError",
        "ViewOptions",
        "EditResult",
        "ManualDecode",
    ] {
        assert!(names.contains(name), "{name}");
    }
    for (name, d) in &all {
        assert!(d.starts_with("export "), "{name}: {d}");
        assert!(d.contains(name.as_str()), "{name}: {d}");
    }
}

#[test]
fn wire_conventions_show_in_the_types() {
    assert!(decl("Bytes").contains("string"), "{}", decl("Bytes"));
    assert!(decl("NodeId").contains("string"), "{}", decl("NodeId"));
    let kind = decl("Kind");
    assert!(kind.contains("\"type\": \"sd_jwt\""), "{kind}");
    let status = decl("Status");
    assert!(
        status.contains("\"pass\"") && status.contains("\"info\""),
        "{status}"
    );
    // i64 times are plain numbers, not bigint.
    let hint = decl("TimeHint");
    assert!(hint.contains("epoch: number"), "{hint}");
    assert!(!hint.contains("bigint"), "{hint}");
    let node = decl("Node");
    for field in ["id", "kind", "main", "raw", "children", "key"] {
        assert!(node.contains(&format!("{field}:")), "{field}: {node}");
    }
    assert!(decl("JsonPathSegment").contains("string | number"));
}

#[test]
fn bindings_are_stable() {
    assert_eq!(bindings(), bindings());
}
