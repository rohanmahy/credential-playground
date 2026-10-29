//! Defaulted request fields are optional in TypeScript (#34): `field?: T`
//! for serde-defaulted fields (serde rejects an explicit `null` there),
//! `field?: T | null` for `Option` fields.
#![cfg(feature = "ts")]
#![allow(clippy::unwrap_used, clippy::panic)]

use tokenator_core::ts::bindings;

fn decl(name: &str) -> String {
    bindings()
        .into_iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("no binding for {name}"))
        .1
}

#[test]
fn defaulted_fields_are_optional() {
    let v = decl("ValidateRequest");
    assert!(v.contains("skew?: number,"), "{v}");
    assert!(v.contains("keys?: Array<KeyRef>,"), "{v}");
    assert!(v.contains("expected_aud?: string | null"), "{v}");
    assert!(v.contains("now: number"), "required stays required: {v}");
    assert!(v.contains("doc: DocRef"), "{v}");
    let k = decl("KeyRef");
    assert!(
        k.contains("index?: number,") && k.contains("label?: string | null"),
        "{k}"
    );
    assert!(k.contains("bytes: Bytes"), "{k}");
    let view = decl("ViewOptions");
    assert!(
        view.contains("layout?: Layout,") && view.contains("now?: number | null"),
        "{view}"
    );
    let issue = decl("IssueRequest");
    assert!(
        issue.contains("view?: ViewOptions,") && issue.contains("randomness?: Bytes | null"),
        "{issue}"
    );
    assert!(issue.contains("issuer: KeyRef"), "{issue}");
    let sd = decl("SdOptions");
    assert!(sd.contains("force_sd?: boolean"), "{sd}");
}

#[test]
fn serde_accepts_what_typescript_allows() {
    // Omitted defaulted fields and explicit nulls for Option fields.
    let req: tokenator_core::ValidateRequest = serde_json::from_str(
        r#"{"doc": {"kind": {"type": "cwt"}, "bytes": ""}, "now": 1, "expected_aud": null}"#,
    )
    .unwrap();
    assert_eq!(req.skew, 60);
    let k: tokenator_core::KeyRef =
        serde_json::from_str(r#"{"bytes": "", "format": null, "role": null}"#).unwrap();
    assert_eq!(k.index, 0);
}
