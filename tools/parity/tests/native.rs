//! The native half of the parity suite (SPEC §11): the committed corpus is
//! what the builder makes from the fixtures, and the native engine
//! reproduces every committed golden. The wasm half is
//! `app/src/test/wasm/parity.test.ts`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::BTreeSet;

use parity::{
    Golden, METHODS, case_text, corpus, parity_dir, read_cases, read_expected, testdata,
    with_big_stack,
};
use tokenator_core::Engine;

#[test]
fn the_committed_corpus_is_what_the_builder_makes() {
    let built = with_big_stack(|| corpus::build(&Engine::new().unwrap(), &testdata()))
        .unwrap()
        .unwrap();
    let committed = read_cases(&parity_dir()).unwrap();
    let built_ids: BTreeSet<_> = built.iter().map(|(id, _)| id.clone()).collect();
    let committed_ids: BTreeSet<_> = committed.keys().cloned().collect();
    assert_eq!(
        built_ids, committed_ids,
        "case ids differ: run `pnpm parity:regen` in app/"
    );
    for (id, case) in &built {
        assert_eq!(
            case_text(case).unwrap(),
            case_text(&committed[id]).unwrap(),
            "{id}: stale request; run `pnpm parity:regen` in app/"
        );
    }
}

#[test]
fn the_native_engine_reproduces_every_golden() {
    let failures = with_big_stack(|| {
        let e = Engine::new().unwrap();
        let cases = read_cases(&parity_dir()).unwrap();
        let expected = read_expected(&parity_dir()).unwrap();
        assert_eq!(
            cases.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>(),
            "every case has exactly one golden"
        );
        let mut failures = Vec::new();
        for (id, case) in &cases {
            let out = case.run(&e).unwrap_or_else(|err| panic!("{id}: {err}"));
            if Golden::of(&out) != expected[id] {
                failures.push(id.clone());
            }
        }
        failures
    })
    .unwrap();
    assert!(failures.is_empty(), "native output differs: {failures:?}");
}

#[test]
fn every_engine_method_is_covered() {
    let cases = read_cases(&parity_dir()).unwrap();
    let expected = read_expected(&parity_dir()).unwrap();
    for m in METHODS {
        let ok = cases.iter().any(|(id, c)| {
            c.method == m && matches!(&expected[id], Golden::Text(t) if t.starts_with(r#"{"ok":"#))
                || c.method == m && matches!(&expected[id], Golden::Digest { .. })
        });
        assert!(ok, "no successful case for {m}");
    }
    for (id, c) in &cases {
        assert!(
            METHODS.contains(&c.method.as_str()),
            "{id}: unknown method {}",
            c.method
        );
        assert!(
            id.starts_with(&format!("{}--", c.method)),
            "{id}: id must start with the method"
        );
    }
    // Error envelopes are covered too.
    let errors = expected
        .values()
        .filter(|g| matches!(g, Golden::Text(t) if t.starts_with(r#"{"err":"#)))
        .count();
    assert!(errors >= 20, "only {errors} error cases");
}

#[test]
fn every_fixture_is_detected_and_every_token_opened() {
    let cases = read_cases(&parity_dir()).unwrap();
    let expected = read_expected(&parity_dir()).unwrap();
    for entry in std::fs::read_dir(testdata().join("tokens")).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if name == "README.md" {
            continue;
        }
        let detect = format!("detect--tokens--{name}");
        assert!(cases.contains_key(&detect), "{name} not detected");
        // Opened unless nothing was detected (COSE_Mac0, COSE_Encrypt0).
        let none = expected[&detect] == Golden::Text(r#"{"ok":[]}"#.into());
        assert!(
            none || cases.contains_key(&format!("open--{name}")),
            "{name} not opened"
        );
    }
    let imports = cases.values().filter(|c| c.method == "key_import").count();
    assert!(imports >= 60, "only {imports} key imports");
}

#[test]
fn the_stack_audit_covers_issue_27() {
    let cases = read_cases(&parity_dir()).unwrap();
    let expected = read_expected(&parity_dir()).unwrap();
    // Each must run in the release wasm build and succeed natively.
    for id in [
        "render--stack--cbor-maps-max-depth",
        "render--stack--cbor-arrays-max-depth",
        "lint--stack--cbor-maps-max-depth",
        "detect--stack--edn-max-depth",
        "render--stack--edn-max-depth",
        "parse_edit--stack--edn-max-depth",
        "issue--stack--deep-cwt",
        "validate--stack--deep-cwt",
        "issue--stack--sd-jwt-chain",
        "validate--stack--sd-jwt-chain",
        "disclose--stack--sd-jwt-chain",
        "key_generate--stack--ml-dsa-87",
        "issue--stack--ml-dsa-87-jose",
        "issue--stack--ml-dsa-87-cose",
        "validate--stack--ml-dsa-87-jose",
        "validate--stack--ml-dsa-87-cose",
    ] {
        let case = cases.get(id).unwrap_or_else(|| panic!("missing {id}"));
        assert!(case.stack, "{id} is not tagged stack");
        if let Golden::Text(t) = &expected[id] {
            assert!(t.starts_with(r#"{"ok":"#), "{id} fails natively: {t:.200}");
        }
    }
    // Validation of the deep and ML-DSA-87 tokens verifies the signature.
    for id in [
        "validate--stack--deep-cwt",
        "validate--stack--sd-jwt-chain",
        "validate--stack--ml-dsa-87-jose",
        "validate--stack--ml-dsa-87-cose",
    ] {
        let Golden::Text(t) = &expected[id] else {
            panic!("{id} is a digest")
        };
        let v: serde_json::Value = serde_json::from_str(t).unwrap();
        assert_eq!(v["ok"]["items"][0]["id"], "signature", "{id}");
        assert_eq!(v["ok"]["items"][0]["status"], "pass", "{id}");
    }
    // One level past MAX_DEPTH is an error, not a trap.
    let Golden::Text(t) = &expected["render--stack--cbor-maps-over-max-depth"] else {
        panic!("digest")
    };
    assert!(t.starts_with(r#"{"err":{"code":"parse""#), "{t}");
}
