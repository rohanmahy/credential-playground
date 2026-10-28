//! Every SD report category, on hand-made payloads (RFC 9901 §7.1).

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{assert_json_text, b64e, digest_b64, json, sha256_b64};
use tokenator_crypto::HashAlg;
use tokenator_jose::{
    Container, Disclosure, DisclosureError, Processed, SdAlg, SdFinding, SlotKind, process,
};

/// A disclosure's base64url text from its JSON.
fn disc(j: &str) -> String {
    b64e(j.as_bytes())
}

/// Runs `process` on payload JSON (with `{D0}`, `{D1}`, ... replaced by the
/// SHA-256 digests of the given disclosures) and returns the compact
/// processed claims plus the report.
fn run(payload_template: &str, discs: &[&str]) -> (String, tokenator_jose::SdReport) {
    let texts: Vec<String> = discs.iter().map(|d| disc(d)).collect();
    let mut payload_text = payload_template.to_owned();
    for (i, t) in texts.iter().enumerate() {
        payload_text = payload_text.replace(&format!("{{D{i}}}"), &sha256_b64(t));
    }
    let payload = json(&payload_text);
    let disclosures: Vec<Disclosure<'_>> = texts.iter().map(|t| Disclosure::new(t)).collect();
    let Processed { claims, report } = process(&payload, &disclosures);
    (common::compact(&claims), report)
}

#[test]
fn clean_object_and_array() {
    let (claims, report) = run(
        r#"{"_sd":["{D0}"],"a":1,"arr":["x",{"...":"{D1}"},"z"]}"#,
        &[r#"["s0","name","v"]"#, r#"["s1","y"]"#],
    );
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_json_text(&json(&claims), r#"{"a":1,"arr":["x","y","z"],"name":"v"}"#);
    assert_eq!(report.sd_alg, SdAlg::Default);
    assert_eq!(report.digests.len(), 2);
    assert_eq!(report.digests[0].kind, SlotKind::Object);
    assert_eq!(report.digests[0].pointer, "/_sd/0");
    assert_eq!(report.digests[1].kind, SlotKind::ArrayElement);
    assert_eq!(report.digests[1].pointer, "/arr/1");
    assert_eq!(report.disclosures[0].slot, Some(0));
    assert_eq!(report.disclosures[1].slot, Some(1));
}

#[test]
fn unmatched_disclosure() {
    let (claims, report) = run(r#"{"a":1}"#, &[r#"["s","b",2]"#]);
    assert_eq!(
        report.findings,
        [SdFinding::UnmatchedDisclosure { disclosure: 0 }]
    );
    assert_eq!(report.disclosures[0].slot, None);
    assert_eq!(
        report.disclosures[0].digest.as_deref(),
        Some(sha256_b64(&disc(r#"["s","b",2]"#)).as_str())
    );
    assert_json_text(&json(&claims), r#"{"a":1}"#);
}

#[test]
fn digests_without_disclosures_are_removed() {
    let decoy = sha256_b64("decoy");
    let (claims, report) = run(
        &format!(r#"{{"_sd":["{decoy}"],"arr":["a",{{"...":"{decoy}x"}},"b"]}}"#),
        &[],
    );
    assert_eq!(
        report.findings,
        [
            SdFinding::DigestWithoutDisclosure { slot: 0 },
            SdFinding::DigestWithoutDisclosure { slot: 1 }
        ]
    );
    assert_json_text(&json(&claims), r#"{"arr":["a","b"]}"#);
}

#[test]
fn duplicate_digest_fills_only_the_first_slot() {
    let (claims, report) = run(
        r#"{"_sd":["{D0}","{D0}"],"arr":[{"...":"{D0}"}]}"#,
        &[r#"["s","n",1]"#],
    );
    let digest = sha256_b64(&disc(r#"["s","n",1]"#));
    assert_eq!(
        report.findings,
        [SdFinding::DuplicateDigest {
            digest,
            slots: vec![0, 1, 2]
        }]
    );
    assert_eq!(report.digests[0].disclosure, Some(0));
    assert_eq!(report.digests[1].disclosure, None);
    assert_eq!(report.digests[2].disclosure, None);
    assert_json_text(&json(&claims), r#"{"arr":[],"n":1}"#);
}

#[test]
fn duplicate_disclosure_uses_the_first() {
    let d = r#"["s","n",1]"#;
    let (claims, report) = run(r#"{"_sd":["{D0}"]}"#, &[d, d]);
    assert_eq!(
        report.findings,
        [SdFinding::DuplicateDisclosure {
            disclosures: vec![0, 1]
        }]
    );
    assert_eq!(report.disclosures[0].slot, Some(0));
    assert_eq!(report.disclosures[1].slot, None);
    assert_json_text(&json(&claims), r#"{"n":1}"#);
}

#[test]
fn forbidden_names() {
    for name in ["_sd", "..."] {
        let d = format!(r#"["s","{name}",1]"#);
        let (claims, report) = run(r#"{"_sd":["{D0}"],"a":1}"#, &[&d]);
        assert_eq!(
            report.findings,
            [SdFinding::ForbiddenName {
                disclosure: 0,
                name: name.into()
            }],
            "{name}"
        );
        assert_eq!(
            report.digests[0].disclosure,
            Some(0),
            "matched, but not inserted"
        );
        assert_json_text(&json(&claims), r#"{"a":1}"#);
    }
}

#[test]
fn kind_mismatch_both_ways() {
    let (claims, report) = run(
        r#"{"_sd":["{D0}"],"arr":[{"...":"{D1}"}]}"#,
        &[r#"["s","v"]"#, r#"["t","n",1]"#],
    );
    assert_eq!(
        report.findings,
        [
            SdFinding::KindMismatch {
                disclosure: 0,
                slot: 0
            },
            SdFinding::KindMismatch {
                disclosure: 1,
                slot: 1
            }
        ]
    );
    assert_json_text(&json(&claims), r#"{"arr":[]}"#);
}

#[test]
fn name_collision_keeps_the_plain_claim() {
    let (claims, report) = run(
        r#"{"a":"plain","_sd":["{D0}"]}"#,
        &[r#"["s","a","hidden"]"#],
    );
    assert_eq!(
        report.findings,
        [SdFinding::NameCollision {
            disclosure: 0,
            name: "a".into()
        }]
    );
    assert_json_text(&json(&claims), r#"{"a":"plain"}"#);
}

#[test]
fn name_collision_between_two_disclosures() {
    let (claims, report) = run(
        r#"{"_sd":["{D0}","{D1}"]}"#,
        &[r#"["s","a",1]"#, r#"["t","a",2]"#],
    );
    assert_eq!(
        report.findings,
        [SdFinding::NameCollision {
            disclosure: 1,
            name: "a".into()
        }]
    );
    assert_json_text(&json(&claims), r#"{"a":1}"#);
}

#[test]
fn malformed_disclosure_that_fills_a_slot() {
    let (claims, report) = run(r#"{"_sd":["{D0}"]}"#, &[r#"{"not":"array"}"#]);
    assert_eq!(
        report.findings,
        [SdFinding::MalformedDisclosure {
            disclosure: 0,
            error: DisclosureError::NotAnArray
        }]
    );
    assert_eq!(report.digests[0].disclosure, Some(0));
    assert_json_text(&json(&claims), "{}");
}

#[test]
fn malformed_disclosure_that_matches_nothing() {
    let payload = json("{}");
    let d = Disclosure::new("!!");
    let processed = process(&payload, std::slice::from_ref(&d));
    let f = &processed.report.findings;
    assert!(f.iter().any(|x| matches!(
        x,
        SdFinding::MalformedDisclosure {
            disclosure: 0,
            error: DisclosureError::Base64(_)
        }
    )));
    assert!(f.contains(&SdFinding::UnmatchedDisclosure { disclosure: 0 }));
}

#[test]
fn sd_not_an_array_and_non_string_entries() {
    let (claims, report) = run(
        r#"{"o":{"_sd":"x"},"_sd":[1,"{D0}"]}"#,
        &[r#"["s","n",true]"#],
    );
    assert_eq!(
        report.findings,
        [
            SdFinding::SdNotArray {
                container: Container::Payload,
                pointer: "/o/_sd".into()
            },
            SdFinding::SdEntryNotString {
                container: Container::Payload,
                pointer: "/_sd/0".into()
            },
        ]
    );
    assert_eq!(report.digests.len(), 1);
    assert_eq!(report.digests[0].pointer, "/_sd/1");
    assert_json_text(&json(&claims), r#"{"o":{},"n":true}"#);
}

#[test]
fn malformed_array_digests_stay_ordinary_elements() {
    let (claims, report) = run(
        r#"{"arr":[{"...":"{D0}","x":1},{"...":5}]}"#,
        &[r#"["s","v"]"#],
    );
    assert_eq!(
        report.findings,
        [
            SdFinding::MalformedArrayDigest {
                container: Container::Payload,
                pointer: "/arr/0".into()
            },
            SdFinding::MalformedArrayDigest {
                container: Container::Payload,
                pointer: "/arr/1".into()
            },
            SdFinding::UnmatchedDisclosure { disclosure: 0 },
        ]
    );
    assert!(report.digests.is_empty());
    let digest = sha256_b64(&disc(r#"["s","v"]"#));
    assert_json_text(
        &json(&claims),
        &format!(r#"{{"arr":[{{"...":"{digest}","x":1}},{{"...":5}}]}}"#),
    );
}

#[test]
fn nested_sd_alg_is_reported_and_kept() {
    let (claims, report) = run(
        r#"{"_sd_alg":"sha-256","o":{"_sd_alg":"sha-256"},"_sd":["{D0}"]}"#,
        &[r#"["s","p",{"_sd_alg":"sha-512"}]"#],
    );
    assert_eq!(
        report.findings,
        [
            SdFinding::NestedSdAlg {
                container: Container::Payload,
                pointer: "/o/_sd_alg".into()
            },
            SdFinding::NestedSdAlg {
                container: Container::Disclosure(0),
                pointer: "/2/_sd_alg".into()
            },
        ]
    );
    assert_eq!(report.sd_alg, SdAlg::Named(HashAlg::Sha256));
    assert_json_text(
        &json(&claims),
        r#"{"o":{"_sd_alg":"sha-256"},"p":{"_sd_alg":"sha-512"}}"#,
    );
}

#[test]
fn unsupported_sd_alg_skips_matching() {
    for (alg_json, sd_alg) in [
        (r#""SHA-256""#, SdAlg::Unsupported("SHA-256".into())),
        (r#""md5""#, SdAlg::Unsupported("md5".into())),
        ("256", SdAlg::NotAString),
    ] {
        let (claims, report) = run(
            &format!(r#"{{"_sd_alg":{alg_json},"_sd":["{{D0}}"],"a":1}}"#),
            &[r#"["s","n",1]"#],
        );
        assert_eq!(report.sd_alg, sd_alg);
        assert_eq!(report.findings, [SdFinding::UnsupportedSdAlg], "{alg_json}");
        assert_eq!(report.digests.len(), 1);
        assert_eq!(report.digests[0].disclosure, None);
        assert_eq!(report.disclosures[0].digest, None);
        assert_eq!(report.disclosures[0].slot, None);
        assert_json_text(&json(&claims), r#"{"a":1}"#);
    }
}

#[test]
fn sha384_and_sha512_payloads() {
    for h in [HashAlg::Sha384, HashAlg::Sha512] {
        let d = disc(r#"["s","n",1]"#);
        let payload_text = format!(
            r#"{{"_sd_alg":"{}","_sd":["{}"]}}"#,
            h.name(),
            digest_b64(h, &d)
        );
        let payload = json(&payload_text);
        let ds = [Disclosure::new(&d)];
        let processed = process(&payload, &ds);
        assert!(processed.report.findings.is_empty(), "{h:?}");
        assert_eq!(processed.report.sd_alg, SdAlg::Named(h));
        assert_json_text(&processed.claims, r#"{"n":1}"#);
        // The same disclosure under a SHA-256 payload does not match.
        let wrong_text = format!(r#"{{"_sd":["{}"]}}"#, digest_b64(h, &d));
        let wrong = json(&wrong_text);
        let processed = process(&wrong, &ds);
        assert!(
            processed
                .report
                .findings
                .contains(&SdFinding::UnmatchedDisclosure { disclosure: 0 })
        );
    }
}

#[test]
fn empty_sd_array_is_removed_silently() {
    let (claims, report) = run(r#"{"_sd":[],"o":{"_sd":[]}}"#, &[]);
    assert!(report.findings.is_empty());
    assert_json_text(&json(&claims), r#"{"o":{}}"#);
}

#[test]
fn recursive_array_disclosure_with_object_value() {
    // An array element whose value is an object with its own `_sd`.
    let inner = r#"["s1","k","v"]"#;
    let inner_digest = sha256_b64(&disc(inner));
    let outer = format!(r#"["s0",{{"_sd":["{inner_digest}"],"plain":0}}]"#);
    let (claims, report) = run(r#"{"arr":[{"...":"{D0}"}]}"#, &[&outer, inner]);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_json_text(&json(&claims), r#"{"arr":[{"plain":0,"k":"v"}]}"#);
    assert_eq!(report.digests[1].container, Container::Disclosure(0));
    assert_eq!(report.digests[1].pointer, "/1/_sd/0");
}

#[test]
fn three_levels_of_recursion() {
    let c = r#"["s2","c",3]"#;
    let b = format!(r#"["s1","b",{{"_sd":["{}"]}}]"#, sha256_b64(&disc(c)));
    let a = format!(r#"["s0","a",{{"_sd":["{}"]}}]"#, sha256_b64(&disc(&b)));
    // Presented in reverse order: order of disclosures does not matter.
    let (claims, report) = run(r#"{"_sd":["{D2}"]}"#, &[c, &b, &a]);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_json_text(&json(&claims), r#"{"a":{"b":{"c":3}}}"#);
    let containers: Vec<Container> = report.digests.iter().map(|s| s.container).collect();
    assert_eq!(
        containers,
        [
            Container::Payload,
            Container::Disclosure(2),
            Container::Disclosure(1)
        ]
    );
}

#[test]
fn processed_order_follows_digest_order_not_disclosure_order() {
    let a = r#"["s0","alpha",1]"#;
    let b = r#"["s1","beta",2]"#;
    let (claims, _) = run(r#"{"_sd":["{D1}","{D0}"],"plain":0}"#, &[a, b]);
    assert_json_text(&json(&claims), r#"{"plain":0,"beta":2,"alpha":1}"#);
}

#[test]
fn findings_do_not_abort_processing() {
    // One bad apple among good ones.
    let (claims, report) = run(
        r#"{"_sd":["{D0}","{D1}","{D2}"],"x":0}"#,
        &[
            r#"["s0","good",1]"#,
            r#"["s1","_sd",2]"#,
            r#"["s2","also_good",3]"#,
        ],
    );
    assert_eq!(
        report.findings,
        [SdFinding::ForbiddenName {
            disclosure: 1,
            name: "_sd".into()
        }]
    );
    assert_json_text(&json(&claims), r#"{"x":0,"good":1,"also_good":3}"#);
}
