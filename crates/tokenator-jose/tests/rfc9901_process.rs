//! RFC 9901 examples: parse, issuer signature, digest matching, and the
//! Processed SD-JWT Payload (compared including member order).

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{
    assert_json_eq, assert_json_text, json, raw, rfc9901_issuer, section_disclosures, split_sd,
    token,
};
use tokenator_crypto::{Alg, CryptoError, HashAlg};
use tokenator_jose::{
    Container, Disclosure, SdAlg, SdFinding, SdReport, SlotKind, Token, VerifyError, parse,
    process, verify_signature,
};

/// Findings other than digests without disclosures (decoys / withheld).
fn problems(report: &SdReport) -> Vec<&SdFinding> {
    report
        .findings
        .iter()
        .filter(|f| !matches!(f, SdFinding::DigestWithoutDisclosure { .. }))
        .collect()
}

fn without_disclosure(report: &SdReport) -> usize {
    report
        .findings
        .iter()
        .filter(|f| matches!(f, SdFinding::DigestWithoutDisclosure { .. }))
        .count()
}

/// Parses a compact fixture, checks its structure against a plain string
/// split, verifies the issuer signature, and processes it.
fn check_compact(name: &str, processed_fixture: Option<&str>, slots: usize, matched: usize) {
    let input = token(name);
    let parsed = parse(&input).unwrap();
    assert!(
        parsed.diagnostics.is_empty(),
        "{name}: {:?}",
        parsed.diagnostics
    );
    let Token::SdJwt(sd) = &parsed.token else {
        panic!("{name}: not an SD-JWT")
    };
    let (jwt, discs, kb) = split_sd(&input);
    assert_eq!(sd.issuer.compact().unwrap(), jwt, "{name}");
    let texts: Vec<&str> = sd.disclosures.iter().map(|d| d.text()).collect();
    assert_eq!(texts, discs, "{name}");
    for d in &sd.disclosures {
        let span = d.part().span();
        assert_eq!(&input[span.start..span.end], d.text(), "{name}");
    }
    assert_eq!(
        sd.kb_jwt.as_ref().map(|k| k.compact().unwrap()),
        (!kb.is_empty()).then(|| kb.to_owned())
    );
    assert_eq!(
        sd.sd_hash_input().unwrap(),
        &input[..input.len() - kb.len()],
        "{name}"
    );

    assert_eq!(
        verify_signature(&sd.issuer, 0, &rfc9901_issuer()),
        Ok(Alg::ES256),
        "{name}"
    );

    let processed = sd.process().unwrap();
    let report = &processed.report;
    assert_eq!(report.sd_alg, SdAlg::Named(HashAlg::Sha256), "{name}");
    assert!(
        problems(report).is_empty(),
        "{name}: {:?}",
        problems(report)
    );
    assert_eq!(report.digests.len(), slots, "{name}: slots");
    assert_eq!(
        report
            .digests
            .iter()
            .filter(|s| s.disclosure.is_some())
            .count(),
        matched,
        "{name}"
    );
    assert_eq!(without_disclosure(report), slots - matched, "{name}");
    assert_eq!(report.disclosures.len(), sd.disclosures.len());
    for (i, m) in report.disclosures.iter().enumerate() {
        assert_eq!(
            m.digest.as_deref(),
            Some(sd.disclosures[i].digest(HashAlg::Sha256).as_str())
        );
        let slot = m
            .slot
            .unwrap_or_else(|| panic!("{name}: disclosure {i} unmatched"));
        assert_eq!(report.digests[slot].disclosure, Some(i), "{name}");
        assert_eq!(report.digests[slot].digest, m.digest.clone().unwrap());
    }
    if let Some(fixture) = processed_fixture {
        let expected_text = raw(fixture);
        assert_json_eq(&processed.claims, &json(&expected_text));
    }
}

#[test]
fn s5_1_issued_sd_jwt_all_disclosures() {
    check_compact("rfc9901-s5.1-sd-jwt.txt", None, 10, 10);
    let input = token("rfc9901-s5.1-sd-jwt.txt");
    let parsed = parse(&input).unwrap();
    let processed = parsed.token.sd_jwt().unwrap().process().unwrap();
    assert_json_text(
        &processed.claims,
        r#"{"iss":"https://issuer.example.com","iat":1683000000,"exp":1883000000,"sub":"user_42","nationalities":["US","DE"],"cnf":{"jwk":{"kty":"EC","crv":"P-256","x":"TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc","y":"ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"}},"updated_at":1570000000,"email":"johndoe@example.com","phone_number":"+1-202-555-0101","family_name":"Doe","phone_number_verified":true,"address":{"street_address":"123 Main St","locality":"Anytown","region":"Anystate","country":"US"},"birthdate":"1940-01-01","given_name":"John"}"#,
    );
}

#[test]
fn s5_1_slot_locations() {
    let input = token("rfc9901-s5.1-sd-jwt.txt");
    let parsed = parse(&input).unwrap();
    let report = parsed.token.sd_jwt().unwrap().process().unwrap().report;
    let where_: Vec<(SlotKind, Container, &str)> = report
        .digests
        .iter()
        .map(|s| (s.kind, s.container, s.pointer.as_str()))
        .collect();
    let mut expected: Vec<(SlotKind, Container, String)> = (0..8)
        .map(|i| (SlotKind::Object, Container::Payload, format!("/_sd/{i}")))
        .collect();
    expected.push((
        SlotKind::ArrayElement,
        Container::Payload,
        "/nationalities/0".into(),
    ));
    expected.push((
        SlotKind::ArrayElement,
        Container::Payload,
        "/nationalities/1".into(),
    ));
    let expected: Vec<(SlotKind, Container, &str)> = expected
        .iter()
        .map(|(k, c, p)| (*k, *c, p.as_str()))
        .collect();
    assert_eq!(where_, expected);
    assert_eq!(
        report.digests[0].digest,
        "CrQe7S5kqBAHt-nMYXgc6bdt2SH5aTY1sU_M-PgkjPI"
    );
    // updated_at is disclosure 7 in the SD-JWT.
    assert_eq!(report.digests[0].disclosure, Some(7));
    assert_eq!(report.digests[8].disclosure, Some(8)); // "US"
}

#[test]
fn s5_2_presentation() {
    check_compact(
        "rfc9901-s5.2-sd-jwt-kb.txt",
        Some("rfc9901-s5.2-processed-payload.json"),
        10,
        4,
    );
}

#[test]
fn a1_presentation_with_decoys() {
    check_compact(
        "rfc9901-a1-presentation.txt",
        Some("rfc9901-a1-processed-payload.json"),
        16,
        2,
    );
}

#[test]
fn a2_presentation_recursive_through_an_array_element() {
    check_compact(
        "rfc9901-a2-presentation.txt",
        Some("rfc9901-a2-processed-payload.json"),
        16,
        6,
    );
}

#[test]
fn a2_walk_order_enters_matched_disclosures() {
    let input = token("rfc9901-a2-presentation.txt");
    let parsed = parse(&input).unwrap();
    let report = parsed.token.sd_jwt().unwrap().process().unwrap().report;
    let v = "/verified_claims/verification";
    let c = "/verified_claims/claims";
    let expected: Vec<(Container, String, Option<usize>)> = vec![
        (Container::Payload, "/_sd/0".into(), None),
        (Container::Payload, "/_sd/1".into(), None),
        (Container::Payload, "/_sd/2".into(), None),
        (Container::Payload, format!("{v}/_sd/0"), None),
        (Container::Payload, format!("{v}/_sd/1"), Some(0)), // time
        (Container::Payload, format!("{v}/evidence/0"), Some(1)),
        (Container::Disclosure(1), "/1/_sd/0".into(), None),
        (Container::Disclosure(1), "/1/_sd/1".into(), None),
        (Container::Disclosure(1), "/1/_sd/2".into(), None),
        (Container::Disclosure(1), "/1/_sd/3".into(), Some(2)), // method
        (Container::Payload, format!("{c}/_sd/0"), None),
        (Container::Payload, format!("{c}/_sd/1"), Some(3)), // given_name
        (Container::Payload, format!("{c}/_sd/2"), None),
        (Container::Payload, format!("{c}/_sd/3"), Some(4)), // family_name
        (Container::Payload, format!("{c}/_sd/4"), Some(5)), // address
        (Container::Payload, format!("{c}/_sd/5"), None),
    ];
    let actual: Vec<(Container, String, Option<usize>)> = report
        .digests
        .iter()
        .map(|s| (s.container, s.pointer.clone(), s.disclosure))
        .collect();
    assert_eq!(actual, expected);
    assert_eq!(report.digests[5].kind, SlotKind::ArrayElement);
    assert_eq!(report.digests[6].kind, SlotKind::Object);
}

#[test]
fn a3_issued_and_presented() {
    check_compact("rfc9901-a3-sd-jwt.txt", None, 27, 27);
    check_compact(
        "rfc9901-a3-sd-jwt-kb.txt",
        Some("rfc9901-a3-processed-payload.json"),
        21,
        3,
    );
    let input = token("rfc9901-a3-sd-jwt.txt");
    let parsed = parse(&input).unwrap();
    let processed = parsed.token.sd_jwt().unwrap().process().unwrap();
    assert_json_text(
        &processed.claims,
        r#"{"iss":"https://pid-issuer.bund.de.example","iat":1683000000,"exp":1883000000,"vct":"urn:eudi:pid:de:1","cnf":{"jwk":{"kty":"EC","crv":"P-256","x":"TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc","y":"ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"}},"given_name":"Erika","place_of_birth":{"locality":"Berlin","country":"DE"},"age_equal_or_over":{"21":true,"18":true,"65":false,"12":true,"16":true,"14":true},"issuing_authority":"DE","expiry_date":"2030-03-12","sex":2,"family_name":"Mustermann","birth_family_name":"Gabler","birthdate":"1963-08-12","age_birth_year":1963,"address":{"street_address":"Heidestraße 17","locality":"Köln","country":"DE","postal_code":"51147"},"issuance_date":"2020-03-11","age_in_years":62,"issuing_country":"DE","nationalities":["DE"]}"#,
    );
}

#[test]
fn a4_issued_and_presented() {
    check_compact("rfc9901-a4-sd-jwt.txt", None, 14, 14);
    check_compact(
        "rfc9901-a4-sd-jwt-kb.txt",
        Some("rfc9901-a4-processed-payload.json"),
        14,
        4,
    );
}

#[test]
fn json_serializations_process_like_compact() {
    for (name, n) in [
        ("rfc9901-s8.2-sd-jwt-json-flattened.json", 4),
        ("rfc9901-s8.2-sd-jwt-kb-json-flattened.json", 2),
        ("rfc9901-s8.3-sd-jwt-kb-json-general.json", 2),
    ] {
        let input = raw(name);
        let parsed = parse(&input).unwrap();
        let sd = parsed.token.sd_jwt().unwrap();
        assert_eq!(
            verify_signature(&sd.issuer, 0, &rfc9901_issuer()),
            Ok(Alg::ES256),
            "{name}"
        );
        let processed = sd.process().unwrap();
        assert!(problems(&processed.report).is_empty(), "{name}");
        assert_eq!(processed.report.digests.len(), 4, "{name}");
        assert_eq!(
            processed
                .report
                .digests
                .iter()
                .filter(|s| s.disclosure.is_some())
                .count(),
            n,
            "{name}"
        );
        assert_eq!(
            common::str_of(&processed.claims, "/family_name"),
            "Doe",
            "{name}"
        );
        assert!(processed.claims.get("_sd").is_none());
        assert!(processed.claims.get("_sd_alg").is_none());
    }
}

#[test]
fn s8_3_second_signature_is_by_an_unpublished_key() {
    let input = raw("rfc9901-s8.3-sd-jwt-kb-json-general.json");
    let parsed = parse(&input).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    assert_eq!(
        verify_signature(&sd.issuer, 1, &rfc9901_issuer()),
        Err(VerifyError::Crypto(CryptoError::InvalidSignature))
    );
}

/// Processes one of the §6 payloads with disclosures from the RFC tables.
fn process_section(payload_file: &str, discs: &[String]) -> (String, SdReport) {
    let text = raw(payload_file);
    let payload = json(&text);
    let disclosures: Vec<Disclosure<'_>> = discs.iter().map(|d| Disclosure::new(d)).collect();
    let processed = process(&payload, &disclosures);
    (common::compact(&processed.claims), processed.report)
}

const S6_BASE: &str = r#""iss":"https://issuer.example.com","iat":1683000000,"exp":1883000000,"sub":"6c5c0a49-b589-431d-bae7-219122a9ec2c""#;

#[test]
fn s6_1_flat() {
    let (claims, report) =
        process_section("rfc9901-s6.1-payload.json", &section_disclosures("6.1"));
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_json_text(
        &json(&claims),
        &format!(
            r#"{{{S6_BASE},"address":{{"street_address":"Schulstr. 12","locality":"Schulpforta","region":"Sachsen-Anhalt","country":"DE"}}}}"#
        ),
    );
}

#[test]
fn s6_2_structured_follows_digest_order() {
    // The disclosures are listed street, locality, region, country, but the
    // processed object follows the order of the digests in `_sd`.
    let (claims, report) =
        process_section("rfc9901-s6.2-payload.json", &section_disclosures("6.2"));
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_json_text(
        &json(&claims),
        &format!(
            r#"{{{S6_BASE},"address":{{"locality":"Schulpforta","street_address":"Schulstr. 12","region":"Sachsen-Anhalt","country":"DE"}}}}"#
        ),
    );
}

#[test]
fn s6_2_country_in_plain() {
    let discs = section_disclosures("6.2");
    let (claims, report) = process_section("rfc9901-s6.2-payload-country-plain.json", &discs[..3]);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_json_text(
        &json(&claims),
        &format!(
            r#"{{{S6_BASE},"address":{{"country":"DE","locality":"Schulpforta","street_address":"Schulstr. 12","region":"Sachsen-Anhalt"}}}}"#
        ),
    );
    // Sending the country disclosure too: nothing references it.
    let (_, report) = process_section("rfc9901-s6.2-payload-country-plain.json", &discs);
    assert_eq!(
        report.findings,
        [SdFinding::UnmatchedDisclosure { disclosure: 3 }]
    );
}

#[test]
fn s6_3_recursive() {
    let discs = section_disclosures("6.3");
    assert_eq!(discs.len(), 5);
    let (claims, report) = process_section("rfc9901-s6.3-payload.json", &discs);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_json_text(
        &json(&claims),
        &format!(
            r#"{{{S6_BASE},"address":{{"locality":"Schulpforta","street_address":"Schulstr. 12","region":"Sachsen-Anhalt","country":"DE"}}}}"#
        ),
    );
    // The address disclosure (index 4) holds four slots of its own.
    assert_eq!(report.digests.len(), 5);
    assert!(
        report.digests[1..]
            .iter()
            .all(|s| s.container == Container::Disclosure(4))
    );
    assert_eq!(report.digests[1].pointer, "/2/_sd/0");

    // Only the parent: an empty address object.
    let (claims, report) = process_section("rfc9901-s6.3-payload.json", &discs[4..]);
    assert_json_text(&json(&claims), &format!(r#"{{{S6_BASE},"address":{{}}}}"#));
    assert_eq!(without_disclosure(&report), 4);

    // Only a child: it cannot connect without its parent.
    let (claims, report) = process_section("rfc9901-s6.3-payload.json", &discs[..1]);
    assert_json_text(&json(&claims), &format!("{{{S6_BASE}}}"));
    assert!(
        report
            .findings
            .contains(&SdFinding::UnmatchedDisclosure { disclosure: 0 })
    );
    assert!(
        report
            .findings
            .contains(&SdFinding::DigestWithoutDisclosure { slot: 0 })
    );
}

#[test]
fn processed_nodes_keep_their_source_spans() {
    let input = token("rfc9901-s5.2-sd-jwt-kb.txt");
    let parsed = parse(&input).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    let processed = sd.process().unwrap();
    // `iss` comes from the payload: its span is into the decoded payload.
    let iss = processed.claims.get("iss").unwrap();
    let payload = sd.issuer.payload.decoded().unwrap();
    let span = iss.span().unwrap();
    assert_eq!(
        &payload[span.start..span.end],
        b"\"https://issuer.example.com\""
    );
    // `family_name` comes from disclosure 0: its span is into that disclosure.
    let family = processed.claims.get("family_name").unwrap();
    let disc = sd.disclosures[0].part().decoded().unwrap();
    let span = family.span().unwrap();
    assert_eq!(&disc[span.start..span.end], b"\"Doe\"");
}
