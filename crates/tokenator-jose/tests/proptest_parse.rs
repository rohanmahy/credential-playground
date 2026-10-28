//! Parsers and processors never panic, on random text and on mutations of
//! valid tokens. Spans always stay inside the input.

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use proptest::prelude::*;
use tokenator_jose::{Disclosure, Parsed, Tamper, parse, tamper};

fn fixtures() -> Vec<String> {
    [
        "rfc7515-a1-jws-hs256.txt",
        "rfc7515-a3-jws-es256.txt",
        "rfc7515-a6-jws-json-general.json",
        "rfc7515-a7-jws-json-flattened.json",
        "rfc9901-s5.2-sd-jwt-kb.txt",
        "rfc9901-a2-presentation.txt",
        "rfc9901-s8.2-sd-jwt-kb-json-flattened.json",
        "rfc9901-s8.3-sd-jwt-kb-json-general.json",
    ]
    .iter()
    .map(|n| common::raw(n))
    .collect()
}

/// Touches everything a UI would: parts, trees, processing, KB checks.
fn exercise(input: &str, parsed: &Parsed<'_>) {
    let in_range = |s: tokenator_jose::Span| assert!(s.start <= s.end && s.end <= input.len());
    for d in &parsed.diagnostics {
        if let Some(s) = d.span {
            in_range(s);
        }
    }
    let jws = parsed.token.jws();
    in_range(jws.span);
    in_range(jws.payload.span());
    let _ = jws.claims();
    for (i, s) in jws.signatures.iter().enumerate() {
        in_range(s.signature.span());
        let _ = jws.header(i);
        let _ = jws.signing_input(i);
    }
    let _ = jws.compact();
    if let Some(sd) = parsed.token.sd_jwt() {
        for d in &sd.disclosures {
            in_range(d.part().span());
            let _ = d.view();
        }
        let _ = sd.sd_hash_input();
        let _ = sd.process();
        let exp = tokenator_jose::KbExpectations {
            aud: Some("a"),
            nonce: None,
            now: 0,
            skew: 60,
            max_age: Some(1),
        };
        let _ = tokenator_jose::check_kb_jwt(sd, &[], &exp);
        let _ = tokenator_jose::select(sd, &[0, 1]);
    }
    let _ = tokenator_jose::to_compact(&parsed.token, 0);
    let _ = tokenator_jose::to_json(&parsed.token, tokenator_jose::JsonSerialization::General);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn random_strings(s in "\\PC*") {
        if let Ok(p) = parse(&s) { exercise(&s, &p); }
    }

    #[test]
    fn token_alphabet_soup(s in "[A-Za-z0-9_\\-.~{}\":,\\[\\] ]{0,200}") {
        if let Ok(p) = parse(&s) { exercise(&s, &p); }
        let _ = tamper(&s, &Tamper::StripSignature);
        let _ = tamper(&s, &Tamper::FlipBit { part: tokenator_jose::PartRef::Payload, bit: 3 });
    }

    #[test]
    fn mutated_valid_tokens(which in 0usize..8, pos in any::<prop::sample::Index>(), byte in any::<u8>(), cut in any::<bool>()) {
        let all = fixtures();
        let mut bytes = all[which].clone().into_bytes();
        let i = pos.index(bytes.len());
        if cut { bytes.truncate(i); } else { bytes[i] = byte; }
        if let Ok(s) = String::from_utf8(bytes) {
            if let Ok(p) = parse(&s) { exercise(&s, &p); }
            let _ = tamper(&s, &Tamper::SetAlg("none".into()));
            let _ = tamper(&s, &Tamper::DuplicateDisclosure(0));
        }
    }

    #[test]
    fn random_disclosures(s in "[A-Za-z0-9_\\-]{0,80}") {
        let d = Disclosure::new(&s);
        let _ = d.view();
        let _ = d.digest(tokenator_crypto::HashAlg::Sha256);
    }

    #[test]
    fn random_payloads_process(j in "[\\[\\]{}\":,._sd0-9a ]{0,120}") {
        if let Ok(payload) = tokenator_json::parse(j.as_bytes()) {
            let ds = [Disclosure::new("WyJzIiwiYSIsMV0"), Disclosure::new("WyJzIiwxXQ")];
            let _ = tokenator_jose::process(&payload, &ds);
            let _ = tokenator_jose::check_time_claims(&payload, 0, 0);
            let _ = tokenator_jose::header_facts(&payload);
            let _ = tokenator_jose::duplicate_members(&payload);
        }
    }
}

#[test]
fn deeply_nested_json_envelope_does_not_overflow() {
    let deep = format!(
        "{{\"payload\":\"e30\",\"header\":{}1{},\"signature\":\"\"}}",
        "[".repeat(10_000),
        "]".repeat(10_000)
    );
    let _ = parse(&deep);
    let deep_payload =
        common::b64e(format!("{}{}", "[".repeat(10_000), "]".repeat(10_000)).as_bytes());
    let t = format!("e30.{deep_payload}.~{deep_payload}~");
    if let Ok(p) = parse(&t) {
        exercise(&t, &p);
    }
}
