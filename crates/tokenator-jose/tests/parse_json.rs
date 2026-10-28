//! JWS JSON serialization (flattened and general), plain and SD-JWT.

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{raw, str_of};
use tokenator_jose::{B64Error, DiagnosticKind, PartRef, Serialization, Token, parse};
use tokenator_json::Value;

/// The contents of the JSON string member `name` (unescaped base64url
/// never needs escapes) located by searching the raw input.
fn located(input: &str, text: &str) -> usize {
    input
        .find(text)
        .unwrap_or_else(|| panic!("{text} not in input"))
}

#[test]
fn rfc7515_a6_general_two_signatures() {
    let input = raw("rfc7515-a6-jws-json-general.json");
    let parsed = parse(&input).unwrap();
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let Token::Jws(jws) = &parsed.token else {
        panic!("not a JWS")
    };
    assert_eq!(jws.serialization, Serialization::JsonGeneral);
    assert_eq!(jws.signatures.len(), 2);
    assert_eq!(jws.span.start, 0);
    assert_eq!(jws.span.end, input.trim_end().len());
    let algs: Vec<String> = (0..2)
        .map(|i| str_of(&jws.header(i).unwrap().unwrap(), "/alg").to_owned())
        .collect();
    assert_eq!(algs, ["RS256", "ES256"]);
    let kids: Vec<&str> = jws
        .signatures
        .iter()
        .map(|s| str_of(s.unprotected.as_ref().unwrap(), "/kid"))
        .collect();
    assert_eq!(kids, ["2010-12-29", "e9bc097a-ce51-4036-9562-d2ade882db0d"]);
    // Every encoded part points at its string contents in the input.
    let mut parts = vec![&jws.payload];
    for s in &jws.signatures {
        parts.push(s.protected.as_ref().unwrap());
        parts.push(&s.signature);
    }
    for part in parts {
        let span = part.span();
        assert_eq!(&input[span.start..span.end], part.text());
        assert_eq!(span.start, located(&input, part.text()));
        assert_eq!(&input[span.start - 1..span.start], "\"");
    }
    // The unprotected header tree has spans into the input itself.
    let kid = jws.signatures[1]
        .unprotected
        .as_ref()
        .unwrap()
        .get("kid")
        .unwrap();
    let span = kid.span().unwrap();
    assert_eq!(
        &input[span.start..span.end],
        "\"e9bc097a-ce51-4036-9562-d2ade882db0d\""
    );
    assert_eq!(
        jws.signing_input(1).unwrap(),
        format!("eyJhbGciOiJFUzI1NiJ9.{}", jws.payload.text())
    );
}

#[test]
fn rfc7515_a7_flattened() {
    let input = raw("rfc7515-a7-jws-json-flattened.json");
    let parsed = parse(&input).unwrap();
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let jws = parsed.token.jws();
    assert!(matches!(parsed.token, Token::Jws(_)));
    assert_eq!(jws.serialization, Serialization::JsonFlattened);
    assert_eq!(jws.signatures.len(), 1);
    assert_eq!(str_of(&jws.header(0).unwrap().unwrap(), "/alg"), "ES256");
    assert_eq!(
        str_of(jws.signatures[0].unprotected.as_ref().unwrap(), "/kid"),
        "e9bc097a-ce51-4036-9562-d2ade882db0d"
    );
    assert_eq!(str_of(&jws.claims().unwrap(), "/iss"), "joe");
    assert_eq!(
        jws.compact().unwrap(),
        common::token("rfc7515-a3-jws-es256.txt"),
        "A.7 carries the A.3 signature"
    );
}

#[test]
fn rfc9901_s8_2_flattened_sd_jwt() {
    let input = raw("rfc9901-s8.2-sd-jwt-json-flattened.json");
    let parsed = parse(&input).unwrap();
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let Token::SdJwt(sd) = &parsed.token else {
        panic!("not an SD-JWT")
    };
    assert_eq!(sd.issuer.serialization, Serialization::JsonFlattened);
    assert_eq!(sd.disclosures.len(), 4);
    assert!(sd.kb_jwt.is_none());
    for d in &sd.disclosures {
        let span = d.part().span();
        assert_eq!(&input[span.start..span.end], d.text());
    }
    let names: Vec<String> = sd
        .disclosures
        .iter()
        .map(|d| d.view().unwrap().name().unwrap().to_owned())
        .collect();
    assert_eq!(names, ["sub", "given_name", "family_name", "birthdate"]);
    // The unprotected header is still available as a tree.
    let header = sd.issuer.signatures[0].unprotected.as_ref().unwrap();
    assert_eq!(
        header.get("disclosures").unwrap().elements().unwrap().len(),
        4
    );
}

#[test]
fn rfc9901_s8_2_flattened_sd_jwt_kb() {
    let input = raw("rfc9901-s8.2-sd-jwt-kb-json-flattened.json");
    let parsed = parse(&input).unwrap();
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let sd = parsed.token.sd_jwt().unwrap();
    assert_eq!(sd.disclosures.len(), 2);
    let kb = sd.kb_jwt.as_ref().unwrap();
    assert_eq!(kb.serialization, Serialization::Compact);
    let span = kb.span;
    let kb_text = &input[span.start..span.end];
    assert!(kb_text.starts_with("eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9."));
    assert_eq!(kb.compact().unwrap(), kb_text);
    let kb_header = kb.header(0).unwrap().unwrap();
    assert_eq!(str_of(&kb_header, "/typ"), "kb+jwt");
    let kb_payload_span = kb.payload.span();
    assert_eq!(
        &input[kb_payload_span.start..kb_payload_span.end],
        kb.payload.text()
    );
}

#[test]
fn rfc9901_s8_3_general_sd_jwt_kb() {
    let input = raw("rfc9901-s8.3-sd-jwt-kb-json-general.json");
    let parsed = parse(&input).unwrap();
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let sd = parsed.token.sd_jwt().unwrap();
    assert_eq!(sd.issuer.serialization, Serialization::JsonGeneral);
    assert_eq!(sd.issuer.signatures.len(), 2);
    assert_eq!(sd.disclosures.len(), 2);
    assert!(sd.kb_jwt.is_some());
    let kid = |i: usize| {
        str_of(
            sd.issuer.signatures[i].unprotected.as_ref().unwrap(),
            "/kid",
        )
    };
    assert_eq!((kid(0), kid(1)), ("issuer-key-1", "issuer-key-2"));
}

#[test]
fn sd_hash_input_for_json_uses_the_compact_form() {
    // RFC 9901 §8.1: protected.payload.signature of the first signature,
    // then each disclosure followed by "~".
    let input = raw("rfc9901-s8.3-sd-jwt-kb-json-general.json");
    let parsed = parse(&input).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    let s0 = &sd.issuer.signatures[0];
    let expected = format!(
        "{}.{}.{}~{}~{}~",
        s0.protected.as_ref().unwrap().text(),
        sd.issuer.payload.text(),
        s0.signature.text(),
        sd.disclosures[0].text(),
        sd.disclosures[1].text()
    );
    assert_eq!(sd.sd_hash_input().unwrap(), expected);
}

#[test]
fn sd_members_in_a_later_signature_are_reported_and_ignored() {
    let input = r#"{"payload":"e30","signatures":[
        {"protected":"eyJhbGciOiJFUzI1NiJ9","signature":"AA"},
        {"protected":"eyJhbGciOiJFUzI1NiJ9","header":{"disclosures":["WyJzIiwiYSIsMV0"]},"signature":"AA"}]}"#;
    let parsed = parse(input).unwrap();
    assert!(
        matches!(parsed.token, Token::Jws(_)),
        "SD members only count in the first header"
    );
    assert!(
        parsed.diagnostics.iter().any(|d| d.kind
            == DiagnosticKind::MisplacedSdMember("disclosures")
            && d.part == PartRef::UnprotectedHeader(1)),
        "{:?}",
        parsed.diagnostics
    );
}

#[test]
fn json_envelope_problems_are_diagnostics() {
    // Missing signature: still a JWS with an empty signature part.
    let parsed = parse(r#"{"payload":"e30","protected":"eyJhbGciOiJub25lIn0"}"#).unwrap();
    assert!(
        parsed
            .diagnostics
            .iter()
            .any(|d| d.kind == DiagnosticKind::MissingMember("signature"))
    );
    assert_eq!(parsed.token.jws().signatures[0].signature.text(), "");

    // Protected header of the wrong type.
    let parsed = parse(r#"{"payload":"e30","protected":7,"signature":""}"#).unwrap();
    assert!(
        parsed
            .diagnostics
            .iter()
            .any(|d| d.kind == DiagnosticKind::WrongType("protected"))
    );
    assert!(parsed.token.jws().signatures[0].protected.is_none());

    // No protected header at all is allowed by RFC 7515 when `header` has alg.
    let parsed = parse(r#"{"payload":"e30","header":{"alg":"none"},"signature":""}"#).unwrap();
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let jws = parsed.token.jws();
    assert!(jws.signatures[0].protected.is_none());
    assert_eq!(jws.signing_input(0).unwrap(), ".e30");
    assert!(jws.compact().is_none());

    // Both forms at once.
    let parsed = parse(
        r#"{"payload":"e30","protected":"e30","signature":"","signatures":[{"protected":"e30","signature":""}]}"#,
    )
    .unwrap();
    assert!(
        parsed
            .diagnostics
            .iter()
            .any(|d| d.kind == DiagnosticKind::MixedSerialization)
    );
    assert_eq!(parsed.token.jws().serialization, Serialization::JsonGeneral);

    // A bad disclosure string inside `disclosures`.
    let parsed = parse(
        r#"{"payload":"e30","protected":"e30","signature":"","header":{"disclosures":["!!", 5]}}"#,
    )
    .unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    assert_eq!(sd.disclosures.len(), 1, "non-strings are skipped");
    assert!(
        parsed
            .diagnostics
            .iter()
            .any(|d| d.part == PartRef::Disclosure(0)
                && d.kind == DiagnosticKind::Base64(B64Error::InvalidByte { offset: 0 }))
    );
    assert!(
        parsed
            .diagnostics
            .iter()
            .any(|d| d.kind == DiagnosticKind::WrongType("disclosures"))
    );
}

#[test]
fn escaped_json_strings_are_unescaped() {
    // "e30" written with a \u escape: text is unescaped, span covers the source.
    let input = r#"{"payload":"e30","protected":"eyJhbGciOiJub25lIn0","signature":""}"#;
    let parsed = parse(input).unwrap();
    let jws = parsed.token.jws();
    assert_eq!(jws.payload.text(), "e30");
    let span = jws.payload.span();
    assert_eq!(&input[span.start..span.end], "e\\u00330");
    assert!(matches!(jws.claims().unwrap().value(), Value::Object(m) if m.is_empty()));
}
