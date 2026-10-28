//! Compact JWS / JWT parsing: original bytes, spans, partial decoding.

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{b64e, raw, segments, str_of, token};
use tokenator_jose::{
    B64Error, DiagnosticKind, ParseError, PartError, PartRef, Serialization, Token, parse,
};
use tokenator_json::Value;

const RFC7515_COMPACT: [&str; 5] = [
    "rfc7515-a1-jws-hs256.txt",
    "rfc7515-a2-jws-rs256.txt",
    "rfc7515-a3-jws-es256.txt",
    "rfc7515-a4-jws-es512-nonjson-payload.txt",
    "rfc7515-a5-unsecured-jws.txt",
];

#[test]
fn rfc7515_compact_examples_keep_original_segments() {
    for name in RFC7515_COMPACT {
        let input = raw(name); // with its trailing newline
        let parsed = parse(&input).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let Token::Jws(jws) = &parsed.token else {
            panic!("{name}: not a JWS")
        };
        assert_eq!(jws.serialization, Serialization::Compact, "{name}");
        assert_eq!(jws.signatures.len(), 1, "{name}");
        let [h, p, s] = segments(input.trim_end());
        let sig = &jws.signatures[0];
        let protected = sig.protected.as_ref().unwrap();
        assert_eq!(protected.text(), h, "{name}");
        assert_eq!(jws.payload.text(), p, "{name}");
        assert_eq!(sig.signature.text(), s, "{name}");
        assert!(sig.unprotected.is_none());
        for part in [protected, &jws.payload, &sig.signature] {
            let span = part.span();
            assert_eq!(&input[span.start..span.end], part.text(), "{name}");
        }
        assert_eq!(jws.span.start, 0);
        assert_eq!(
            jws.span.end,
            input.trim_end().len(),
            "{name}: trailing newline excluded"
        );
        assert_eq!(jws.signing_input(0).unwrap(), format!("{h}.{p}"), "{name}");
        assert_eq!(jws.compact().unwrap(), input.trim_end(), "{name}");
    }
}

#[test]
fn rfc7515_a1_header_bytes_include_crlf() {
    let input = token("rfc7515-a1-jws-hs256.txt");
    let parsed = parse(&input).unwrap();
    let jws = parsed.token.jws();
    let protected = jws.signatures[0].protected.as_ref().unwrap();
    assert_eq!(
        protected.decoded().unwrap(),
        b"{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"
    );
    let header = jws.header(0).unwrap().unwrap();
    assert_eq!(str_of(&header, "/alg"), "HS256");
    assert_eq!(str_of(&header, "/typ"), "JWT");
    // Spans in the header tree are relative to the decoded header bytes.
    let alg = header.get("alg").unwrap();
    let span = alg.span().unwrap();
    assert_eq!(
        &protected.decoded().unwrap()[span.start..span.end],
        b"\"HS256\""
    );
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
}

#[test]
fn jwt_claims_keep_number_lexemes() {
    let input = token("rfc7519-s3.1-jwt-hs256.txt");
    let parsed = parse(&input).unwrap();
    let claims = parsed.token.jws().claims().unwrap();
    assert_eq!(str_of(&claims, "/iss"), "joe");
    assert!(matches!(claims.get("exp").unwrap().value(), Value::Number(n) if n == "1300819380"));
    assert!(matches!(
        claims.get("http://example.com/is_root").unwrap().value(),
        Value::Bool(true)
    ));
}

#[test]
fn rfc7515_a4_non_json_payload_is_a_diagnostic_not_an_error() {
    let input = token("rfc7515-a4-jws-es512-nonjson-payload.txt");
    let parsed = parse(&input).unwrap();
    let jws = parsed.token.jws();
    assert_eq!(jws.payload.decoded().unwrap(), b"Payload");
    assert!(matches!(jws.claims(), Err(PartError::Json(_))));
    assert_eq!(parsed.diagnostics.len(), 1, "{:?}", parsed.diagnostics);
    let d = &parsed.diagnostics[0];
    assert_eq!(d.part, PartRef::Payload);
    assert!(matches!(d.kind, DiagnosticKind::Json(_)));
    assert_eq!(d.span, Some(jws.payload.span()));
    // The header and signature are still fully available.
    assert_eq!(str_of(&jws.header(0).unwrap().unwrap(), "/alg"), "ES512");
    assert_eq!(jws.signatures[0].signature.decoded().unwrap().len(), 132);
}

#[test]
fn rfc7515_a5_unsecured_has_empty_signature() {
    let input = token("rfc7515-a5-unsecured-jws.txt");
    let parsed = parse(&input).unwrap();
    let sig = &parsed.token.jws().signatures[0].signature;
    assert_eq!(sig.text(), "");
    assert_eq!(sig.decoded().unwrap(), b"");
    assert_eq!(sig.span().start, input.len());
    assert!(parsed.diagnostics.is_empty());
}

#[test]
fn surrounding_whitespace_is_ignored_and_spans_stay_absolute() {
    let t = token("rfc7515-a3-jws-es256.txt");
    let input = format!(" \t\r\n{t}\r\n ");
    let parsed = parse(&input).unwrap();
    let jws = parsed.token.jws();
    assert_eq!(jws.span.start, 4);
    assert_eq!(jws.span.end, 4 + t.len());
    let p = jws.payload.span();
    assert_eq!(&input[p.start..p.end], jws.payload.text());
}

#[test]
fn bad_header_base64_does_not_hide_payload() {
    let t = token("rfc7519-s3.1-jwt-hs256.txt");
    let [_, p, s] = segments(&t);
    let input = format!("eyJ+bad.{p}.{s}");
    let parsed = parse(&input).unwrap();
    let jws = parsed.token.jws();
    assert_eq!(str_of(&jws.claims().unwrap(), "/iss"), "joe");
    let protected = jws.signatures[0].protected.as_ref().unwrap();
    assert_eq!(
        protected.decoded(),
        Err(B64Error::InvalidByte { offset: 3 })
    );
    assert_eq!(parsed.diagnostics.len(), 1, "{:?}", parsed.diagnostics);
    assert_eq!(parsed.diagnostics[0].part, PartRef::ProtectedHeader(0));
    assert_eq!(
        parsed.diagnostics[0].kind,
        DiagnosticKind::Base64(B64Error::InvalidByte { offset: 3 })
    );
}

#[test]
fn header_that_is_not_json_or_not_an_object() {
    let t = token("rfc7519-s3.1-jwt-hs256.txt");
    let [_, p, s] = segments(&t);
    for (header, expect_not_object) in [(b"{\"alg\":".as_slice(), false), (b"[1,2]", true)] {
        let input = format!("{}.{p}.{s}", b64e(header));
        let parsed = parse(&input).unwrap();
        assert_eq!(parsed.diagnostics.len(), 1, "{:?}", parsed.diagnostics);
        let d = &parsed.diagnostics[0];
        assert_eq!(d.part, PartRef::ProtectedHeader(0));
        if expect_not_object {
            assert_eq!(d.kind, DiagnosticKind::NotAnObject);
        } else {
            assert!(matches!(d.kind, DiagnosticKind::Json(_)));
        }
        // The payload is unaffected.
        assert_eq!(str_of(&parsed.token.jws().claims().unwrap(), "/iss"), "joe");
    }
}

#[test]
fn payload_that_is_json_but_not_an_object() {
    let input = format!("{}.{}.", b64e(b"{\"alg\":\"none\"}"), b64e(b"[1]"));
    let parsed = parse(&input).unwrap();
    assert!(
        parsed
            .diagnostics
            .iter()
            .any(|d| d.part == PartRef::Payload && d.kind == DiagnosticKind::NotAnObject),
        "{:?}",
        parsed.diagnostics
    );
}

#[test]
fn wrong_segment_counts() {
    let parsed = parse("eyJhbGciOiJub25lIn0.e30").unwrap();
    let jws = parsed.token.jws();
    assert_eq!(jws.signatures[0].signature.text(), "");
    assert!(
        parsed
            .diagnostics
            .iter()
            .any(|d| d.kind == DiagnosticKind::SegmentCount { found: 2 }),
        "{:?}",
        parsed.diagnostics
    );
    // The header and payload still decode.
    assert_eq!(str_of(&jws.header(0).unwrap().unwrap(), "/alg"), "none");

    let parsed = parse("eyJhbGciOiJub25lIn0.e30.c2ln.ZXh0cmE").unwrap();
    let sig = &parsed.token.jws().signatures[0].signature;
    assert_eq!(sig.text(), "c2ln.ZXh0cmE");
    assert_eq!(sig.decoded(), Err(B64Error::InvalidByte { offset: 4 }));
    assert!(
        parsed
            .diagnostics
            .iter()
            .any(|d| d.kind == DiagnosticKind::SegmentCount { found: 4 })
    );
}

#[test]
fn every_part_broken_still_parses() {
    let parsed = parse("!!.??.**").unwrap();
    let parts: Vec<PartRef> = parsed.diagnostics.iter().map(|d| d.part).collect();
    assert_eq!(
        parts,
        [
            PartRef::ProtectedHeader(0),
            PartRef::Payload,
            PartRef::Signature(0)
        ]
    );
    assert!(parsed.diagnostics.iter().all(|d| matches!(
        d.kind,
        DiagnosticKind::Base64(B64Error::InvalidByte { offset: 0 })
    )));
}

#[test]
fn fatal_errors_only_for_unrecognizable_input() {
    assert_eq!(parse("").unwrap_err(), ParseError::Empty);
    assert_eq!(parse(" \n\t").unwrap_err(), ParseError::Empty);
    assert_eq!(parse("hello").unwrap_err(), ParseError::NotAToken);
    assert_eq!(parse("[1, 2]").unwrap_err(), ParseError::NotAToken);
    assert!(matches!(
        parse("{\"payload\":").unwrap_err(),
        ParseError::Json(_)
    ));
    assert_eq!(parse("{\"a\":1}").unwrap_err(), ParseError::NotAJwsEnvelope);
    assert_eq!(
        parse("{\"payload\":1,\"signature\":\"\"}").unwrap_err(),
        ParseError::NotAJwsEnvelope
    );
}

#[test]
fn compact_with_tilde_is_an_sd_jwt() {
    let jwt = token("rfc9901-s5.1-issuer-signed-jwt.txt");
    let with_tilde = format!("{jwt}~");
    let parsed = parse(&with_tilde).unwrap();
    let Token::SdJwt(sd) = &parsed.token else {
        panic!("not an SD-JWT")
    };
    assert!(sd.disclosures.is_empty());
    assert!(sd.kb_jwt.is_none());
    assert_eq!(sd.issuer.compact().unwrap(), jwt);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    // Without the tilde it is a plain JWT.
    assert!(matches!(parse(&jwt).unwrap().token, Token::Jws(_)));
}

#[test]
fn rfc7519_unsecured_jwt() {
    let input = token("rfc7519-s6.1-unsecured-jwt.txt");
    let parsed = parse(&input).unwrap();
    let jws = parsed.token.jws();
    assert_eq!(str_of(&jws.header(0).unwrap().unwrap(), "/alg"), "none");
    assert_eq!(jws.signatures[0].signature.text(), "");
    assert_eq!(str_of(&jws.claims().unwrap(), "/iss"), "joe");
}
