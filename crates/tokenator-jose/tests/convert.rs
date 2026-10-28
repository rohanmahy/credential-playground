//! Compact ↔ JSON serialization.

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{raw, rfc9901_issuer, str_of, token};
use tokenator_crypto::Alg;
use tokenator_jose::{
    JoseError, JsonSerialization, Serialization, Token, check_kb_jwt, parse, to_compact, to_json,
    verify_signature,
};

#[test]
fn rfc7515_a7_to_compact_is_a3() {
    let input = raw("rfc7515-a7-jws-json-flattened.json");
    let parsed = parse(&input).unwrap();
    let c = to_compact(&parsed.token, 0).unwrap();
    assert_eq!(c.text, token("rfc7515-a3-jws-es256.txt"));
    assert_eq!(c.dropped, ["kid"]);
}

#[test]
fn rfc7515_a6_each_signature_to_compact() {
    let input = raw("rfc7515-a6-jws-json-general.json");
    let parsed = parse(&input).unwrap();
    assert_eq!(
        to_compact(&parsed.token, 0).unwrap().text,
        token("rfc7515-a2-jws-rs256.txt")
    );
    assert_eq!(
        to_compact(&parsed.token, 1).unwrap().text,
        token("rfc7515-a3-jws-es256.txt")
    );
    assert_eq!(
        to_compact(&parsed.token, 2).unwrap_err(),
        JoseError::NoSuchSignature(2)
    );
    assert_eq!(
        to_json(&parsed.token, JsonSerialization::Flattened).unwrap_err(),
        JoseError::MultipleSignatures
    );
}

#[test]
fn compact_to_json_and_back() {
    let t = token("rfc7515-a3-jws-es256.txt");
    let parsed = parse(&t).unwrap();
    for form in [JsonSerialization::Flattened, JsonSerialization::General] {
        let j = to_json(&parsed.token, form).unwrap();
        let reparsed = parse(&j).unwrap();
        assert!(reparsed.diagnostics.is_empty());
        let expected = match form {
            JsonSerialization::Flattened => Serialization::JsonFlattened,
            JsonSerialization::General => Serialization::JsonGeneral,
        };
        assert_eq!(reparsed.token.jws().serialization, expected);
        assert_eq!(to_compact(&reparsed.token, 0).unwrap().text, t);
        assert_eq!(
            to_compact(&reparsed.token, 0).unwrap().dropped,
            Vec::<String>::new()
        );
        assert_eq!(
            verify_signature(reparsed.token.jws(), 0, &common::rfc7515_vector("A.3").key),
            Ok(Alg::ES256)
        );
    }
}

#[test]
fn rfc9901_compact_sd_jwt_kb_to_json_matches_s8_semantics() {
    let t = token("rfc9901-s5.2-sd-jwt-kb.txt");
    let parsed = parse(&t).unwrap();
    let j = to_json(&parsed.token, JsonSerialization::Flattened).unwrap();
    let reparsed = parse(&j).unwrap();
    let Token::SdJwt(sd) = &reparsed.token else {
        panic!("not an SD-JWT")
    };
    assert_eq!(sd.disclosures.len(), 4);
    assert!(sd.kb_jwt.is_some());
    assert_eq!(
        verify_signature(&sd.issuer, 0, &rfc9901_issuer()),
        Ok(Alg::ES256)
    );
    // sd_hash is defined over the compact form, so the KB-JWT still binds.
    let exp = tokenator_jose::KbExpectations {
        aud: None,
        nonce: None,
        now: common::RFC9901_KB_IAT,
        skew: 0,
        max_age: None,
    };
    assert_eq!(
        check_kb_jwt(sd, &[], &exp).unwrap().sd_hash,
        tokenator_jose::ValueCheck::Match
    );
    assert_eq!(to_compact(&reparsed.token, 0).unwrap().text, t);
}

#[test]
fn sd_jwt_without_disclosures_keeps_an_empty_array() {
    let jwt = token("rfc9901-s5.1-issuer-signed-jwt.txt");
    let t = format!("{jwt}~");
    let parsed = parse(&t).unwrap();
    let j = to_json(&parsed.token, JsonSerialization::General).unwrap();
    let reparsed = parse(&j).unwrap();
    let sd = reparsed.token.sd_jwt().expect("still an SD-JWT");
    assert!(sd.disclosures.is_empty());
    let header = sd.issuer.signatures[0].unprotected.as_ref().unwrap();
    assert_eq!(
        header.get("disclosures").unwrap().elements().unwrap().len(),
        0
    );
    assert_eq!(to_compact(&reparsed.token, 0).unwrap().text, t);
}

#[test]
fn rfc9901_json_examples_to_compact() {
    let input = raw("rfc9901-s8.3-sd-jwt-kb-json-general.json");
    let parsed = parse(&input).unwrap();
    let c = to_compact(&parsed.token, 0).unwrap();
    assert_eq!(c.dropped, ["kid"]);
    let sd = parsed.token.sd_jwt().unwrap();
    let kb = sd.kb_jwt.as_ref().unwrap().compact().unwrap();
    assert_eq!(c.text, format!("{}{kb}", sd.sd_hash_input().unwrap()));
    // Signature 1 has no disclosures in its header, but they belong to the
    // token, not to a signature, so they come along.
    let c1 = to_compact(&parsed.token, 1).unwrap();
    assert!(c1.text.contains('~'));
    let reparsed = parse(&c1.text).unwrap();
    assert_eq!(reparsed.token.sd_jwt().unwrap().disclosures.len(), 2);
}

#[test]
fn json_preserves_other_unprotected_members() {
    let input = raw("rfc9901-s8.3-sd-jwt-kb-json-general.json");
    let parsed = parse(&input).unwrap();
    let j = to_json(&parsed.token, JsonSerialization::General).unwrap();
    let reparsed = parse(&j).unwrap();
    let sigs = &reparsed.token.jws().signatures;
    assert_eq!(sigs.len(), 2);
    assert_eq!(
        str_of(sigs[0].unprotected.as_ref().unwrap(), "/kid"),
        "issuer-key-1"
    );
    assert_eq!(
        str_of(sigs[1].unprotected.as_ref().unwrap(), "/kid"),
        "issuer-key-2"
    );
}

#[test]
fn no_protected_header_cannot_become_compact() {
    let parsed = parse(r#"{"payload":"e30","header":{"alg":"none"},"signature":""}"#).unwrap();
    assert_eq!(
        to_compact(&parsed.token, 0).unwrap_err(),
        JoseError::NoProtectedHeader
    );
}
