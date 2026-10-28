//! RFC 7515 Appendix A: verify every example, reproduce the deterministic one.

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{issuer_key, raw, rfc7515_vector, rng, segments, token};
use tokenator_crypto::{Alg, CryptoError, sign_deterministic};
use tokenator_jose::{Edits, VerifyError, parse, resign, verify_signature};
use tokenator_keys::to_public;

#[test]
fn vectors_match_the_fixture_tokens() {
    for (section, file) in [
        ("A.2", "rfc7515-a2-jws-rs256.txt"),
        ("A.3", "rfc7515-a3-jws-es256.txt"),
        ("A.4", "rfc7515-a4-jws-es512-nonjson-payload.txt"),
    ] {
        let v = rfc7515_vector(section);
        let parsed_input = token(file);
        let parsed = parse(&parsed_input).unwrap();
        let jws = parsed.token.jws();
        assert_eq!(jws.signing_input(0).unwrap(), v.signing_input, "{section}");
        assert_eq!(jws.signatures[0].signature.text(), v.signature, "{section}");
    }
}

#[test]
fn a2_rs256_verifies() {
    let v = rfc7515_vector("A.2");
    let input = token("rfc7515-a2-jws-rs256.txt");
    let parsed = parse(&input).unwrap();
    assert_eq!(
        verify_signature(parsed.token.jws(), 0, &v.key),
        Ok(Alg::RS256)
    );
    assert_eq!(
        verify_signature(parsed.token.jws(), 0, &to_public(&v.key)),
        Ok(Alg::RS256)
    );
}

#[test]
fn a2_rs256_is_reproduced_byte_for_byte() {
    // RSASSA-PKCS1-v1_5 is deterministic: re-signing the original header and
    // payload bytes with the A.2 key gives the RFC signature.
    let v = rfc7515_vector("A.2");
    let input = token("rfc7515-a2-jws-rs256.txt");
    let parsed = parse(&input).unwrap();
    let out = resign(&parsed.token, &Edits::default(), &v.key, &mut rng(9)).unwrap();
    assert_eq!(out, input);
}

#[test]
fn a3_es256_verifies() {
    let v = rfc7515_vector("A.3");
    let input = token("rfc7515-a3-jws-es256.txt");
    let parsed = parse(&input).unwrap();
    assert_eq!(
        verify_signature(parsed.token.jws(), 0, &v.key),
        Ok(Alg::ES256)
    );
}

#[test]
fn a3_es256_resigned_differs_but_verifies() {
    // The RFC's ECDSA signature used a random k; a new one differs but
    // still verifies, and the header and payload bytes are untouched.
    let v = rfc7515_vector("A.3");
    let input = token("rfc7515-a3-jws-es256.txt");
    let parsed = parse(&input).unwrap();
    let out = resign(&parsed.token, &Edits::default(), &v.key, &mut rng(9)).unwrap();
    let [h, p, s] = segments(&input);
    let [h2, p2, s2] = segments(&out);
    assert_eq!((h, p), (h2, p2));
    assert_ne!(s, s2);
    let reparsed = parse(&out).unwrap();
    assert_eq!(
        verify_signature(reparsed.token.jws(), 0, &v.key),
        Ok(Alg::ES256)
    );
}

#[test]
fn a4_es512_verifies_despite_non_json_payload() {
    let v = rfc7515_vector("A.4");
    let input = token("rfc7515-a4-jws-es512-nonjson-payload.txt");
    let parsed = parse(&input).unwrap();
    assert_eq!(
        verify_signature(parsed.token.jws(), 0, &v.key),
        Ok(Alg::ES512)
    );
}

#[test]
fn a1_hs256_is_unsupported() {
    let input = token("rfc7515-a1-jws-hs256.txt");
    let parsed = parse(&input).unwrap();
    let key = rfc7515_vector("A.3").key;
    assert_eq!(
        verify_signature(parsed.token.jws(), 0, &key),
        Err(VerifyError::UnsupportedAlg("HS256".into()))
    );
}

#[test]
fn a5_alg_none_is_never_accepted() {
    let input = token("rfc7515-a5-unsecured-jws.txt");
    let parsed = parse(&input).unwrap();
    let key = rfc7515_vector("A.3").key;
    assert_eq!(
        verify_signature(parsed.token.jws(), 0, &key),
        Err(VerifyError::AlgNone)
    );
}

#[test]
fn a6_general_each_signature_with_its_key() {
    let input = raw("rfc7515-a6-jws-json-general.json");
    let parsed = parse(&input).unwrap();
    let jws = parsed.token.jws();
    let rsa = rfc7515_vector("A.2").key;
    let ec = rfc7515_vector("A.3").key;
    assert_eq!(verify_signature(jws, 0, &rsa), Ok(Alg::RS256));
    assert_eq!(verify_signature(jws, 1, &ec), Ok(Alg::ES256));
    assert!(matches!(
        verify_signature(jws, 0, &ec),
        Err(VerifyError::Crypto(CryptoError::KeyNotSuitable {
            alg: Alg::RS256,
            ..
        }))
    ));
    assert!(matches!(
        verify_signature(jws, 1, &rsa),
        Err(VerifyError::Crypto(CryptoError::KeyNotSuitable {
            alg: Alg::ES256,
            ..
        }))
    ));
    assert_eq!(
        verify_signature(jws, 2, &ec),
        Err(VerifyError::NoSuchSignature(2))
    );
}

#[test]
fn a7_flattened_verifies() {
    let input = raw("rfc7515-a7-jws-json-flattened.json");
    let parsed = parse(&input).unwrap();
    let ec = rfc7515_vector("A.3").key;
    assert_eq!(verify_signature(parsed.token.jws(), 0, &ec), Ok(Alg::ES256));
}

#[test]
fn wrong_key_of_the_right_type_is_an_invalid_signature() {
    let input = token("rfc7515-a3-jws-es256.txt");
    let parsed = parse(&input).unwrap();
    let other = issuer_key(Alg::ES256);
    assert_eq!(
        verify_signature(parsed.token.jws(), 0, &other),
        Err(VerifyError::Crypto(CryptoError::InvalidSignature))
    );
}

#[test]
fn compact_has_only_signature_zero() {
    let input = token("rfc7515-a3-jws-es256.txt");
    let parsed = parse(&input).unwrap();
    let key = rfc7515_vector("A.3").key;
    assert_eq!(
        verify_signature(parsed.token.jws(), 1, &key),
        Err(VerifyError::NoSuchSignature(1))
    );
}

#[test]
fn alg_from_the_unprotected_header_when_not_protected() {
    // RFC 7515 allows alg in the unprotected header of a JSON serialization;
    // the signing input then starts with an empty protected header.
    let v = rfc7515_vector("A.3");
    let input = token("rfc7515-a3-jws-es256.txt");
    let [_, payload, _] = segments(&input);
    let private = v.key.private_key().unwrap();
    let sig = sign_deterministic(Alg::ES256, private, format!(".{payload}").as_bytes()).unwrap();
    let envelope = format!(
        r#"{{"payload":"{payload}","header":{{"alg":"ES256"}},"signature":"{}"}}"#,
        common::b64e(&sig)
    );
    let parsed = parse(&envelope).unwrap();
    assert_eq!(
        verify_signature(parsed.token.jws(), 0, &v.key),
        Ok(Alg::ES256)
    );

    let no_alg = r#"{"payload":"e30","signature":""}"#;
    let parsed = parse(no_alg).unwrap();
    assert_eq!(
        verify_signature(parsed.token.jws(), 0, &v.key),
        Err(VerifyError::MissingAlg)
    );
}

#[test]
fn unreadable_headers_and_signatures() {
    let key = rfc7515_vector("A.3").key;
    let input = token("rfc7515-a3-jws-es256.txt");
    let [h, p, s] = segments(&input);
    let bad_header = format!("!!.{p}.{s}");
    let parsed = parse(&bad_header).unwrap();
    assert_eq!(
        verify_signature(parsed.token.jws(), 0, &key),
        Err(VerifyError::HeaderUnreadable)
    );

    let bad_sig = format!("{h}.{p}.!!");
    let parsed = parse(&bad_sig).unwrap();
    assert!(matches!(
        verify_signature(parsed.token.jws(), 0, &key),
        Err(VerifyError::SignatureUnreadable(_))
    ));

    let alg_number = format!("{}.{p}.{s}", common::b64e(br#"{"alg":256}"#));
    let parsed = parse(&alg_number).unwrap();
    assert_eq!(
        verify_signature(parsed.token.jws(), 0, &key),
        Err(VerifyError::AlgNotString)
    );
}
