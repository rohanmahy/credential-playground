//! Edit & re-sign: unedited bytes stay identical.

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{b64d, issuer_key, raw, rfc9901_issuer, rng, segment_json, segments, split_sd, token};
use tokenator_crypto::Alg;
use tokenator_jose::{
    Edits, JoseError, Serialization, ValueCheck, check_kb_jwt, parse, resign, verify_signature,
};
use tokenator_json::{Member, Node, Value};
use tokenator_keys::to_public;

#[test]
fn no_edits_keeps_header_payload_and_disclosures() {
    let input = token("rfc9901-s5.2-sd-jwt-kb.txt");
    let parsed = parse(&input).unwrap();
    let key = issuer_key(Alg::ES256);
    let out = resign(&parsed.token, &Edits::default(), &key, &mut rng(4)).unwrap();
    let (jwt, discs, kb) = split_sd(&input);
    let (jwt2, discs2, kb2) = split_sd(&out);
    let [h, p, s] = segments(jwt);
    let [h2, p2, s2] = segments(jwt2);
    assert_eq!((h, p), (h2, p2));
    assert_ne!(s, s2);
    assert_eq!(discs, discs2);
    assert_eq!(kb, kb2, "the KB-JWT is copied, and is now stale");
    let reparsed = parse(&out).unwrap();
    let sd = reparsed.token.sd_jwt().unwrap();
    assert_eq!(
        verify_signature(&sd.issuer, 0, &to_public(&key)),
        Ok(Alg::ES256)
    );
    assert!(verify_signature(&sd.issuer, 0, &rfc9901_issuer()).is_err());
    let exp = tokenator_jose::KbExpectations {
        aud: None,
        nonce: None,
        now: 0,
        skew: 0,
        max_age: None,
    };
    assert!(matches!(
        check_kb_jwt(sd, &[], &exp).unwrap().sd_hash,
        ValueCheck::Mismatch { .. }
    ));
}

#[test]
fn edited_payload_changes_only_the_edited_value() {
    let input = token("rfc9901-s5.1-sd-jwt.txt");
    let parsed = parse(&input).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    let original = sd.issuer.payload.decoded().unwrap().to_vec();
    let mut payload = sd.issuer.claims().unwrap();
    payload
        .get_mut("sub")
        .unwrap()
        .set_value(Value::String("user_43".into()));
    let key = issuer_key(Alg::ES256);
    let edits = Edits {
        header: None,
        payload: Some(&payload),
    };
    let out = resign(&parsed.token, &edits, &key, &mut rng(4)).unwrap();
    let (jwt, discs, _) = split_sd(&out);
    let [h, p, _] = segments(jwt);
    assert_eq!(h, segments(split_sd(&input).0)[0], "header untouched");
    let expected = String::from_utf8(original)
        .unwrap()
        .replace(r#""sub": "user_42""#, r#""sub": "user_43""#);
    assert_eq!(
        String::from_utf8(b64d(p)).unwrap(),
        expected,
        "the RFC's spacing survives"
    );
    assert_eq!(discs, split_sd(&input).1);
    let reparsed = parse(&out).unwrap();
    let sd2 = reparsed.token.sd_jwt().unwrap();
    assert_eq!(verify_signature(&sd2.issuer, 0, &key), Ok(Alg::ES256));
    let processed = sd2.process().unwrap();
    assert!(
        processed.report.findings.is_empty(),
        "digests untouched, so all still match"
    );
    assert_eq!(common::str_of(&processed.claims, "/sub"), "user_43");
}

#[test]
fn edited_header_alg_selects_the_algorithm() {
    let input = token("rfc7515-a3-jws-es256.txt");
    let parsed = parse(&input).unwrap();
    let mut header = parsed.token.jws().header(0).unwrap().unwrap();
    header
        .get_mut("alg")
        .unwrap()
        .set_value(Value::String("EdDSA".into()));
    if let Value::Object(ms) = header.value_mut() {
        ms.push(Member::new("kid", Node::new(Value::String("ed".into()))));
    }
    let key = issuer_key(Alg::EdDSA);
    let out = resign(
        &parsed.token,
        &Edits {
            header: Some(&header),
            payload: None,
        },
        &key,
        &mut rng(4),
    )
    .unwrap();
    assert_eq!(
        segment_json(segments(&out)[0]),
        r#"{"alg":"EdDSA","kid":"ed"}"#
    );
    assert_eq!(segments(&out)[1], segments(&input)[1]);
    let reparsed = parse(&out).unwrap();
    assert_eq!(
        verify_signature(reparsed.token.jws(), 0, &key),
        Ok(Alg::EdDSA)
    );
}

#[test]
fn resign_errors() {
    let key = issuer_key(Alg::ES256);
    for (name, err) in [
        (
            "rfc7515-a5-unsecured-jws.txt",
            JoseError::UnusableAlg(Some("none".into())),
        ),
        (
            "rfc7515-a1-jws-hs256.txt",
            JoseError::UnusableAlg(Some("HS256".into())),
        ),
    ] {
        let input = token(name);
        let parsed = parse(&input).unwrap();
        assert_eq!(
            resign(&parsed.token, &Edits::default(), &key, &mut rng(4)).unwrap_err(),
            err,
            "{name}"
        );
    }
    let input = token("rfc7515-a2-jws-rs256.txt");
    let parsed = parse(&input).unwrap();
    assert!(matches!(
        resign(&parsed.token, &Edits::default(), &key, &mut rng(4)).unwrap_err(),
        JoseError::Crypto(_)
    ));
    let public = to_public(&key);
    let input = token("rfc7515-a3-jws-es256.txt");
    let parsed = parse(&input).unwrap();
    assert_eq!(
        resign(&parsed.token, &Edits::default(), &public, &mut rng(4)).unwrap_err(),
        JoseError::NoPrivateKey
    );
    let bad = format!("!!.{}.", segments(&input)[1]);
    let parsed = parse(&bad).unwrap();
    assert!(matches!(
        resign(&parsed.token, &Edits::default(), &key, &mut rng(4)).unwrap_err(),
        JoseError::Part {
            part: tokenator_jose::PartRef::ProtectedHeader(0),
            ..
        }
    ));
}

#[test]
fn json_serialization_stays_json_with_its_layout() {
    let input = raw("rfc7515-a7-jws-json-flattened.json");
    let parsed = parse(&input).unwrap();
    let key = common::rfc7515_vector("A.3").key;
    let out = resign(&parsed.token, &Edits::default(), &key, &mut rng(4)).unwrap();
    let reparsed = parse(&out).unwrap();
    let jws = reparsed.token.jws();
    assert_eq!(jws.serialization, Serialization::JsonFlattened);
    assert_eq!(verify_signature(jws, 0, &key), Ok(Alg::ES256));
    // Only the signature string changed; the envelope's layout is kept.
    let old_sig = parsed.token.jws().signatures[0].signature.text().to_owned();
    let new_sig = jws.signatures[0].signature.text();
    assert_eq!(out.trim_end(), input.trim_end().replace(&old_sig, new_sig));
}

#[test]
fn general_resigns_signature_zero_only() {
    let input = raw("rfc7515-a6-jws-json-general.json");
    let parsed = parse(&input).unwrap();
    let rsa = common::rfc7515_vector("A.2").key;
    let ec = common::rfc7515_vector("A.3").key;
    let out = resign(&parsed.token, &Edits::default(), &rsa, &mut rng(4)).unwrap();
    assert_eq!(
        out.trim_end(),
        input.trim_end(),
        "PKCS#1 v1.5 over the same bytes: identical"
    );
    let reparsed = parse(&out).unwrap();
    assert_eq!(
        verify_signature(reparsed.token.jws(), 1, &ec),
        Ok(Alg::ES256)
    );
}
