//! Checks the fixtures and test helpers themselves, without calling this
//! crate, so a failure elsewhere is never a broken fixture.

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_crypto::{Alg, verify};
use tokenator_keys::to_public;

#[test]
fn rfc9901_disclosure_table_is_consistent() {
    let rows = rfc9901_disclosures();
    assert_eq!(rows.len(), 87);
    for (section, claim, digest, text) in &rows {
        assert_eq!(&sha256_b64(text), digest, "{section} {claim}");
    }
}

#[test]
fn rfc9901_tokens_split_and_digests_are_embedded() {
    for name in [
        "rfc9901-s5.1-sd-jwt.txt",
        "rfc9901-s5.2-sd-jwt-kb.txt",
        "rfc9901-a1-presentation.txt",
        "rfc9901-a2-presentation.txt",
        "rfc9901-a3-sd-jwt.txt",
        "rfc9901-a3-sd-jwt-kb.txt",
        "rfc9901-a4-sd-jwt.txt",
        "rfc9901-a4-sd-jwt-kb.txt",
    ] {
        let t = token(name);
        let (jwt, discs, _) = split_sd(&t);
        let [_, p, _] = segments(jwt);
        let mut haystack = segment_json(p);
        for d in &discs {
            haystack.push_str(&segment_json(d));
        }
        for d in &discs {
            assert!(haystack.contains(&sha256_b64(d)), "{name}");
        }
    }
}

#[test]
fn rfc9901_issuer_signatures_verify_with_tokenator_crypto() {
    let key = rfc9901_issuer().public_key();
    for name in [
        "rfc9901-s5.1-sd-jwt.txt",
        "rfc9901-a3-sd-jwt.txt",
        "rfc9901-a4-sd-jwt.txt",
    ] {
        let t = token(name);
        let (jwt, _, _) = split_sd(&t);
        let [h, p, s] = segments(jwt);
        verify(Alg::ES256, &key, format!("{h}.{p}").as_bytes(), &b64d(s)).unwrap();
    }
}

#[test]
fn rfc7515_vectors_verify_with_tokenator_crypto() {
    for (section, alg) in [
        ("A.2", Alg::RS256),
        ("A.3", Alg::ES256),
        ("A.4", Alg::ES512),
    ] {
        let v = rfc7515_vector(section);
        assert_eq!(tokenator_crypto::alg_from_jose(&v.alg), Some(alg));
        verify(
            alg,
            &v.key.public_key(),
            v.signing_input.as_bytes(),
            &b64d(&v.signature),
        )
        .unwrap();
    }
}

#[test]
fn json_fixtures_parse() {
    for name in [
        "rfc9901-s5.1-input-claims.json",
        "rfc9901-s5.2-processed-payload.json",
        "rfc9901-a1-input-claims.json",
        "rfc9901-a1-processed-payload.json",
        "rfc9901-a2-input-claims.json",
        "rfc9901-a2-processed-payload.json",
        "rfc9901-a3-input-claims.json",
        "rfc9901-a3-processed-payload.json",
        "rfc9901-a4-input-claims.json",
        "rfc9901-a4-processed-payload.json",
        "rfc9901-s6-input-claims.json",
        "rfc9901-s6.1-payload.json",
        "rfc9901-s6.2-payload.json",
        "rfc9901-s6.2-payload-country-plain.json",
        "rfc9901-s6.3-payload.json",
        "rfc9901-s8.2-sd-jwt-json-flattened.json",
        "rfc9901-s8.2-sd-jwt-kb-json-flattened.json",
        "rfc9901-s8.3-sd-jwt-kb-json-general.json",
        "rfc7515-a6-jws-json-general.json",
        "rfc7515-a7-jws-json-flattened.json",
    ] {
        let text = raw(name);
        assert!(text.ends_with("}\n"), "{name}");
        let _ = json(&text);
    }
}

#[test]
fn test_keys_for_every_alg() {
    for alg in Alg::ALL {
        let issuer = issuer_key(alg);
        let holder = holder_key(alg);
        assert!(issuer.is_private() && holder.is_private(), "{alg:?}");
        assert!(!issuer.same_material(&holder), "{alg:?}");
        let sig =
            tokenator_crypto::sign(alg, issuer.private_key().unwrap(), b"m", &mut rng(1)).unwrap();
        verify(alg, &to_public(&issuer).public_key(), b"m", &sig).unwrap();
        // Holder keys must convert to a public JWK for `cnf`.
        let _ = public_jwk(&holder).to_json();
    }
}

#[test]
fn same_json_requires_order() {
    assert!(same_json(
        &json(r#"{"a":1,"b":[true]}"#),
        &json(r#"{ "a" : 1, "b" : [ true ] }"#)
    ));
    assert!(!same_json(
        &json(r#"{"a":1,"b":2}"#),
        &json(r#"{"b":2,"a":1}"#)
    ));
    assert!(!same_json(&json("1.0"), &json("1")));
}
