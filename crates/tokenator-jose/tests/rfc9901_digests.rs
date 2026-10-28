//! RFC 9901 §4.2: disclosure contents and digests, including every
//! digest/disclosure pair the RFC lists.

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{digest_b64, rfc9901_disclosures, sha256_b64};
use tokenator_crypto::HashAlg;
use tokenator_jose::{Disclosure, DisclosureError, DisclosureKind, sd_digest};
use tokenator_json::Value;

const MOBIUS: &str = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0";

#[test]
fn s4_2_1_property_disclosure() {
    let d = Disclosure::new(MOBIUS);
    let v = d.view().unwrap();
    assert_eq!(v.kind(), DisclosureKind::Property);
    assert_eq!(v.salt(), "_26bc4LT-ac6q2KI6cBW5es");
    assert_eq!(v.name(), Some("family_name"));
    assert!(matches!(v.value().value(), Value::String(s) if s == "Möbius"));
    // §4.2.3
    assert_eq!(
        d.digest(HashAlg::Sha256),
        "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"
    );
    assert_eq!(
        sd_digest(MOBIUS, HashAlg::Sha256),
        "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"
    );
    assert_eq!(d.text(), MOBIUS);
    assert_eq!(d.part().span().start, 0);
    assert_eq!(d.part().span().end, MOBIUS.len());
}

#[test]
fn s4_2_1_encoding_variants_differ_only_in_digest() {
    // The same claim in three other encodings: same contents, and the
    // digest is over the encoded text, so every digest differs.
    let variants = [
        "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNXHUwMGY2Yml1cyJd",
        "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd",
        "WwoiXzI2YmM0TFQtYWM2cTJLSTZjQlc1ZXMiLAoiZmFtaWx5X25hbWUiLAoiTcO2Yml1cyIKXQ",
    ];
    let mut digests = vec![Disclosure::new(MOBIUS).digest(HashAlg::Sha256)];
    for text in variants {
        let d = Disclosure::new(text);
        let v = d.view().unwrap();
        assert_eq!(v.salt(), "_26bc4LT-ac6q2KI6cBW5es");
        assert_eq!(v.name(), Some("family_name"));
        assert!(
            matches!(v.value().value(), Value::String(s) if s == "Möbius"),
            "{text}"
        );
        assert_eq!(d.digest(HashAlg::Sha256), sha256_b64(text));
        digests.push(d.digest(HashAlg::Sha256));
    }
    digests.sort();
    digests.dedup();
    assert_eq!(digests.len(), 4);
}

#[test]
fn s4_2_2_array_element_disclosure() {
    let d = Disclosure::new("WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0");
    let v = d.view().unwrap();
    assert_eq!(v.kind(), DisclosureKind::ArrayElement);
    assert_eq!(v.salt(), "lklxF5jMYlGTPUovMNIvCA");
    assert_eq!(v.name(), None);
    assert!(matches!(v.value().value(), Value::String(s) if s == "FR"));
    // §4.2.4.2
    assert_eq!(
        d.digest(HashAlg::Sha256),
        "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs"
    );
}

#[test]
fn s4_2_6_recursive_array_elements() {
    // The RFC shows these three without their base64url; the compact JSON
    // encoding reproduces the listed digests.
    for (json, digest) in [
        (
            r#"["16_mAd0GiwaZokU26_0i0h","DE"]"#,
            "PmnlrRjhLcwf8zTDdK15HVGwHtPYjddvD362WjBLwro",
        ),
        (
            r#"["fn9fN0rD-fFs2n303ZI-0c","FR"]"#,
            "r823HFN6Ba_lpSANYtXqqCBAH-TsQlIzfOK0lRAFLCM",
        ),
        (
            r#"["YIKesqOkXXNzMQtsX_-_lw","UK"]"#,
            "nP5GYjwhFm6ESlAeC4NCaIliW4tz0hTrUeoJB3lb5TA",
        ),
    ] {
        let text = tokenator_jose::b64u_encode(json.as_bytes());
        assert_eq!(Disclosure::new(&text).digest(HashAlg::Sha256), digest);
    }
}

#[test]
fn every_listed_digest_and_disclosure() {
    let rows = rfc9901_disclosures();
    assert_eq!(rows.len(), 87);
    for (section, claim, digest, text) in rows {
        let d = Disclosure::new(&text);
        assert_eq!(d.digest(HashAlg::Sha256), digest, "{section} {claim}");
        let v = d
            .view()
            .unwrap_or_else(|e| panic!("{section} {claim}: {e:?}"));
        match claim.strip_prefix("Claim ") {
            Some(name) => {
                assert_eq!(v.kind(), DisclosureKind::Property, "{section} {claim}");
                assert_eq!(v.name(), Some(name), "{section} {claim}");
            }
            None => {
                assert_eq!(claim, "Array Entry");
                assert_eq!(v.kind(), DisclosureKind::ArrayElement, "{section}");
            }
        }
        assert_eq!(v.salt().len(), 22, "{section} {claim}: 128-bit salts");
    }
}

#[test]
fn escaped_values_are_decoded() {
    // A.1 given_name: "太郎"
    let rows = rfc9901_disclosures();
    let (_, _, _, text) = rows
        .iter()
        .find(|r| r.0 == "A.1" && r.1 == "Claim given_name")
        .unwrap()
        .clone();
    let d = Disclosure::new(&text);
    let v = d.view().unwrap();
    assert!(matches!(v.value().value(), Value::String(s) if s == "太郎"));
}

#[test]
fn other_hashes() {
    for h in [HashAlg::Sha384, HashAlg::Sha512] {
        let d = Disclosure::new(MOBIUS);
        assert_eq!(d.digest(h), digest_b64(h, MOBIUS));
        assert_eq!(d.digest(h).len(), (h.output_len() * 4).div_ceil(3));
    }
}

#[test]
fn malformed_disclosures() {
    let enc = |s: &str| tokenator_jose::b64u_encode(s.as_bytes());
    let cases: Vec<(String, DisclosureError)> = vec![
        (enc(r#"{"a":1}"#), DisclosureError::NotAnArray),
        (enc(r#"["salt"]"#), DisclosureError::WrongLength(1)),
        (
            enc(r#"["salt","a","b","c"]"#),
            DisclosureError::WrongLength(4),
        ),
        (enc("[]"), DisclosureError::WrongLength(0)),
        (enc(r#"[1,"a","b"]"#), DisclosureError::SaltNotString),
        (enc(r#"[1,"b"]"#), DisclosureError::SaltNotString),
        (enc(r#"["s",2,"b"]"#), DisclosureError::NameNotString),
    ];
    for (text, err) in cases {
        let d = Disclosure::new(&text);
        assert_eq!(d.view().unwrap_err(), err, "{text}");
        // The digest is still defined: it only looks at the text.
        assert_eq!(d.digest(HashAlg::Sha256), sha256_b64(&text));
    }
    assert!(matches!(
        Disclosure::new("!!").view(),
        Err(DisclosureError::Base64(_))
    ));
    assert!(matches!(
        Disclosure::new(&enc("[\"s\",")).view(),
        Err(DisclosureError::Json(_))
    ));
    assert_eq!(
        Disclosure::new("!!").digest(HashAlg::Sha256),
        sha256_b64("!!")
    );
}

#[test]
fn forbidden_names_are_accepted_by_the_view() {
    // Reported by processing, not by decoding.
    for name in ["_sd", "..."] {
        let text = tokenator_jose::b64u_encode(format!(r#"["salt","{name}",1]"#).as_bytes());
        let d = Disclosure::new(&text);
        assert_eq!(d.view().unwrap().name(), Some(name));
    }
}
