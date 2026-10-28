//! Issuance options and errors.

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{b64d, issuer_key, json, rng, segment_json, segments, split_sd, str_of};
use tokenator_crypto::{Alg, CryptoError, HashAlg};
use tokenator_jose::{
    Cnf, DecoyDigests, DecoySpec, DigestOrder, IssueOptions, JoseError, JsonStyle, PartRef,
    SaltSource, SdAlg, issue, parse,
};
use tokenator_json::Node;
use tokenator_keys::to_public;

fn payload_of(token: &str) -> String {
    let (jwt, _, _) = split_sd(token);
    segment_json(segments(jwt)[1])
}

#[test]
fn header_members_in_order() {
    let key = issuer_key(Alg::ES256);
    let claims = json(r#"{"a":1}"#);
    let mut opts = IssueOptions::new(&key, Alg::ES256);
    opts.typ = Some("vc+sd-jwt".into());
    opts.kid = Some("k1".into());
    opts.x5c = vec!["MIIB".into(), "MIIC".into()];
    opts.extra_header = vec![("foo".into(), Node::new(tokenator_json::Value::Bool(true)))];
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    let [h, p, _] = segments(&issued.token);
    assert_eq!(
        segment_json(h),
        r#"{"alg":"ES256","typ":"vc+sd-jwt","kid":"k1","x5c":["MIIB","MIIC"],"foo":true}"#
    );
    assert_eq!(segment_json(p), r#"{"a":1}"#);
}

#[test]
fn minimal_header() {
    let key = issuer_key(Alg::Ed25519);
    let issued = issue(
        &json("{}"),
        &IssueOptions::new(&key, Alg::Ed25519),
        &mut rng(1),
    )
    .unwrap();
    assert_eq!(
        segment_json(segments(&issued.token)[0]),
        r#"{"alg":"Ed25519"}"#
    );
}

#[test]
fn payload_layout_sd_first_then_claims_then_sd_alg_then_cnf() {
    let key = issuer_key(Alg::ES256);
    let claims = json(r#"{"x":1,"y":2,"z":{"p":3,"q":4}}"#);
    let mut opts = IssueOptions::new(&key, Alg::ES256);
    opts.sd = vec!["/y".into(), "/z/q".into()];
    opts.cnf = Some(Cnf::Kid("h".into()));
    opts.salts = SaltSource::Fixed(vec!["s0".into(), "s1".into()]);
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    let d_y = &issued.disclosures[0];
    let d_q = &issued.disclosures[1];
    assert_eq!(d_y.pointer, "/y");
    assert_eq!(
        String::from_utf8(b64d(&d_y.text)).unwrap(),
        r#"["s0","y",2]"#
    );
    assert_eq!(
        String::from_utf8(b64d(&d_q.text)).unwrap(),
        r#"["s1","q",4]"#
    );
    assert_eq!(
        payload_of(&issued.token),
        format!(
            r#"{{"_sd":["{}"],"x":1,"z":{{"_sd":["{}"],"p":3}},"_sd_alg":"sha-256","cnf":{{"kid":"h"}}}}"#,
            d_y.digest, d_q.digest
        )
    );
}

#[test]
fn spaced_style_and_ascii_escapes() {
    let key = issuer_key(Alg::ES256);
    let claims = json(r#"{"n":"Möbius 😀","k":[1,{"a":null}]}"#);
    let mut opts = IssueOptions::new(&key, Alg::ES256);
    opts.style = JsonStyle::Spaced { ascii_only: true };
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    assert_eq!(
        payload_of(&issued.token),
        r#"{"n": "Möbius 😀", "k": [1, {"a": null}]}"#
    );
    opts.style = JsonStyle::Spaced { ascii_only: false };
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    assert_eq!(
        payload_of(&issued.token),
        r#"{"n": "Möbius 😀", "k": [1, {"a": null}]}"#
    );
}

#[test]
fn number_lexemes_survive() {
    let key = issuer_key(Alg::ES256);
    let claims = json(r#"{"a":1.50,"b":-0,"c":1E+3}"#);
    let mut opts = IssueOptions::new(&key, Alg::ES256);
    opts.sd = vec!["/c".into()];
    opts.salts = SaltSource::Fixed(vec!["s".into()]);
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    assert!(payload_of(&issued.token).contains(r#""a":1.50,"b":-0"#));
    assert_eq!(
        String::from_utf8(b64d(&issued.disclosures[0].text)).unwrap(),
        r#"["s","c",1E+3]"#
    );
}

#[test]
fn random_salts_are_128_bits() {
    let key = issuer_key(Alg::ES256);
    let claims = json(r#"{"a":1,"b":2}"#);
    let mut opts = IssueOptions::new(&key, Alg::ES256);
    opts.sd = vec!["/a".into(), "/b".into()];
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    let salts: Vec<String> = issued
        .disclosures
        .iter()
        .map(|d| {
            let t = String::from_utf8(b64d(&d.text)).unwrap();
            str_of(&json(&t), "/0").to_owned()
        })
        .collect();
    assert_ne!(salts[0], salts[1]);
    for s in salts {
        assert_eq!(s.len(), 22);
        assert_eq!(b64d(&s).len(), 16);
    }
}

#[test]
fn digest_orders() {
    let key = issuer_key(Alg::ES256);
    let claims = json(r#"{"a":1,"b":2,"c":3,"d":4}"#);
    let mut opts = IssueOptions::new(&key, Alg::ES256);
    opts.sd = vec!["/a".into(), "/b".into(), "/c".into(), "/d".into()];
    opts.decoys = vec![DecoySpec {
        at: String::new(),
        digests: DecoyDigests::Fixed(vec!["DECOY".into()]),
    }];
    let sd_of = |issued: &tokenator_jose::Issued| -> Vec<String> {
        let p = payload_of(&issued.token);
        let root = json(&p);
        root.get("_sd")
            .unwrap()
            .elements()
            .unwrap()
            .iter()
            .map(|n| match n.value() {
                tokenator_json::Value::String(s) => s.to_string(),
                _ => panic!(),
            })
            .collect()
    };
    opts.digest_order = DigestOrder::Creation;
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    let mut expected: Vec<String> = issued
        .disclosures
        .iter()
        .map(|d| d.digest.clone())
        .collect();
    expected.push("DECOY".into());
    assert_eq!(sd_of(&issued), expected);

    opts.digest_order = DigestOrder::Sorted;
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    let mut sorted = expected.clone();
    sorted.sort();
    assert_eq!(sd_of(&issued), sorted);
}

#[test]
fn random_decoys_in_objects_and_arrays() {
    let key = issuer_key(Alg::ES256);
    let claims = json(r#"{"o":{"k":1},"arr":["x"]}"#);
    let mut opts = IssueOptions::new(&key, Alg::ES256);
    opts.decoys = vec![
        DecoySpec {
            at: "/o".into(),
            digests: DecoyDigests::Random(3),
        },
        DecoySpec {
            at: "/arr".into(),
            digests: DecoyDigests::Random(2),
        },
    ];
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    assert!(issued.token.ends_with('~'), "decoys alone make an SD-JWT");
    assert!(issued.disclosures.is_empty());
    let p = payload_of(&issued.token);
    let root = json(&p);
    let sd = root.pointer("/o/_sd").unwrap().elements().unwrap();
    assert_eq!(sd.len(), 3);
    let arr = root.get("arr").unwrap().elements().unwrap();
    assert_eq!(arr.len(), 3);
    assert_eq!(common::compact(&arr[0]), r#""x""#);
    for el in &arr[1..] {
        assert_eq!(str_of(el, "/...").len(), 43);
    }
    let parsed = parse(&issued.token).unwrap();
    let report = parsed.token.sd_jwt().unwrap().process().unwrap().report;
    assert_eq!(report.digests.len(), 5);
    assert!(report.digests.iter().all(|s| s.disclosure.is_none()));
}

#[test]
fn decoys_inside_a_disclosed_claim_live_in_its_disclosure() {
    let key = issuer_key(Alg::ES256);
    let claims = json(r#"{"o":{"k":1}}"#);
    let mut opts = IssueOptions::new(&key, Alg::ES256);
    opts.sd = vec!["/o".into()];
    opts.decoys = vec![DecoySpec {
        at: "/o".into(),
        digests: DecoyDigests::Fixed(vec!["D1".into()]),
    }];
    opts.salts = SaltSource::Fixed(vec!["s".into()]);
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    assert_eq!(
        String::from_utf8(b64d(&issued.disclosures[0].text)).unwrap(),
        r#"["s","o",{"_sd":["D1"],"k":1}]"#
    );
}

#[test]
fn sd_alg_choices() {
    let key = issuer_key(Alg::ES256);
    let claims = json(r#"{"a":1}"#);
    let mut opts = IssueOptions::new(&key, Alg::ES256);
    opts.sd = vec!["/a".into()];
    opts.sd_alg = Some(HashAlg::Sha384);
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    assert!(payload_of(&issued.token).contains(r#""_sd_alg":"sha-384""#));
    assert_eq!(
        issued.disclosures[0].digest,
        common::digest_b64(HashAlg::Sha384, &issued.disclosures[0].text)
    );
    let parsed = parse(&issued.token).unwrap();
    let report = parsed.token.sd_jwt().unwrap().process().unwrap().report;
    assert_eq!(report.sd_alg, SdAlg::Named(HashAlg::Sha384));
    assert!(report.findings.is_empty());

    opts.sd_alg = None;
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    assert!(!payload_of(&issued.token).contains("_sd_alg"));
    assert_eq!(
        issued.disclosures[0].digest,
        common::sha256_b64(&issued.disclosures[0].text)
    );
    let parsed = parse(&issued.token).unwrap();
    assert_eq!(
        parsed
            .token
            .sd_jwt()
            .unwrap()
            .process()
            .unwrap()
            .report
            .sd_alg,
        SdAlg::Default
    );
}

#[test]
fn errors() {
    let key = issuer_key(Alg::ES256);
    let claims = json(r#"{"a":1,"arr":[1],"cnf":{"kid":"x"},"_sd_alg":"sha-256"}"#);
    let run = |sd: Vec<&str>, decoys: Vec<DecoySpec>, cnf: Option<Cnf>| {
        let mut opts = IssueOptions::new(&key, Alg::ES256);
        opts.sd = sd.into_iter().map(String::from).collect();
        opts.decoys = decoys;
        opts.cnf = cnf;
        issue(&claims, &opts, &mut rng(1))
    };
    assert_eq!(
        run(vec!["/nope"], vec![], None).unwrap_err(),
        JoseError::NoSuchClaim("/nope".into())
    );
    assert_eq!(
        run(vec!["/arr/5"], vec![], None).unwrap_err(),
        JoseError::NoSuchClaim("/arr/5".into())
    );
    assert_eq!(
        run(vec![""], vec![], None).unwrap_err(),
        JoseError::InvalidSdPath(String::new())
    );
    assert_eq!(
        run(vec!["/_sd_alg"], vec![], None).unwrap_err(),
        JoseError::InvalidSdPath("/_sd_alg".into())
    );
    assert_eq!(
        run(
            vec![],
            vec![DecoySpec {
                at: "/a".into(),
                digests: DecoyDigests::Random(1)
            }],
            None
        )
        .unwrap_err(),
        JoseError::InvalidDecoyTarget("/a".into())
    );
    assert_eq!(
        run(vec![], vec![], Some(Cnf::Kid("k".into()))).unwrap_err(),
        JoseError::ClaimConflict("/cnf".into())
    );
    assert_eq!(
        run(vec!["/a"], vec![], None).unwrap_err(),
        JoseError::ClaimConflict("/_sd_alg".into())
    );

    let arr = json("[1]");
    assert_eq!(
        issue(&arr, &IssueOptions::new(&key, Alg::ES256), &mut rng(1)).unwrap_err(),
        JoseError::NotAnObject(PartRef::Payload)
    );
    let public = to_public(&key);
    assert_eq!(
        issue(
            &json("{}"),
            &IssueOptions::new(&public, Alg::ES256),
            &mut rng(1)
        )
        .unwrap_err(),
        JoseError::NoPrivateKey
    );
    assert!(matches!(
        issue(
            &json("{}"),
            &IssueOptions::new(&key, Alg::EdDSA),
            &mut rng(1)
        )
        .unwrap_err(),
        JoseError::Crypto(CryptoError::KeyNotSuitable {
            alg: Alg::EdDSA,
            ..
        })
    ));
    let mut opts = IssueOptions::new(&key, Alg::ES256);
    opts.sd = vec!["/a".into(), "/x".into()];
    opts.salts = SaltSource::Fixed(vec!["only-one".into()]);
    assert_eq!(
        issue(&json(r#"{"a":1,"x":2}"#), &opts, &mut rng(1)).unwrap_err(),
        JoseError::SaltsExhausted
    );
}

#[test]
fn existing_sd_in_an_object_that_gets_digests_conflicts() {
    let key = issuer_key(Alg::ES256);
    let mut opts = IssueOptions::new(&key, Alg::ES256);
    opts.sd = vec!["/o/a".into()];
    assert_eq!(
        issue(&json(r#"{"o":{"_sd":[],"a":1}}"#), &opts, &mut rng(1)).unwrap_err(),
        JoseError::ClaimConflict("/o/_sd".into())
    );
}
