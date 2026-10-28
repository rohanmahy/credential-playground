//! Disclose / present: selection rules (report, never fix) and KB-JWT
//! construction, reproducing the RFC 9901 presentations.

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{
    RFC9901_AUD, RFC9901_KB_IAT, RFC9901_NONCE, holder_key, issuer_key, json, raw, rng, segments,
    split_sd, str_of, token,
};
use tokenator_crypto::{Alg, CryptoError};
use tokenator_jose::{
    HolderKey, IssueOptions, JoseError, JsonStyle, KbExpectations, KbOptions, SelectionFinding,
    Serialization, Token, ValueCheck, VerifyError, check_kb_jwt, issue, parse, present, select,
};

fn expect() -> KbExpectations<'static> {
    KbExpectations {
        aud: Some(RFC9901_AUD),
        nonce: Some(RFC9901_NONCE),
        now: RFC9901_KB_IAT,
        skew: 60,
        max_age: Some(300),
    }
}

#[test]
fn reproduces_the_rfc_presentations_without_kb() {
    for (issued, keep, presented) in [
        (
            "rfc9901-s5.1-sd-jwt.txt",
            vec![1, 5, 0, 8],
            "rfc9901-s5.2-sd-jwt-kb.txt",
        ),
        (
            "rfc9901-a3-sd-jwt.txt",
            vec![20, 17, 8],
            "rfc9901-a3-sd-jwt-kb.txt",
        ),
        (
            "rfc9901-a4-sd-jwt.txt",
            vec![6, 5, 0, 1],
            "rfc9901-a4-sd-jwt-kb.txt",
        ),
    ] {
        let input = token(issued);
        let parsed = parse(&input).unwrap();
        let sd = parsed.token.sd_jwt().unwrap();
        let out = present(sd, &keep, None, &mut rng(3)).unwrap();
        assert!(
            out.selection.findings.is_empty(),
            "{issued}: {:?}",
            out.selection.findings
        );
        assert_eq!(out.selection.kept, keep);
        let reference = token(presented);
        let (_, _, kb) = split_sd(&reference);
        assert_eq!(
            out.token,
            &reference[..reference.len() - kb.len()],
            "{issued}"
        );
    }
}

#[test]
fn reproduces_the_rfc_kb_jwt_header_and_payload() {
    // With the RFC's style, the KB-JWT header and payload segments of §5.2
    // come out identical; the signature is ours (the holder's private key
    // is not published), so it does not verify against `cnf`.
    let input = token("rfc9901-s5.1-sd-jwt.txt");
    let parsed = parse(&input).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    let holder = holder_key(Alg::ES256);
    let mut kb = KbOptions::new(
        &holder,
        Alg::ES256,
        RFC9901_AUD,
        RFC9901_NONCE,
        RFC9901_KB_IAT,
    );
    kb.style = JsonStyle::Spaced { ascii_only: true };
    let out = present(sd, &[1, 5, 0, 8], Some(&kb), &mut rng(3)).unwrap();
    let (_, _, our_kb) = split_sd(&out.token);
    let reference = token("rfc9901-s5.2-sd-jwt-kb.txt");
    let (_, _, rfc_kb) = split_sd(&reference);
    let [h, p, _] = segments(our_kb);
    let [rh, rp, _] = segments(rfc_kb);
    assert_eq!((h, p), (rh, rp));

    let reparsed = parse(&out.token).unwrap();
    let report = check_kb_jwt(reparsed.token.sd_jwt().unwrap(), &[], &expect()).unwrap();
    assert_eq!(report.holder_key, HolderKey::CnfJwk);
    assert_eq!(
        report.signature,
        Err(VerifyError::Crypto(CryptoError::InvalidSignature))
    );
    assert_eq!(report.sd_hash, ValueCheck::Match);
    assert_eq!(report.typ, ValueCheck::Match);
}

#[test]
fn kb_jwt_default_layout() {
    let input = token("rfc9901-s5.1-sd-jwt.txt");
    let parsed = parse(&input).unwrap();
    let holder = holder_key(Alg::EdDSA);
    let kb = KbOptions::new(&holder, Alg::EdDSA, "aud-1", "n-1", 1_700_000_000);
    let out = present(parsed.token.sd_jwt().unwrap(), &[0], Some(&kb), &mut rng(3)).unwrap();
    let (jwt, discs, kb_jwt) = split_sd(&out.token);
    let [h, p, _] = segments(kb_jwt);
    assert_eq!(common::segment_json(h), r#"{"alg":"EdDSA","typ":"kb+jwt"}"#);
    let sd_hash = common::sha256_b64(&format!("{jwt}~{}~", discs[0]));
    assert_eq!(
        common::segment_json(p),
        format!(r#"{{"nonce":"n-1","aud":"aud-1","iat":1700000000,"sd_hash":"{sd_hash}"}}"#)
    );
}

#[test]
fn kb_typ_can_be_omitted_or_changed() {
    let input = token("rfc9901-s5.1-sd-jwt.txt");
    let parsed = parse(&input).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    let holder = holder_key(Alg::ES256);
    for (typ, check) in [
        (None, ValueCheck::Missing),
        (
            Some("JWT".to_owned()),
            ValueCheck::Mismatch {
                expected: "kb+jwt".into(),
                found: "JWT".into(),
            },
        ),
    ] {
        let mut kb = KbOptions::new(
            &holder,
            Alg::ES256,
            RFC9901_AUD,
            RFC9901_NONCE,
            RFC9901_KB_IAT,
        );
        kb.typ = typ;
        let out = present(sd, &[0], Some(&kb), &mut rng(3)).unwrap();
        let reparsed = parse(&out.token).unwrap();
        let report = check_kb_jwt(reparsed.token.sd_jwt().unwrap(), &[], &expect()).unwrap();
        assert_eq!(report.typ, check);
    }
}

#[test]
fn missing_parent_is_reported_not_added() {
    let input = token("rfc9901-a3-sd-jwt.txt");
    let parsed = parse(&input).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    // "18" (17) lives inside age_equal_or_over (20); street_address (3)
    // inside address (7).
    let sel = select(sd, &[17, 3]).unwrap();
    assert_eq!(
        sel.findings,
        [
            SelectionFinding::MissingParent {
                disclosure: 17,
                parent: 20
            },
            SelectionFinding::MissingParent {
                disclosure: 3,
                parent: 7
            },
        ]
    );
    let out = present(sd, &[17, 3], None, &mut rng(3)).unwrap();
    assert_eq!(out.selection, sel);
    let (_, discs, _) = split_sd(&out.token);
    assert_eq!(
        discs,
        [sd.disclosures[17].text(), sd.disclosures[3].text()],
        "nothing added"
    );
    // The verifier side sees the consequence: both unmatched.
    let reparsed = parse(&out.token).unwrap();
    let report = reparsed.token.sd_jwt().unwrap().process().unwrap().report;
    assert!(
        report
            .findings
            .contains(&tokenator_jose::SdFinding::UnmatchedDisclosure { disclosure: 0 })
    );
    assert!(
        report
            .findings
            .contains(&tokenator_jose::SdFinding::UnmatchedDisclosure { disclosure: 1 })
    );
}

#[test]
fn parent_after_child_is_fine() {
    let input = token("rfc9901-a3-sd-jwt.txt");
    let parsed = parse(&input).unwrap();
    let sel = select(parsed.token.sd_jwt().unwrap(), &[17, 20]).unwrap();
    assert!(sel.findings.is_empty(), "{:?}", sel.findings);
}

#[test]
fn only_the_immediate_parent_is_reported() {
    let key = issuer_key(Alg::ES256);
    let claims = json(r#"{"a":{"b":{"c":1}}}"#);
    let mut opts = IssueOptions::new(&key, Alg::ES256);
    opts.sd = vec!["/a".into(), "/a/b".into(), "/a/b/c".into()];
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    let pointers: Vec<&str> = issued
        .disclosures
        .iter()
        .map(|d| d.pointer.as_str())
        .collect();
    assert_eq!(
        pointers,
        ["/a/b/c", "/a/b", "/a"],
        "inner disclosures are created first"
    );
    let parsed = parse(&issued.token).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    let sel = select(sd, &[0, 1]).unwrap();
    assert_eq!(
        sel.findings,
        [SelectionFinding::MissingParent {
            disclosure: 1,
            parent: 2
        }]
    );
    let sel = select(sd, &[0]).unwrap();
    assert_eq!(
        sel.findings,
        [SelectionFinding::MissingParent {
            disclosure: 0,
            parent: 1
        }]
    );
    assert!(select(sd, &[2, 1, 0]).unwrap().findings.is_empty());
}

#[test]
fn duplicates_and_out_of_range() {
    let input = token("rfc9901-s5.1-sd-jwt.txt");
    let parsed = parse(&input).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    let sel = select(sd, &[2, 2, 2]).unwrap();
    assert_eq!(
        sel.findings,
        [
            SelectionFinding::Duplicate { disclosure: 2 },
            SelectionFinding::Duplicate { disclosure: 2 }
        ]
    );
    assert_eq!(sel.kept, [2, 2, 2]);
    let out = present(sd, &[2, 2], None, &mut rng(3)).unwrap();
    assert_eq!(
        split_sd(&out.token).1.len(),
        2,
        "duplicates are sent as asked"
    );
    assert_eq!(
        select(sd, &[10]).unwrap_err(),
        JoseError::NoSuchDisclosure(10)
    );
    assert_eq!(
        present(sd, &[0, 99], None, &mut rng(3)).unwrap_err(),
        JoseError::NoSuchDisclosure(99)
    );
}

#[test]
fn unreachable_disclosure() {
    let input = token("rfc9901-s5.1-sd-jwt.txt");
    let foreign = common::b64e(br#"["salt","stranger",1]"#);
    let with_foreign = format!("{input}{foreign}~");
    let parsed = parse(&with_foreign).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    assert_eq!(sd.disclosures.len(), 11);
    let sel = select(sd, &[10]).unwrap();
    assert_eq!(
        sel.findings,
        [SelectionFinding::Unreachable { disclosure: 10 }]
    );
}

#[test]
fn empty_selection_and_existing_kb_is_dropped() {
    let input = token("rfc9901-s5.2-sd-jwt-kb.txt");
    let parsed = parse(&input).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    let out = present(sd, &[], None, &mut rng(3)).unwrap();
    let (jwt, _, _) = split_sd(&input);
    assert_eq!(out.token, format!("{jwt}~"));
}

#[test]
fn json_serialization_stays_json() {
    let input = raw("rfc9901-s8.2-sd-jwt-json-flattened.json");
    let parsed = parse(&input).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    let holder = holder_key(Alg::ES256);
    let kb = KbOptions::new(
        &holder,
        Alg::ES256,
        RFC9901_AUD,
        RFC9901_NONCE,
        RFC9901_KB_IAT,
    );
    let out = present(sd, &[2, 1], Some(&kb), &mut rng(3)).unwrap();
    let reparsed = parse(&out.token).unwrap();
    let Token::SdJwt(sd2) = &reparsed.token else {
        panic!("not an SD-JWT")
    };
    assert_eq!(sd2.issuer.serialization, Serialization::JsonFlattened);
    assert_eq!(sd2.issuer.payload.text(), sd.issuer.payload.text());
    assert_eq!(
        sd2.issuer.signatures[0].signature.text(),
        sd.issuer.signatures[0].signature.text()
    );
    let texts: Vec<&str> = sd2.disclosures.iter().map(|d| d.text()).collect();
    assert_eq!(texts, [sd.disclosures[2].text(), sd.disclosures[1].text()]);
    let report = check_kb_jwt(sd2, &[], &expect()).unwrap();
    assert_eq!(report.sd_hash, ValueCheck::Match);
    assert_eq!(report.aud, ValueCheck::Match);
    let header = sd2.issuer.signatures[0].unprotected.as_ref().unwrap();
    assert!(str_of(header, "/kb_jwt").contains('.'));
}

#[test]
fn json_general_keeps_other_signatures() {
    let input = raw("rfc9901-s8.3-sd-jwt-kb-json-general.json");
    let parsed = parse(&input).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    let out = present(sd, &[0], None, &mut rng(3)).unwrap();
    let reparsed = parse(&out.token).unwrap();
    let sd2 = reparsed.token.sd_jwt().unwrap();
    assert_eq!(sd2.issuer.serialization, Serialization::JsonGeneral);
    assert_eq!(sd2.issuer.signatures.len(), 2);
    assert!(sd2.kb_jwt.is_none(), "the old KB-JWT is dropped");
    assert_eq!(sd2.disclosures.len(), 1);
    assert_eq!(
        str_of(
            sd2.issuer.signatures[0].unprotected.as_ref().unwrap(),
            "/kid"
        ),
        "issuer-key-1"
    );
    assert_eq!(
        str_of(
            sd2.issuer.signatures[1].unprotected.as_ref().unwrap(),
            "/kid"
        ),
        "issuer-key-2"
    );
}

#[test]
fn present_needs_a_private_holder_key() {
    let input = token("rfc9901-s5.1-sd-jwt.txt");
    let parsed = parse(&input).unwrap();
    let public = common::rfc9901_holder();
    let kb = KbOptions::new(&public, Alg::ES256, "a", "n", 0);
    assert_eq!(
        present(parsed.token.sd_jwt().unwrap(), &[0], Some(&kb), &mut rng(3)).unwrap_err(),
        JoseError::NoPrivateKey
    );
}

#[test]
fn unsupported_sd_alg_blocks_the_kb_jwt_only() {
    // A payload whose `_sd_alg` is unknown: disclosing works, sd_hash can't.
    let key = issuer_key(Alg::ES256);
    let claims = json(r#"{"_sd_alg":"md5","a":1}"#);
    let mut opts = IssueOptions::new(&key, Alg::ES256);
    opts.sd_alg = None;
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    let as_sd = format!("{}~", issued.token);
    let parsed = parse(&as_sd).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    assert!(present(sd, &[], None, &mut rng(3)).is_ok());
    let holder = holder_key(Alg::ES256);
    let kb = KbOptions::new(&holder, Alg::ES256, "a", "n", 0);
    assert_eq!(
        present(sd, &[], Some(&kb), &mut rng(3)).unwrap_err(),
        JoseError::UnsupportedSdAlg(Some("md5".into()))
    );
}
