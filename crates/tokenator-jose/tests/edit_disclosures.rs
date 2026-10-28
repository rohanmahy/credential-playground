//! Editing disclosures and digests (never re-signs).

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{
    b64d, b64e, raw, rfc9901_issuer, rng, segment_json, segments, sha256_b64, split_sd, token,
};
use tokenator_crypto::{Alg, CryptoError};
use tokenator_jose::{
    DisclosureOp, JoseError, JsonStyle, SdFinding, SdReport, Serialization, VerifyError,
    edit_disclosures, parse, verify_signature,
};
use tokenator_json::{Node, Value};

fn edit(input: &str, ops: &[DisclosureOp]) -> Result<String, JoseError> {
    let parsed = parse(input).unwrap();
    edit_disclosures(
        parsed.token.sd_jwt().unwrap(),
        ops,
        JsonStyle::Compact,
        &mut rng(7),
    )
}

fn report(t: &str) -> SdReport {
    let parsed = parse(t).unwrap();
    parsed.token.sd_jwt().unwrap().process().unwrap().report
}

fn issuer_ok(t: &str) -> Result<Alg, VerifyError> {
    let parsed = parse(t).unwrap();
    verify_signature(parsed.token.jws(), 0, &rfc9901_issuer())
}

fn count(r: &SdReport, f: impl Fn(&SdFinding) -> bool) -> usize {
    r.findings.iter().filter(|x| f(x)).count()
}

const SD: &str = "rfc9901-s5.1-sd-jwt.txt";

#[test]
fn remove() {
    let input = token(SD);
    let out = edit(&input, &[DisclosureOp::Remove(0)]).unwrap();
    let (jwt, discs, kb) = split_sd(&out);
    assert_eq!(jwt, split_sd(&input).0);
    assert_eq!(discs, split_sd(&input).1[1..]);
    assert_eq!(kb, "");
    assert_eq!(issuer_ok(&out), Ok(Alg::ES256));
    let r = report(&out);
    assert_eq!(
        count(&r, |f| matches!(
            f,
            SdFinding::DigestWithoutDisclosure { .. }
        )),
        1
    );
    assert_eq!(
        edit(&input, &[DisclosureOp::Remove(10)]).unwrap_err(),
        JoseError::NoSuchDisclosure(10)
    );
}

#[test]
fn append_and_forge_are_unmatched() {
    let input = token(SD);
    let foreign = b64e(br#"["x","stranger",true]"#);
    let out = edit(
        &input,
        &[
            DisclosureOp::Append(foreign.clone()),
            DisclosureOp::Forge {
                salt: Some("fixed".into()),
                name: Some("admin".into()),
                value: Node::new(Value::Bool(true)),
            },
            DisclosureOp::Forge {
                salt: None,
                name: None,
                value: Node::new(Value::Null),
            },
        ],
    )
    .unwrap();
    let (_, discs, _) = split_sd(&out);
    assert_eq!(discs.len(), 13);
    assert_eq!(discs[10], foreign);
    assert_eq!(
        String::from_utf8(b64d(discs[11])).unwrap(),
        r#"["fixed","admin",true]"#
    );
    let last = String::from_utf8(b64d(discs[12])).unwrap();
    assert!(
        last.starts_with("[\"") && last.ends_with("\",null]"),
        "{last}"
    );
    let r = report(&out);
    for i in 10..13 {
        assert!(
            r.findings
                .contains(&SdFinding::UnmatchedDisclosure { disclosure: i })
        );
    }
    assert_eq!(issuer_ok(&out), Ok(Alg::ES256));
}

#[test]
fn forge_uses_the_style() {
    let input = token(SD);
    let parsed = parse(&input).unwrap();
    let out = edit_disclosures(
        parsed.token.sd_jwt().unwrap(),
        &[DisclosureOp::Forge {
            salt: Some("s".into()),
            name: Some("n".into()),
            value: Node::new(Value::String("é".into())),
        }],
        JsonStyle::Spaced { ascii_only: true },
        &mut rng(7),
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(b64d(split_sd(&out).1[10])).unwrap(),
        r#"["s", "n", "é"]"#
    );
}

#[test]
fn reorder_with_repeats_and_omissions() {
    let input = token(SD);
    let orig = split_sd(&input).1;
    let out = edit(&input, &[DisclosureOp::Reorder(vec![9, 0, 0])]).unwrap();
    assert_eq!(split_sd(&out).1, [orig[9], orig[0], orig[0]]);
    let r = report(&out);
    assert!(r.findings.contains(&SdFinding::DuplicateDisclosure {
        disclosures: vec![1, 2]
    }));
    assert_eq!(
        edit(&input, &[DisclosureOp::Reorder(vec![11])]).unwrap_err(),
        JoseError::NoSuchDisclosure(11)
    );
}

#[test]
fn replace_value_keeps_salt_and_name() {
    let input = token(SD);
    let out = edit(
        &input,
        &[DisclosureOp::ReplaceValue {
            index: 0,
            value: Node::new(Value::String("Jane".into())),
        }],
    )
    .unwrap();
    let new = split_sd(&out).1[0].to_owned();
    assert_eq!(
        String::from_utf8(b64d(&new)).unwrap(),
        r#"["2GLC42sKQveCfGfryNRN9w","given_name","Jane"]"#
    );
    let r = report(&out);
    assert!(
        r.findings
            .contains(&SdFinding::UnmatchedDisclosure { disclosure: 0 })
    );
    assert_eq!(
        count(&r, |f| matches!(
            f,
            SdFinding::DigestWithoutDisclosure { .. }
        )),
        1
    );
}

#[test]
fn replace_value_of_an_array_element() {
    let input = token(SD);
    let out = edit(
        &input,
        &[DisclosureOp::ReplaceValue {
            index: 8,
            value: Node::new(Value::String("FR".into())),
        }],
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(b64d(split_sd(&out).1[8])).unwrap(),
        r#"["lklxF5jMYlGTPUovMNIvCA","FR"]"#
    );
}

#[test]
fn add_digest_changes_the_payload_minimally() {
    let input = token(SD);
    let out = edit(
        &input,
        &[DisclosureOp::AddDigest {
            at: String::new(),
            digest: Some("NEWDIGEST".into()),
        }],
    )
    .unwrap();
    let (jwt, discs, _) = split_sd(&out);
    let [h, p, s] = segments(jwt);
    let [h0, p0, s0] = segments(split_sd(&input).0);
    assert_eq!((h, s), (h0, s0), "header and old signature kept");
    let old = segment_json(p0);
    let new = segment_json(p);
    assert_eq!(new.len(), old.len() + r#", "NEWDIGEST""#.len(), "{new}");
    assert!(new.contains(r#""jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4", "NEWDIGEST"]"#));
    assert_eq!(discs, split_sd(&input).1);
    assert_eq!(
        issuer_ok(&out),
        Err(VerifyError::Crypto(CryptoError::InvalidSignature))
    );
    let r = report(&out);
    assert_eq!(
        count(&r, |f| matches!(
            f,
            SdFinding::DigestWithoutDisclosure { .. }
        )),
        1
    );
}

#[test]
fn add_random_digest_to_an_array() {
    let input = token(SD);
    let out = edit(
        &input,
        &[DisclosureOp::AddDigest {
            at: "/nationalities".into(),
            digest: None,
        }],
    )
    .unwrap();
    let r = report(&out);
    assert_eq!(r.digests.len(), 11);
    assert_eq!(r.digests[10].pointer, "/nationalities/2");
    assert_eq!(r.digests[10].digest.len(), 43);
    assert_eq!(
        edit(
            &input,
            &[DisclosureOp::AddDigest {
                at: "/sub".into(),
                digest: None
            }]
        )
        .unwrap_err(),
        JoseError::InvalidDecoyTarget("/sub".into())
    );
    assert_eq!(
        edit(
            &input,
            &[DisclosureOp::AddDigest {
                at: "/nope".into(),
                digest: None
            }]
        )
        .unwrap_err(),
        JoseError::NoSuchClaim("/nope".into())
    );
}

#[test]
fn remove_digest() {
    let input = token(SD);
    let given = sha256_b64(split_sd(&input).1[0]);
    let us = sha256_b64(split_sd(&input).1[8]);
    let out = edit(
        &input,
        &[
            DisclosureOp::RemoveDigest(given),
            DisclosureOp::RemoveDigest(us),
        ],
    )
    .unwrap();
    let r = report(&out);
    assert_eq!(r.digests.len(), 8);
    assert!(
        r.findings
            .contains(&SdFinding::UnmatchedDisclosure { disclosure: 0 })
    );
    assert!(
        r.findings
            .contains(&SdFinding::UnmatchedDisclosure { disclosure: 8 })
    );
    assert_eq!(
        issuer_ok(&out),
        Err(VerifyError::Crypto(CryptoError::InvalidSignature))
    );
}

#[test]
fn ops_apply_in_sequence() {
    let input = token(SD);
    let orig = split_sd(&input).1;
    let out = edit(&input, &[DisclosureOp::Remove(0), DisclosureOp::Remove(0)]).unwrap();
    assert_eq!(split_sd(&out).1, orig[2..]);
    assert_eq!(edit(&input, &[]).unwrap(), input);
}

#[test]
fn kb_jwt_is_kept_and_goes_stale() {
    let input = token("rfc9901-s5.2-sd-jwt-kb.txt");
    let out = edit(&input, &[DisclosureOp::Remove(3)]).unwrap();
    assert_eq!(split_sd(&out).2, split_sd(&input).2);
    let parsed = parse(&out).unwrap();
    let exp = tokenator_jose::KbExpectations {
        aud: None,
        nonce: None,
        now: 0,
        skew: 0,
        max_age: None,
    };
    let kb = tokenator_jose::check_kb_jwt(parsed.token.sd_jwt().unwrap(), &[], &exp).unwrap();
    assert!(matches!(
        kb.sd_hash,
        tokenator_jose::ValueCheck::Mismatch { .. }
    ));
}

#[test]
fn json_serialization_stays_json() {
    let input = raw("rfc9901-s8.2-sd-jwt-json-flattened.json");
    let out = edit(&input, &[DisclosureOp::Remove(0)]).unwrap();
    let parsed = parse(&out).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    assert_eq!(sd.issuer.serialization, Serialization::JsonFlattened);
    assert_eq!(sd.disclosures.len(), 3);
    assert_eq!(
        verify_signature(&sd.issuer, 0, &rfc9901_issuer()),
        Ok(Alg::ES256)
    );
}
