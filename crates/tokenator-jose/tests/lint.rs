//! Facts for the core's linter.

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{RFC9901_HOLDER_JWK, issuer_key, json, jwk_key, token};
use tokenator_crypto::{Alg, Curve, KeyMismatch, KeyType};
use tokenator_jose::{
    AlgFact, CnfFact, CritFact, HeaderFacts, StrFact, cnf, duplicate_members, header_facts,
    jwk_findings, key_findings, parse,
};
use tokenator_keys::{DeclaredAlg, Jwk};

#[test]
fn rfc_headers() {
    let t = token("rfc7515-a1-jws-hs256.txt");
    let parsed = parse(&t).unwrap();
    let h = parsed.token.jws().header(0).unwrap().unwrap();
    assert_eq!(
        header_facts(&h),
        HeaderFacts {
            alg: AlgFact::Unsupported("HS256".into()),
            typ: StrFact::Value("JWT".into()),
            cty: StrFact::Absent,
            kid: StrFact::Absent,
            crit: CritFact::Absent,
        }
    );
    let t = token("rfc9901-s5.2-sd-jwt-kb.txt");
    let parsed = parse(&t).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    let f = header_facts(&sd.issuer.header(0).unwrap().unwrap());
    assert_eq!(f.alg, AlgFact::Known(Alg::ES256));
    assert_eq!(f.typ, StrFact::Value("example+sd-jwt".into()));
    let kb = sd.kb_jwt.as_ref().unwrap();
    assert_eq!(
        header_facts(&kb.header(0).unwrap().unwrap()).typ,
        StrFact::Value("kb+jwt".into())
    );
}

#[test]
fn alg_facts() {
    for (h, fact) in [
        ("{}", AlgFact::Missing),
        (r#"{"alg":1}"#, AlgFact::NotAString),
        (r#"{"alg":"none"}"#, AlgFact::None),
        (r#"{"alg":"ML-DSA-65"}"#, AlgFact::Known(Alg::MlDsa65)),
        (r#"{"alg":"Ed25519"}"#, AlgFact::Known(Alg::Ed25519)),
        (r#"{"alg":"es256"}"#, AlgFact::Unsupported("es256".into())),
        ("[1]", AlgFact::Missing),
    ] {
        assert_eq!(header_facts(&json(h)).alg, fact, "{h}");
    }
}

#[test]
fn string_facts() {
    let f = header_facts(&json(r#"{"alg":"ES256","typ":5,"cty":"JWT","kid":"k"}"#));
    assert_eq!(f.typ, StrFact::NotAString);
    assert_eq!(f.cty, StrFact::Value("JWT".into()));
    assert_eq!(f.kid, StrFact::Value("k".into()));
}

#[test]
fn crit_facts() {
    let crit = |h: &str| header_facts(&json(h)).crit;
    assert_eq!(crit(r#"{"crit":"exp"}"#), CritFact::Malformed);
    assert_eq!(crit(r#"{"crit":["exp",1]}"#), CritFact::Malformed);
    assert_eq!(crit(r#"{"crit":[]}"#), CritFact::Empty);
    assert_eq!(
        crit(r#"{"alg":"ES256","b64":false,"crit":["b64","exp","alg"]}"#),
        CritFact::Entries {
            not_understood: vec!["b64".into(), "exp".into()],
            registered: vec!["alg".into()],
            missing: vec!["exp".into()],
        }
    );
}

#[test]
fn duplicate_members_everywhere() {
    let text = r#"{"a":1,"o":{"x":1,"x":2,"x":3},"a":2,"arr":[{"k":0,"k":0}]}"#;
    let node = json(text);
    let d = duplicate_members(&node);
    let summary: Vec<(&str, &str, usize)> = d
        .iter()
        .map(|m| (m.pointer.as_str(), m.name.as_str(), m.spans.len()))
        .collect();
    assert_eq!(summary, [("", "a", 2), ("/o", "x", 3), ("/arr/0", "k", 2)]);
    let s = d[0].spans[1];
    assert_eq!(&text[s.start..s.end], r#""a""#);
    assert!(duplicate_members(&json(r#"{"a":{"a":1}}"#)).is_empty());
}

#[test]
fn duplicate_header_members_survive_decoding() {
    let h = common::b64e(br#"{"alg":"none","alg":"ES256"}"#);
    let t = format!("{h}.e30.");
    let parsed = parse(&t).unwrap();
    let header = parsed.token.jws().header(0).unwrap().unwrap();
    assert_eq!(duplicate_members(&header).len(), 1);
    assert_eq!(header_facts(&header).alg, AlgFact::None, "the first wins");
}

#[test]
fn cnf_facts() {
    let jwk = format!(r#"{{"cnf":{{"jwk":{RFC9901_HOLDER_JWK},"kid":"x"}}}}"#);
    assert!(matches!(cnf(&json(&jwk)), CnfFact::Jwk(j) if j.get_str("crv") == Some("P-256")));
    assert!(matches!(cnf(&json(r#"{"cnf":{"kid":"h1"}}"#)), CnfFact::Kid(k) if k == "h1"));
    assert!(
        matches!(cnf(&json(r#"{"cnf":{"jkt":"t","jku":"u"}}"#)), CnfFact::Other(v) if v == ["jkt", "jku"])
    );
    assert!(matches!(cnf(&json(r#"{"cnf":[1]}"#)), CnfFact::NotAnObject));
    assert!(matches!(cnf(&json("{}")), CnfFact::Absent));
}

#[test]
fn key_and_jwk_findings() {
    let es = issuer_key(Alg::ES256);
    assert!(key_findings(Alg::ES256, &es).is_empty());
    assert_eq!(
        key_findings(Alg::ES384, &es),
        [KeyMismatch::Curve {
            expected: Curve::P384,
            found: Some(Curve::P256)
        }]
    );
    assert!(matches!(
        key_findings(Alg::EdDSA, &es).as_slice(),
        [KeyMismatch::KeyType {
            expected: KeyType::Okp,
            found: KeyType::Ec
        }]
    ));
    let mut declared = es.clone();
    declared.alg = Some(DeclaredAlg::Known(Alg::ES384));
    assert_eq!(
        key_findings(Alg::ES256, &declared),
        [KeyMismatch::DeclaredAlg {
            alg: Alg::ES256,
            declared: DeclaredAlg::Known(Alg::ES384)
        }]
    );

    let holder = Jwk::parse(RFC9901_HOLDER_JWK.as_bytes()).unwrap();
    assert!(jwk_findings(Alg::ES256, &holder).unwrap().is_empty());
    assert_eq!(jwk_findings(Alg::ES512, &holder).unwrap().len(), 1);
    // Without valid key material (x and y missing).
    let partial = Jwk::parse(br#"{"kty":"EC","crv":"P-256","alg":"ES384"}"#).unwrap();
    assert_eq!(
        jwk_findings(Alg::ES256, &partial).unwrap(),
        [KeyMismatch::DeclaredAlg {
            alg: Alg::ES256,
            declared: DeclaredAlg::Known(Alg::ES384)
        }]
    );
    assert!(jwk_findings(Alg::ES256, &Jwk::parse(br#"{"kty":"oct"}"#).unwrap()).is_err());
    let _ = jwk_key(RFC9901_HOLDER_JWK);
}
