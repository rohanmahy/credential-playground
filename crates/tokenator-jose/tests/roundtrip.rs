//! issue → present → verify for every algorithm, issuer and holder keys
//! from tokenator-keys.

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{assert_json_text, holder_key, issuer_key, json, public_jwk, rng, split_sd};
use tokenator_crypto::{Alg, CryptoError};
use tokenator_jose::{
    Cnf, DecoyDigests, DecoySpec, HolderKey, IssueOptions, KbExpectations, KbOptions, KbReport,
    SdFinding, TimeStatus, Token, ValueCheck, VerifyError, check_kb_jwt, issue, parse, present,
    verify_signature,
};
use tokenator_keys::to_public;

const CLAIMS: &str = r#"{"iss":"https://issuer.example","iat":1700000000,"exp":1900000000,"sub":"alice","given_name":"Alice","address":{"street":"1 Main St","city":"Springfield"},"nationalities":["DE","FR"]}"#;

const NOW: i64 = 1_800_000_000;

fn expectations() -> KbExpectations<'static> {
    KbExpectations {
        aud: Some("https://verifier"),
        nonce: Some("n-0S6"),
        now: NOW,
        skew: 60,
        max_age: Some(300),
    }
}

fn sd_round_trip(alg: Alg, holder_alg: Alg) {
    let issuer = issuer_key(alg);
    let holder = holder_key(holder_alg);
    let claims = json(CLAIMS);
    let mut opts = IssueOptions::new(&issuer, alg);
    opts.typ = Some("example+sd-jwt".into());
    opts.cnf = Some(Cnf::Jwk(public_jwk(&holder)));
    opts.sd = vec![
        "/given_name".into(),
        "/address".into(),
        "/address/street".into(),
        "/nationalities/1".into(),
    ];
    opts.decoys = vec![DecoySpec {
        at: String::new(),
        digests: DecoyDigests::Random(2),
    }];
    let issued = issue(&claims, &opts, &mut rng(11)).unwrap_or_else(|e| panic!("{alg:?}: {e:?}"));
    assert_eq!(issued.disclosures.len(), 4, "{alg:?}");

    // The holder checks what was issued.
    let parsed = parse(&issued.token).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    assert_eq!(
        verify_signature(&sd.issuer, 0, &to_public(&issuer)),
        Ok(alg),
        "{alg:?}"
    );
    let processed = sd.process().unwrap();
    let decoys = processed
        .report
        .findings
        .iter()
        .filter(|f| matches!(f, SdFinding::DigestWithoutDisclosure { .. }))
        .count();
    assert_eq!(decoys, 2, "{alg:?}: only the decoys lack disclosures");
    assert_eq!(
        processed.report.findings.len(),
        2,
        "{alg:?}: {:?}",
        processed.report.findings
    );
    assert_eq!(
        common::str_of(&processed.claims, "/address/street"),
        "1 Main St"
    );
    assert_eq!(common::str_of(&processed.claims, "/nationalities/1"), "FR");
    assert!(processed.claims.get("cnf").is_some());

    // Present given_name, address (without street), and FR.
    let pos = |p: &str| {
        issued
            .disclosures
            .iter()
            .position(|d| d.pointer == p)
            .unwrap()
    };
    let keep = [pos("/given_name"), pos("/address"), pos("/nationalities/1")];
    let kb = KbOptions::new(&holder, holder_alg, "https://verifier", "n-0S6", NOW - 10);
    let presented = present(sd, &keep, Some(&kb), &mut rng(12)).unwrap();
    assert!(presented.selection.findings.is_empty(), "{alg:?}");

    // The verifier.
    let parsed = parse(&presented.token).unwrap();
    let Token::SdJwt(sd) = &parsed.token else {
        panic!("not an SD-JWT")
    };
    assert_eq!(
        verify_signature(&sd.issuer, 0, &to_public(&issuer)),
        Ok(alg),
        "{alg:?}"
    );
    let processed = sd.process().unwrap();
    assert!(
        processed
            .report
            .findings
            .iter()
            .all(|f| matches!(f, SdFinding::DigestWithoutDisclosure { .. }))
    );
    // Plain claims keep their order; the two disclosed top-level claims are
    // appended in (random, salt-dependent) digest order.
    let names: Vec<&str> = processed
        .claims
        .members()
        .unwrap()
        .iter()
        .map(|m| m.key().as_ref())
        .collect();
    assert_eq!(
        names[..6],
        ["iss", "iat", "exp", "sub", "nationalities", "cnf"],
        "{alg:?}"
    );
    let mut disclosed = names[6..].to_vec();
    disclosed.sort_unstable();
    assert_eq!(disclosed, ["address", "given_name"], "{alg:?}");
    assert_json_text(
        processed.claims.get("address").unwrap(),
        r#"{"city":"Springfield"}"#,
    );
    assert_json_text(
        processed.claims.get("nationalities").unwrap(),
        r#"["DE","FR"]"#,
    );
    assert_json_text(
        processed.claims.pointer("/cnf/jwk").unwrap(),
        &public_jwk(&holder).to_json(),
    );
    let report = check_kb_jwt(sd, &[], &expectations()).unwrap();
    assert_eq!(
        report,
        KbReport {
            holder_key: HolderKey::CnfJwk,
            signature: Ok(holder_alg),
            typ: ValueCheck::Match,
            sd_hash: ValueCheck::Match,
            aud: ValueCheck::Match,
            nonce: ValueCheck::Match,
            iat: TimeStatus::Valid,
        },
        "{alg:?} / {holder_alg:?}"
    );
}

macro_rules! round_trips {
    ($($name:ident: $alg:expr, $holder:expr;)*) => {$(
        #[test]
        fn $name() {
            sd_round_trip($alg, $holder);
        }
    )*};
}

round_trips! {
    es256: Alg::ES256, Alg::ES256;
    es384: Alg::ES384, Alg::ES256;
    es512: Alg::ES512, Alg::ES384;
    eddsa: Alg::EdDSA, Alg::EdDSA;
    ed25519: Alg::Ed25519, Alg::Ed25519;
    rs256: Alg::RS256, Alg::ES256;
    rs384: Alg::RS384, Alg::RS256;
    rs512: Alg::RS512, Alg::ES256;
    ps256: Alg::PS256, Alg::PS256;
    ps384: Alg::PS384, Alg::ES256;
    ps512: Alg::PS512, Alg::ES512;
    ml_dsa_44: Alg::MlDsa44, Alg::MlDsa44;
    ml_dsa_65: Alg::MlDsa65, Alg::ES256;
    ml_dsa_87: Alg::MlDsa87, Alg::MlDsa65;
}

#[test]
fn plain_jwt_for_every_alg() {
    for alg in Alg::ALL {
        let key = issuer_key(alg);
        let claims = json(CLAIMS);
        let issued = issue(&claims, &IssueOptions::new(&key, alg), &mut rng(1)).unwrap();
        assert!(!issued.token.contains('~'), "{alg:?}");
        assert!(issued.disclosures.is_empty());
        assert_eq!(issued.token.matches('.').count(), 2);
        let parsed = parse(&issued.token).unwrap();
        assert!(matches!(parsed.token, Token::Jws(_)));
        assert_eq!(
            verify_signature(parsed.token.jws(), 0, &key),
            Ok(alg),
            "{alg:?}"
        );
        let payload = parsed.token.jws().claims().unwrap();
        assert_json_text(&payload, CLAIMS);
        assert!(
            payload.get("_sd_alg").is_none(),
            "{alg:?}: no _sd_alg in a plain JWT"
        );
        let other = holder_key(alg);
        assert_eq!(
            verify_signature(parsed.token.jws(), 0, &other),
            Err(VerifyError::Crypto(CryptoError::InvalidSignature)),
            "{alg:?}"
        );
    }
}

#[test]
fn same_seed_same_token_different_seed_different_salts() {
    let key = issuer_key(Alg::ES256);
    let claims = json(CLAIMS);
    let mut opts = IssueOptions::new(&key, Alg::ES256);
    opts.sd = vec!["/sub".into()];
    let a = issue(&claims, &opts, &mut rng(5)).unwrap();
    let b = issue(&claims, &opts, &mut rng(5)).unwrap();
    let c = issue(&claims, &opts, &mut rng(6)).unwrap();
    assert_eq!(a, b);
    assert_ne!(a.disclosures[0].text, c.disclosures[0].text);
}

#[test]
fn kb_with_cnf_kid_and_candidates() {
    let issuer = issuer_key(Alg::ES256);
    let holder = common::with_kid(holder_key(Alg::Ed25519), "holder-1");
    let decoy_holder = common::with_kid(holder_key(Alg::ES256), "someone-else");
    let claims = json(CLAIMS);
    let mut opts = IssueOptions::new(&issuer, Alg::ES256);
    opts.cnf = Some(Cnf::Kid("holder-1".into()));
    opts.sd = vec!["/sub".into()];
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    let parsed = parse(&issued.token).unwrap();
    let kb = KbOptions::new(&holder, Alg::Ed25519, "https://verifier", "n-0S6", NOW);
    let presented = present(parsed.token.sd_jwt().unwrap(), &[0], Some(&kb), &mut rng(2)).unwrap();
    let parsed = parse(&presented.token).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    assert_eq!(
        common::str_of(&sd.issuer.claims().unwrap(), "/cnf/kid"),
        "holder-1"
    );

    let candidates = [decoy_holder.clone(), to_public(&holder)];
    let report = check_kb_jwt(sd, &candidates, &expectations()).unwrap();
    assert_eq!(
        report.holder_key,
        HolderKey::CnfKid {
            kid: "holder-1".into(),
            candidate: 1
        }
    );
    assert_eq!(report.signature, Ok(Alg::Ed25519));

    let report = check_kb_jwt(sd, &[decoy_holder], &expectations()).unwrap();
    assert_eq!(
        report.holder_key,
        HolderKey::CnfKidUnmatched("holder-1".into())
    );
    assert_eq!(report.signature, Err(VerifyError::NoKey));
    assert_eq!(report.sd_hash, ValueCheck::Match, "other checks still run");
}

#[test]
fn kb_without_usable_cnf() {
    let issuer = issuer_key(Alg::ES256);
    let holder = holder_key(Alg::ES256);
    for (claims_text, expected) in [
        (r#"{"sub":"a"}"#, HolderKey::NoCnf(vec![])),
        (
            r#"{"sub":"a","cnf":{"jkt":"abc","jku":"https://x"}}"#,
            HolderKey::NoCnf(vec!["jkt".into(), "jku".into()]),
        ),
    ] {
        let claims = json(claims_text);
        let mut opts = IssueOptions::new(&issuer, Alg::ES256);
        opts.sd = vec!["/sub".into()];
        let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
        let parsed = parse(&issued.token).unwrap();
        let kb = KbOptions::new(&holder, Alg::ES256, "https://verifier", "n-0S6", NOW);
        let presented =
            present(parsed.token.sd_jwt().unwrap(), &[0], Some(&kb), &mut rng(2)).unwrap();
        let parsed = parse(&presented.token).unwrap();
        let report = check_kb_jwt(
            parsed.token.sd_jwt().unwrap(),
            &[to_public(&holder)],
            &expectations(),
        )
        .unwrap();
        assert_eq!(report.holder_key, expected, "{claims_text}");
        assert_eq!(report.signature, Err(VerifyError::NoKey));
    }
}

#[test]
fn kb_with_invalid_cnf_jwk() {
    let issuer = issuer_key(Alg::ES256);
    let holder = holder_key(Alg::ES256);
    let claims = json(r#"{"sub":"a","cnf":{"jwk":{"kty":"EC","crv":"P-256"}}}"#);
    let mut opts = IssueOptions::new(&issuer, Alg::ES256);
    opts.sd = vec!["/sub".into()];
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    let parsed = parse(&issued.token).unwrap();
    let kb = KbOptions::new(&holder, Alg::ES256, "https://verifier", "n-0S6", NOW);
    let presented = present(parsed.token.sd_jwt().unwrap(), &[0], Some(&kb), &mut rng(2)).unwrap();
    let parsed = parse(&presented.token).unwrap();
    let report = check_kb_jwt(parsed.token.sd_jwt().unwrap(), &[], &expectations()).unwrap();
    assert!(
        matches!(report.holder_key, HolderKey::CnfJwkInvalid(_)),
        "{:?}",
        report.holder_key
    );
    assert_eq!(report.signature, Err(VerifyError::NoKey));
}

#[test]
fn kb_signed_with_the_wrong_holder_key() {
    let issuer = issuer_key(Alg::ES256);
    let holder = holder_key(Alg::ES256);
    let thief = issuer_key(Alg::ES256);
    let claims = json(CLAIMS);
    let mut opts = IssueOptions::new(&issuer, Alg::ES256);
    opts.cnf = Some(Cnf::Jwk(public_jwk(&holder)));
    opts.sd = vec!["/sub".into()];
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    let parsed = parse(&issued.token).unwrap();
    let kb = KbOptions::new(&thief, Alg::ES256, "https://verifier", "n-0S6", NOW);
    let presented = present(parsed.token.sd_jwt().unwrap(), &[0], Some(&kb), &mut rng(2)).unwrap();
    let parsed = parse(&presented.token).unwrap();
    let report = check_kb_jwt(parsed.token.sd_jwt().unwrap(), &[], &expectations()).unwrap();
    assert_eq!(
        report.signature,
        Err(VerifyError::Crypto(CryptoError::InvalidSignature))
    );
}

#[test]
fn kb_payload_problems() {
    // A hand-assembled KB-JWT with a non-string nonce and no aud, iat or
    // sd_hash, properly signed by the holder.
    let issuer = issuer_key(Alg::ES256);
    let holder = holder_key(Alg::ES256);
    let claims = json(CLAIMS);
    let mut opts = IssueOptions::new(&issuer, Alg::ES256);
    opts.cnf = Some(Cnf::Jwk(public_jwk(&holder)));
    opts.sd = vec!["/sub".into()];
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    let h = common::b64e(br#"{"alg":"ES256","typ":"kb+jwt"}"#);
    let p = common::b64e(br#"{"nonce":42}"#);
    let sig = tokenator_crypto::sign_deterministic(
        Alg::ES256,
        holder.private_key().unwrap(),
        format!("{h}.{p}").as_bytes(),
    )
    .unwrap();
    let token = format!("{}{h}.{p}.{}", issued.token, common::b64e(&sig));
    let parsed = parse(&token).unwrap();
    let report = check_kb_jwt(parsed.token.sd_jwt().unwrap(), &[], &expectations()).unwrap();
    assert_eq!(report.signature, Ok(Alg::ES256));
    assert_eq!(report.nonce, ValueCheck::NotAString);
    assert_eq!(report.aud, ValueCheck::Missing);
    assert_eq!(report.sd_hash, ValueCheck::Missing);
    assert_eq!(report.iat, TimeStatus::Absent);
    let (_, discs, _) = split_sd(&token);
    assert_eq!(discs.len(), 1);
}
