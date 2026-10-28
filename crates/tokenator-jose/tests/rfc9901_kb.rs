//! KB-JWT checks on the RFC 9901 presentations.

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{
    RFC9901_AUD, RFC9901_KB_IAT, RFC9901_NONCE, raw, rfc9901_holder, sha256_b64, split_sd, token,
};
use tokenator_crypto::Alg;
use tokenator_jose::{
    HolderKey, KbExpectations, KbReport, TimeStatus, ValueCheck, check_kb_jwt, parse,
};

fn expect(now: i64) -> KbExpectations<'static> {
    KbExpectations {
        aud: Some(RFC9901_AUD),
        nonce: Some(RFC9901_NONCE),
        now,
        skew: 60,
        max_age: Some(300),
    }
}

fn all_good() -> KbReport {
    KbReport {
        holder_key: HolderKey::CnfJwk,
        signature: Ok(Alg::ES256),
        typ: ValueCheck::Match,
        sd_hash: ValueCheck::Match,
        aud: ValueCheck::Match,
        nonce: ValueCheck::Match,
        iat: TimeStatus::Valid,
    }
}

const PRESENTATIONS: [&str; 5] = [
    "rfc9901-s5.2-sd-jwt-kb.txt",
    "rfc9901-a3-sd-jwt-kb.txt",
    "rfc9901-a4-sd-jwt-kb.txt",
    "rfc9901-s8.2-sd-jwt-kb-json-flattened.json",
    "rfc9901-s8.3-sd-jwt-kb-json-general.json",
];

#[test]
fn every_rfc_kb_jwt_passes() {
    for name in PRESENTATIONS {
        let input = raw(name);
        let parsed = parse(&input).unwrap();
        let sd = parsed.token.sd_jwt().unwrap();
        let report = check_kb_jwt(sd, &[], &expect(RFC9901_KB_IAT + 5)).unwrap();
        assert_eq!(report, all_good(), "{name}");
    }
}

#[test]
fn sd_hash_is_over_the_presented_sd_jwt() {
    let input = token("rfc9901-s5.2-sd-jwt-kb.txt");
    let (_, _, kb) = split_sd(&input);
    let presented = &input[..input.len() - kb.len()];
    assert_eq!(
        sha256_b64(presented),
        "0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY"
    );
    let parsed = parse(&input).unwrap();
    assert_eq!(
        parsed.token.sd_jwt().unwrap().sd_hash_input().unwrap(),
        presented
    );
}

#[test]
fn no_kb_jwt_gives_none() {
    for name in ["rfc9901-s5.1-sd-jwt.txt", "rfc9901-a1-presentation.txt"] {
        let input = token(name);
        let parsed = parse(&input).unwrap();
        assert!(
            check_kb_jwt(parsed.token.sd_jwt().unwrap(), &[], &expect(0)).is_none(),
            "{name}"
        );
    }
    let input = raw("rfc9901-s8.2-sd-jwt-json-flattened.json");
    let parsed = parse(&input).unwrap();
    assert!(check_kb_jwt(parsed.token.sd_jwt().unwrap(), &[], &expect(0)).is_none());
}

#[test]
fn wrong_audience_and_nonce() {
    let input = token("rfc9901-s5.2-sd-jwt-kb.txt");
    let parsed = parse(&input).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    let exp = KbExpectations {
        aud: Some("https://other.example"),
        nonce: Some("nope"),
        ..expect(RFC9901_KB_IAT)
    };
    let report = check_kb_jwt(sd, &[], &exp).unwrap();
    assert_eq!(
        report.aud,
        ValueCheck::Mismatch {
            expected: "https://other.example".into(),
            found: RFC9901_AUD.into()
        }
    );
    assert_eq!(
        report.nonce,
        ValueCheck::Mismatch {
            expected: "nope".into(),
            found: RFC9901_NONCE.into()
        }
    );
    // Everything else still passes.
    assert_eq!(report.signature, Ok(Alg::ES256));
    assert_eq!(report.sd_hash, ValueCheck::Match);
}

#[test]
fn unchecked_values_are_reported() {
    let input = token("rfc9901-a3-sd-jwt-kb.txt");
    let parsed = parse(&input).unwrap();
    let exp = KbExpectations {
        aud: None,
        nonce: None,
        ..expect(RFC9901_KB_IAT)
    };
    let report = check_kb_jwt(parsed.token.sd_jwt().unwrap(), &[], &exp).unwrap();
    assert_eq!(report.aud, ValueCheck::Unchecked(RFC9901_AUD.into()));
    assert_eq!(report.nonce, ValueCheck::Unchecked(RFC9901_NONCE.into()));
}

#[test]
fn iat_freshness() {
    let input = token("rfc9901-a4-sd-jwt-kb.txt");
    let parsed = parse(&input).unwrap();
    let sd = parsed.token.sd_jwt().unwrap();
    let iat_at = |now: i64, max_age: Option<u64>| {
        check_kb_jwt(
            sd,
            &[],
            &KbExpectations {
                max_age,
                ..expect(now)
            },
        )
        .unwrap()
        .iat
    };
    assert_eq!(iat_at(RFC9901_KB_IAT, Some(300)), TimeStatus::Valid);
    assert_eq!(
        iat_at(RFC9901_KB_IAT + 360, Some(300)),
        TimeStatus::Valid,
        "max_age + skew"
    );
    assert_eq!(iat_at(RFC9901_KB_IAT + 361, Some(300)), TimeStatus::TooOld);
    assert_eq!(
        iat_at(RFC9901_KB_IAT + 1_000_000, None),
        TimeStatus::Valid,
        "no max age"
    );
    assert_eq!(
        iat_at(RFC9901_KB_IAT - 60, Some(300)),
        TimeStatus::Valid,
        "within skew"
    );
    assert_eq!(iat_at(RFC9901_KB_IAT - 61, Some(300)), TimeStatus::InFuture);
}

#[test]
fn candidates_are_ignored_when_cnf_has_a_jwk() {
    let input = token("rfc9901-s5.2-sd-jwt-kb.txt");
    let parsed = parse(&input).unwrap();
    let wrong = common::holder_key(Alg::ES256);
    let report = check_kb_jwt(
        parsed.token.sd_jwt().unwrap(),
        &[wrong, rfc9901_holder()],
        &expect(RFC9901_KB_IAT),
    )
    .unwrap();
    assert_eq!(report.holder_key, HolderKey::CnfJwk);
    assert_eq!(report.signature, Ok(Alg::ES256));
}

#[test]
fn removing_a_disclosure_breaks_sd_hash_only() {
    let input = token("rfc9901-s5.2-sd-jwt-kb.txt");
    let (jwt, discs, kb) = split_sd(&input);
    let fewer = format!("{jwt}~{}~{}~{kb}", discs[0], discs[1]);
    let parsed = parse(&fewer).unwrap();
    let report =
        check_kb_jwt(parsed.token.sd_jwt().unwrap(), &[], &expect(RFC9901_KB_IAT)).unwrap();
    let computed = sha256_b64(&format!("{jwt}~{}~{}~", discs[0], discs[1]));
    assert_eq!(
        report.sd_hash,
        ValueCheck::Mismatch {
            expected: computed,
            found: "0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY".into()
        }
    );
    assert_eq!(report.signature, Ok(Alg::ES256));
}
