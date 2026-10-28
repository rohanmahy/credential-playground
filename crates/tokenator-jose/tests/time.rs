//! Time claims against an injected clock (RFC 7519 §4.1.4-4.1.6).

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{json, token};
use tokenator_jose::{TimeReport, TimeStatus, check_time_claims, parse};

const RFC7519_EXP: i64 = 1300819380;

fn report(claims: &str, now: i64, skew: u64) -> TimeReport {
    check_time_claims(&json(claims), now, skew)
}

#[test]
fn rfc7519_example_exp_boundaries() {
    let input = token("rfc7519-s3.1-jwt-hs256.txt");
    let parsed = parse(&input).unwrap();
    let claims = parsed.token.jws().claims().unwrap();
    let at = |now, skew| check_time_claims(&claims, now, skew);
    assert_eq!(
        at(RFC7519_EXP - 1, 0),
        TimeReport {
            exp: TimeStatus::Valid,
            nbf: TimeStatus::Absent,
            iat: TimeStatus::Absent
        }
    );
    assert_eq!(
        at(RFC7519_EXP, 0).exp,
        TimeStatus::Expired,
        "exp itself is already expired"
    );
    assert_eq!(at(RFC7519_EXP + 59, 60).exp, TimeStatus::Valid);
    assert_eq!(at(RFC7519_EXP + 60, 60).exp, TimeStatus::Expired);
}

#[test]
fn nbf_boundaries() {
    let c = r#"{"nbf": 1000}"#;
    assert_eq!(
        report(c, 1000, 0).nbf,
        TimeStatus::Valid,
        "nbf itself is valid"
    );
    assert_eq!(report(c, 999, 0).nbf, TimeStatus::NotYetValid);
    assert_eq!(report(c, 940, 60).nbf, TimeStatus::Valid);
    assert_eq!(report(c, 939, 60).nbf, TimeStatus::NotYetValid);
}

#[test]
fn iat_in_the_future() {
    let c = r#"{"iat": 1000}"#;
    assert_eq!(report(c, 1000, 0).iat, TimeStatus::Valid);
    assert_eq!(report(c, 999, 0).iat, TimeStatus::InFuture);
    assert_eq!(report(c, 940, 60).iat, TimeStatus::Valid);
    assert_eq!(report(c, 939, 60).iat, TimeStatus::InFuture);
    assert_eq!(
        report(c, 1_000_000, 0).iat,
        TimeStatus::Valid,
        "old iat is fine for a JWT"
    );
}

#[test]
fn fractional_and_exponent_numeric_dates() {
    let c = r#"{"exp": 1000.5, "nbf": 1e3}"#;
    assert_eq!(report(c, 1000, 0).exp, TimeStatus::Valid);
    assert_eq!(report(c, 1001, 0).exp, TimeStatus::Expired);
    assert_eq!(report(c, 1000, 0).nbf, TimeStatus::Valid);
    assert_eq!(report(c, 999, 0).nbf, TimeStatus::NotYetValid);
}

#[test]
fn non_numbers_and_absence() {
    let r = report(r#"{"exp": "1300819380", "nbf": null, "iat": [1]}"#, 0, 0);
    assert_eq!(
        r,
        TimeReport {
            exp: TimeStatus::NotANumber,
            nbf: TimeStatus::NotANumber,
            iat: TimeStatus::NotANumber
        }
    );
    let r = report("{}", 0, 0);
    assert_eq!(
        r,
        TimeReport {
            exp: TimeStatus::Absent,
            nbf: TimeStatus::Absent,
            iat: TimeStatus::Absent
        }
    );
    // Not an object at all: nothing is present.
    assert_eq!(report("[1]", 0, 0).exp, TimeStatus::Absent);
}

#[test]
fn extreme_values_do_not_panic() {
    let c = r#"{"exp": -1, "nbf": 1e400, "iat": 99999999999999999999999}"#;
    assert_eq!(report(c, i64::MAX, 0).exp, TimeStatus::Expired);
    assert_eq!(report(c, i64::MIN, 0).iat, TimeStatus::InFuture);
    let _ = report(c, i64::MAX, u64::MAX);
    let _ = report(c, i64::MIN, u64::MAX);
    let _ = report(r#"{"exp": 1e-400, "nbf": -0, "iat": -1e400}"#, i64::MIN, 0);
}

#[test]
fn duplicate_time_claims_use_the_first() {
    // tokenator-json keeps duplicates; lookups take the first (the linter
    // reports the duplicate separately).
    let r = report(r#"{"exp": 2000, "exp": 10}"#, 1000, 0);
    assert_eq!(r.exp, TimeStatus::Valid);
}
