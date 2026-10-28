//! CWT claims, NumericDate and time checks (RFC 8392 §2, §3; sd-cwt-08
//! §5.2), and `cnf` (RFC 8747, RFC 9679).

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_cbor::{FloatWidth, Item, Value, decode};
use tokenator_cose::claims::{
    Cnf, NumericDate, TimeError, TimeOptions, TimeStatus, check_times, claim, numeric_date,
    parse_cnf, resolve_cnf,
};
use tokenator_cose::{CoseError, Label, Sign1Backend};
use tokenator_keys::{HashAlg, Kid, ThumbprintKind, thumbprint};

const A1_EXP: i64 = 1_444_064_944;
const A1_NBF: i64 = 1_443_944_944;

fn opts(now: i64, skew: u64) -> TimeOptions {
    TimeOptions { now, skew }
}

fn claims_with(key: i64, v: Item<'static>) -> Item<'static> {
    map(vec![(int(key), v)])
}

#[test]
fn rfc8392_a1_claim_lookup() {
    let bytes = token(RFC8392_A1);
    let c = decode(&bytes).unwrap();
    let get = |k: i64| claim(&c, &Label::Int(k)).map(enc);
    assert_eq!(get(1), Some(enc(&text("coap://as.example.com"))));
    assert_eq!(get(2), Some(enc(&text("erikw"))));
    assert_eq!(get(3), Some(enc(&text("coap://light.example.com"))));
    assert_eq!(get(4), Some(enc(&int(A1_EXP))));
    assert_eq!(get(7), Some(h("420b71")));
    assert_eq!(get(8), None);
    assert!(claim(&c, &Label::Text("iss".into())).is_none());
}

#[test]
fn claim_lookup_by_value_not_encoding() {
    // {0x18 0x01: "x", "name": 2}
    let bytes = h("a2 1801 6178 646e616d65 02");
    let c = decode(&bytes).unwrap();
    assert_eq!(claim(&c, &Label::Int(1)).map(enc), Some(h("6178")));
    assert_eq!(
        claim(&c, &Label::Text("name".into())).map(enc),
        Some(h("02"))
    );
    // First of duplicate keys.
    let dup = h("a2 01 02 01 03");
    let c = decode(&dup).unwrap();
    assert_eq!(claim(&c, &Label::Int(1)).map(enc), Some(h("02")));
    // Not a map.
    assert!(claim(&decode(&h("80")).unwrap(), &Label::Int(1)).is_none());
}

#[test]
fn numeric_dates() {
    assert_eq!(numeric_date(&int(0)), Ok(NumericDate::Int(0)));
    assert_eq!(numeric_date(&int(-1)), Ok(NumericDate::Int(-1)));
    assert_eq!(numeric_date(&int(A1_EXP)), Ok(NumericDate::Int(A1_EXP)));
    assert_eq!(
        numeric_date(&Item::float(1_443_944_944.5)),
        Ok(NumericDate::Float(1_443_944_944.5))
    );
    assert_eq!(NumericDate::Int(5).as_f64(), 5.0);
    assert_eq!(NumericDate::Float(5.5).as_f64(), 5.5);
    // A 2^53 float is allowed; just above is not.
    let max = 9_007_199_254_740_992.0;
    assert_eq!(numeric_date(&Item::float(max)), Ok(NumericDate::Float(max)));
    assert_eq!(
        numeric_date(&Item::float(-max)),
        Ok(NumericDate::Float(-max))
    );
    assert_eq!(
        numeric_date(&Item::float(max * 2.0)),
        Err(TimeError::OutOfRange)
    );
    assert_eq!(
        numeric_date(&Item::new(Value::Float(f64::NAN, FloatWidth::F16))),
        Err(TimeError::NotFinite)
    );
    assert_eq!(
        numeric_date(&Item::new(Value::Float(f64::INFINITY, FloatWidth::F16))),
        Err(TimeError::NotFinite)
    );
    assert_eq!(
        numeric_date(&Item::new(Value::Float(f64::NEG_INFINITY, FloatWidth::F64))),
        Err(TimeError::NotFinite)
    );
    // Beyond i64.
    assert_eq!(
        numeric_date(&Item::new(Value::Uint(u64::MAX))),
        Err(TimeError::OutOfRange)
    );
    assert_eq!(
        numeric_date(&Item::new(Value::Nint(u64::MAX))),
        Err(TimeError::OutOfRange)
    );
    // Wrong types, including a tagged date.
    assert_eq!(numeric_date(&text("1444064944")), Err(TimeError::WrongType));
    assert_eq!(
        numeric_date(&tag(1, int(A1_EXP))),
        Err(TimeError::WrongType)
    );
    assert_eq!(numeric_date(&null()), Err(TimeError::WrongType));
}

#[test]
fn rfc8392_a7_float_iat() {
    let bytes = token(RFC8392_A7);
    // COSE_Mac0 is unsupported, but its payload is a claims set.
    let (tags, els) = elements(&bytes);
    assert_eq!(tags, [17]);
    let payload = bstr_of(&els[2]);
    let c = decode(&payload).unwrap();
    assert_eq!(
        numeric_date(claim(&c, &Label::Int(6)).unwrap()),
        Ok(NumericDate::Float(1_443_944_944.5))
    );
    let r = check_times(&c, &opts(1_443_944_944, 0));
    assert_eq!(r.exp, None);
    assert_eq!(r.nbf, None);
    assert_eq!(
        r.iat,
        Some(TimeStatus::IssuedInFuture(NumericDate::Float(
            1_443_944_944.5
        )))
    );
    let r = check_times(&c, &opts(1_443_944_945, 0));
    assert_eq!(
        r.iat,
        Some(TimeStatus::Ok(NumericDate::Float(1_443_944_944.5)))
    );
}

#[test]
fn rfc8392_a1_times() {
    let bytes = token(RFC8392_A1);
    let c = decode(&bytes).unwrap();
    let r = check_times(&c, &opts(A1_NBF + 10, 60));
    assert!(r.is_ok());
    assert_eq!(r.exp, Some(TimeStatus::Ok(NumericDate::Int(A1_EXP))));
    assert_eq!(r.nbf, Some(TimeStatus::Ok(NumericDate::Int(A1_NBF))));
    assert_eq!(r.iat, Some(TimeStatus::Ok(NumericDate::Int(A1_NBF))));
    // After exp.
    let r = check_times(&c, &opts(A1_EXP + 1000, 60));
    assert_eq!(r.exp, Some(TimeStatus::Expired(NumericDate::Int(A1_EXP))));
    assert!(!r.is_ok());
    // Before nbf (and iat in the future).
    let r = check_times(&c, &opts(A1_NBF - 1000, 60));
    assert_eq!(
        r.nbf,
        Some(TimeStatus::NotYetValid(NumericDate::Int(A1_NBF)))
    );
    assert_eq!(
        r.iat,
        Some(TimeStatus::IssuedInFuture(NumericDate::Int(A1_NBF)))
    );
}

#[test]
fn exp_boundaries_with_skew() {
    let c = claims_with(4, int(1000));
    let st = |now, skew| check_times(&c, &opts(now, skew)).exp.unwrap();
    assert_eq!(st(999, 0), TimeStatus::Ok(NumericDate::Int(1000)));
    assert_eq!(st(1000, 0), TimeStatus::Expired(NumericDate::Int(1000)));
    assert_eq!(st(1059, 60), TimeStatus::Ok(NumericDate::Int(1000)));
    assert_eq!(st(1060, 60), TimeStatus::Expired(NumericDate::Int(1000)));
    // Float exp.
    let c = claims_with(4, Item::float(1000.5));
    let st = |now| check_times(&c, &opts(now, 0)).exp.unwrap();
    assert_eq!(st(1000), TimeStatus::Ok(NumericDate::Float(1000.5)));
    assert_eq!(st(1001), TimeStatus::Expired(NumericDate::Float(1000.5)));
}

#[test]
fn nbf_boundaries_with_skew() {
    let c = claims_with(5, int(1000));
    let st = |now, skew| check_times(&c, &opts(now, skew)).nbf.unwrap();
    assert_eq!(st(1000, 0), TimeStatus::Ok(NumericDate::Int(1000)));
    assert_eq!(st(999, 0), TimeStatus::NotYetValid(NumericDate::Int(1000)));
    assert_eq!(st(940, 60), TimeStatus::Ok(NumericDate::Int(1000)));
    assert_eq!(st(939, 60), TimeStatus::NotYetValid(NumericDate::Int(1000)));
}

#[test]
fn iat_boundaries_with_skew() {
    let c = claims_with(6, int(1000));
    let st = |now, skew| check_times(&c, &opts(now, skew)).iat.unwrap();
    assert_eq!(st(1000, 0), TimeStatus::Ok(NumericDate::Int(1000)));
    assert_eq!(
        st(999, 0),
        TimeStatus::IssuedInFuture(NumericDate::Int(1000))
    );
    assert_eq!(st(940, 60), TimeStatus::Ok(NumericDate::Int(1000)));
    assert_eq!(
        st(939, 60),
        TimeStatus::IssuedInFuture(NumericDate::Int(1000))
    );
    // Long ago is fine for iat.
    assert_eq!(st(i64::MAX, 0), TimeStatus::Ok(NumericDate::Int(1000)));
}

#[test]
fn invalid_time_claims_are_reported() {
    let c = map(vec![
        (int(4), text("tomorrow")),
        (int(5), Item::new(Value::Float(f64::NAN, FloatWidth::F16))),
        (int(6), tag(1, int(5))),
    ]);
    let r = check_times(&c, &opts(0, 60));
    assert_eq!(r.exp, Some(TimeStatus::Invalid(TimeError::WrongType)));
    assert_eq!(r.nbf, Some(TimeStatus::Invalid(TimeError::NotFinite)));
    assert_eq!(r.iat, Some(TimeStatus::Invalid(TimeError::WrongType)));
    assert!(!r.is_ok());
}

#[test]
fn no_time_claims() {
    let r = check_times(&map(vec![]), &opts(0, 0));
    assert_eq!((r.exp, r.nbf, r.iat), (None, None, None));
    assert!(r.is_ok());
    // Not a map: nothing to check.
    let r = check_times(&arr(vec![]), &opts(0, 0));
    assert!(r.is_ok());
}

#[test]
fn time_checks_survive_extreme_clocks() {
    let c = map(vec![
        (int(4), int(i64::MAX)),
        (int(5), int(i64::MIN)),
        (int(6), int(0)),
    ]);
    for now in [i64::MIN, -1, 0, i64::MAX] {
        let _ = check_times(&c, &opts(now, u64::MAX));
        let _ = check_times(&c, &opts(now, 0));
    }
}

// ---------------------------------------------------------------- cnf

#[test]
fn cnf_cose_key_from_sd_cwt() {
    let bytes = token(SD_ISSUER);
    let msg = B.parse(&bytes).unwrap();
    let payload = msg.payload_item().unwrap();
    let cnf_item = claim(payload, &Label::Int(8)).unwrap();
    let Cnf::CoseKey(cwk) = parse_cnf(cnf_item).unwrap() else {
        panic!("not a COSE_Key")
    };
    assert_eq!(cwk.to_cbor(), enc(&holder_cnf_inner()));
    let key = resolve_cnf(&Cnf::CoseKey(cwk), &[]).unwrap().unwrap();
    assert!(key.same_material(&public(&sd_holder())));
}

fn holder_cnf_inner() -> Item<'static> {
    let Value::Map(mut m) = holder_cnf().value else {
        unreachable!()
    };
    m.remove(0).1
}

#[test]
fn cnf_kid_and_thumbprint() {
    let holder = public(&sd_holder());
    let mut with_kid = holder.clone();
    with_kid.kid = Some(Kid::Bytes(b"holder-1".to_vec()));
    let other = public(&key_for(tokenator_cose::Alg::ES256, 5));

    let cnf = parse_cnf(&map(vec![(int(3), bs(b"holder-1"))])).unwrap();
    assert_eq!(cnf, Cnf::Kid(b"holder-1".to_vec().into()));
    let found = resolve_cnf(&cnf, &[other.clone(), with_kid.clone()])
        .unwrap()
        .unwrap();
    assert!(found.same_material(&holder));
    assert_eq!(
        resolve_cnf(&cnf, std::slice::from_ref(&other)).unwrap(),
        None
    );

    // ckt: RFC 9679 SHA-256 thumbprint, sd-cwt-08 C.1 value.
    let ckt = h("8343d73cdfcb81f2c7cd11a5f317be8eb34e4807ec8c9ceb282495cffdf037e0");
    assert_eq!(
        thumbprint(&holder, ThumbprintKind::Cose, HashAlg::Sha256),
        ckt
    );
    let cnf = parse_cnf(&map(vec![(int(5), bs(&ckt))])).unwrap();
    assert_eq!(cnf, Cnf::Thumbprint(ckt.clone().into()));
    let found = resolve_cnf(&cnf, &[other.clone(), holder.clone()])
        .unwrap()
        .unwrap();
    assert!(found.same_material(&holder));
    assert_eq!(resolve_cnf(&cnf, &[other]).unwrap(), None);
}

#[test]
fn cnf_other_forms() {
    let enc_key = arr(vec![bs(b"protected"), map(vec![]), bs(b"ct")]);
    assert_eq!(
        parse_cnf(&map(vec![(int(2), enc_key.clone())])).unwrap(),
        Cnf::EncryptedCoseKey(enc_key)
    );
    assert_eq!(
        parse_cnf(&map(vec![(int(4), bs(b"osc"))])).unwrap(),
        Cnf::Other(Label::Int(4), bs(b"osc"))
    );
    assert_eq!(
        parse_cnf(&map(vec![(text("jwk"), map(vec![]))])).unwrap(),
        Cnf::Other(Label::Text("jwk".into()), map(vec![]))
    );
    // Neither an encrypted key nor a kid can be resolved without candidates.
    assert_eq!(
        resolve_cnf(&Cnf::Kid(b"x".to_vec().into()), &[]).unwrap(),
        None
    );
}

#[test]
fn cnf_malformed() {
    for bad in [
        arr(vec![]),
        map(vec![]),
        map(vec![(int(1), int(5))]),
        map(vec![(int(3), text("kid"))]),
        map(vec![(int(5), int(1))]),
        map(vec![(int(3), bs(b"a")), (int(5), bs(b"b"))]),
    ] {
        assert!(
            matches!(parse_cnf(&bad), Err(CoseError::Cnf(_))),
            "{}",
            hex::encode(enc(&bad))
        );
    }
}

#[test]
fn cnf_cose_key_that_is_not_a_key() {
    // {1: {1: 2, -1: 1}}: an EC2 key without x/y parses as a COSE_Key map
    // but cannot be resolved.
    let cnf = parse_cnf(&map(vec![(
        int(1),
        map(vec![(int(1), int(2)), (int(-1), int(1))]),
    )]))
    .unwrap();
    assert!(matches!(cnf, Cnf::CoseKey(_)));
    assert!(matches!(resolve_cnf(&cnf, &[]), Err(CoseError::Key(_))));
}
