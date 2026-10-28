//! Disclose, Present, and SD-KBT verification (sd-cwt-08 §3.3, §8, §9).

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::borrow::Cow;

use common::*;
use tokenator_cbor::{Item, Value, Width, decode};
use tokenator_cose::claims::{Cnf, NumericDate, TimeStatus};
use tokenator_cose::kbt::{
    KbtFinding, KbtOptions, KbtReport, PresentOptions, Selection, TimeRule, disclose, present,
    verify_kbt,
};
use tokenator_cose::sd::{FixedSalts, IssueOptions, RngSalts, Typ, issue, parse_sd_cwt};
use tokenator_cose::{Alg, ContentType, CoseError, Key, Sign1Backend, Sign1Parts, SignOptions};
use tokenator_keys::{HashAlg, Kid, ThumbprintKind, thumbprint};

fn fig26_opts() -> PresentOptions<'static> {
    let mut o = PresentOptions::new(Alg::ES256);
    o.selection = Selection::Indices(vec![0, 1, 3]);
    o.aud = Some(SD_AUD.into());
    o.iat = Some(SD_KBT_IAT);
    o.cnonce = Some(h(SD_CNONCE).into());
    o
}

fn kopts() -> KbtOptions<'static> {
    KbtOptions {
        now: SD_NOW,
        skew: 60,
        expected_aud: Some(SD_AUD.into()),
        expected_cnonce: Some(h(SD_CNONCE).into()),
        ..KbtOptions::default()
    }
}

fn verify(kbt: &[u8]) -> KbtReport<'_> {
    verify_kbt(&B, kbt, Some(&sd_issuer()), &kopts()).unwrap()
}

/// Presents the issuer example with Figure 26 options changed by `f`.
fn present_with(f: impl FnOnce(&mut PresentOptions<'static>)) -> Vec<u8> {
    let mut o = fig26_opts();
    f(&mut o);
    present(&B, &token(SD_ISSUER), &sd_holder(), &o, None).unwrap()
}

/// Findings and validity of a verified KBT, owned.
struct Checked {
    findings: Vec<KbtFinding>,
    valid: bool,
}

impl Checked {
    fn is_valid(&self) -> bool {
        self.valid
    }
}

fn check(kbt: Vec<u8>) -> Checked {
    let r = verify(&kbt);
    Checked {
        findings: r.findings.clone(),
        valid: r.is_valid(),
    }
}

trait Findings {
    fn list(&self) -> &[KbtFinding];
}

impl Findings for Checked {
    fn list(&self) -> &[KbtFinding] {
        &self.findings
    }
}

impl Findings for KbtReport<'_> {
    fn list(&self) -> &[KbtFinding] {
        &self.findings
    }
}

fn has(r: &impl Findings, f: &KbtFinding) -> bool {
    r.list().contains(f)
}

/// A KBT signed by `holder` around `inner` (a COSE_Sign1, encoded) with
/// the given KBT protected entries after alg/kcwt and the given payload.
fn manual_kbt(
    inner: &[u8],
    protected_rest: Vec<(Item<'static>, Item<'static>)>,
    payload: &Item<'_>,
    holder: &Key,
) -> Vec<u8> {
    let kcwt = decode(inner).unwrap().into_owned();
    let mut prot = vec![(int(1), int(-7)), (int(13), kcwt)];
    prot.extend(protected_rest);
    let parts = Sign1Parts {
        tags: vec![18],
        protected: Cow::Owned(enc(&map(prot))),
        unprotected: map(vec![]),
        payload: Some(Cow::Owned(enc(payload))),
        signature: Cow::Borrowed(&[]),
    };
    B.sign(&parts, holder, &SignOptions::new(Alg::ES256), None)
        .unwrap()
}

fn typ294() -> Vec<(Item<'static>, Item<'static>)> {
    vec![(int(16), int(294))]
}

/// A custom SD-CWT issued by a generated ES256 key for the C.1 holder.
fn custom_sd_cwt(claims: Vec<(Item<'static>, Item<'static>)>) -> (Vec<u8>, Key) {
    let issuer = key_for(Alg::ES256, 1);
    let mut m = vec![(int(1), text("https://issuer.example"))];
    m.extend(claims);
    m.push((int(8), holder_cnf()));
    m.push((tbr(int(500)), tru()));
    let out = issue(
        &B,
        &map(m),
        &issuer,
        &IssueOptions::new(Alg::ES256),
        &mut RngSalts::new(&mut rng(1)),
        None,
    )
    .unwrap();
    (out.bytes, issuer)
}

// ------------------------------------------------------------ disclose

#[test]
fn disclose_reproduces_the_kbt_inner_token() {
    let out = disclose(&B, &token(SD_ISSUER), &Selection::Indices(vec![0, 1, 3])).unwrap();
    assert_eq!(out, kcwt_of(&token(SD_KBT)));
}

#[test]
fn disclose_all_and_none() {
    let issuer = token(SD_ISSUER);
    assert_eq!(disclose(&B, &issuer, &Selection::All).unwrap(), issuer);
    let none = disclose(&B, &issuer, &Selection::None).unwrap();
    assert_eq!(unprotected_of(&none), h("a0"));
    assert_eq!(protected_of(&none), protected_of(&issuer));
    assert_eq!(payload_of(&none), payload_of(&issuer));
    assert_eq!(signature_of(&none), signature_of(&issuer));
    assert_eq!(
        disclose(&B, &issuer, &Selection::Indices(vec![])).unwrap(),
        none
    );
}

#[test]
fn disclose_reorders_and_repeats() {
    let issuer = token(SD_ISSUER);
    let all = disclosures_of(&issuer);
    let out = disclose(&B, &issuer, &Selection::Indices(vec![4, 0, 0])).unwrap();
    assert_eq!(
        disclosures_of(&out),
        [all[4].clone(), all[0].clone(), all[0].clone()]
    );
}

#[test]
fn disclose_keeps_other_unprotected_entries() {
    let issuer = key_for(Alg::ES256, 1);
    let mut opts = IssueOptions::new(Alg::ES256);
    opts.unprotected_extra = vec![(int(4), bs(b"kid"))];
    let out = issue(
        &B,
        &map(vec![(int(8), holder_cnf()), (tbr(int(500)), tru())]),
        &issuer,
        &opts,
        &mut FixedSalts::new(vec![vec![0; 16]]),
        None,
    )
    .unwrap();
    let none = disclose(&B, &out.bytes, &Selection::None).unwrap();
    assert_eq!(unprotected_of(&none), enc(&map(vec![(int(4), bs(b"kid"))])));
}

#[test]
fn disclose_errors() {
    assert_eq!(
        disclose(&B, &token(SD_ISSUER), &Selection::Indices(vec![5])).unwrap_err(),
        CoseError::DisclosureIndex(5)
    );
    assert!(matches!(
        disclose(&B, &[0xff], &Selection::All),
        Err(CoseError::Cbor(_))
    ));
}

#[test]
fn disclose_inside_a_kbt_breaks_only_the_kbt_signature() {
    let kbt = token(SD_KBT);
    let out = disclose(&B, &kbt, &Selection::Indices(vec![0])).unwrap();
    let r = verify(&out);
    assert_eq!(r.issuer_signature, Ok(Alg::ES384));
    assert_eq!(r.kbt_signature, Err(CoseError::InvalidSignature));
    assert_eq!(disclosures_of(&kcwt_of(&out)).len(), 1);
}

// ------------------------------------------------------------ present

#[test]
fn present_reproduces_figure26_headers_and_payload() {
    let kbt = present_with(|_| {});
    let fx = token(SD_KBT);
    assert_eq!(protected_of(&kbt), protected_of(&fx));
    assert_eq!(payload_of(&kbt), payload_of(&fx));
    assert_eq!(unprotected_of(&kbt), h("a0"));
    assert_eq!(elements(&kbt).0, [18]);
    let r = verify(&kbt);
    assert!(r.is_valid(), "{r:?}");
    // Deterministic ECDSA.
    assert_eq!(present_with(|_| {}), kbt);
}

#[test]
fn present_all_none_and_cti() {
    let kbt = present_with(|o| o.selection = Selection::All);
    assert_eq!(disclosures_of(&kcwt_of(&kbt)).len(), 5);
    let r = verify(&kbt);
    assert!(r.is_valid(), "{r:?}");
    assert!(r.sd.as_ref().unwrap().undisclosed.is_empty());

    let kbt = present_with(|o| {
        o.selection = Selection::None;
        o.iat = None;
        o.cti = Some(Cow::Borrowed(b"kbt-1"));
    });
    assert_eq!(unprotected_of(&kcwt_of(&kbt)), h("a0"));
    // {3: aud, 7: h'6b62742d31', 39: cnonce}
    let payload = decode(&payload_of(&kbt)).unwrap().into_owned();
    let Value::Map(m) = &payload.value else {
        panic!()
    };
    let keys: Vec<Vec<u8>> = m.iter().map(|(k, _)| enc(k)).collect();
    assert_eq!(keys, [h("03"), h("07"), h("1827")]);
    let r = verify(&kbt);
    assert!(r.is_valid(), "{r:?}");
    assert_eq!(r.sd.as_ref().unwrap().undisclosed.len(), 5);
}

#[test]
fn present_payload_and_header_order_with_extras() {
    let kbt = present_with(|o| {
        o.cti = Some(Cow::Borrowed(b"c"));
        o.extra_claims = vec![(int(4), int(1_725_244_300))];
        o.protected_extra = vec![(int(4), bs(b"holder-kid"))];
    });
    let payload = decode(&payload_of(&kbt)).unwrap().into_owned();
    let Value::Map(m) = &payload.value else {
        panic!()
    };
    let keys: Vec<Vec<u8>> = m.iter().map(|(k, _)| enc(k)).collect();
    assert_eq!(keys, [h("03"), h("06"), h("07"), h("1827"), h("04")]);
    let prot = decode(&protected_of(&kbt)).unwrap().into_owned();
    let Value::Map(m) = &prot.value else { panic!() };
    let keys: Vec<Vec<u8>> = m.iter().map(|(k, _)| enc(k)).collect();
    assert_eq!(keys, [h("01"), h("0d"), h("10"), h("04")]);
    assert!(verify(&kbt).is_valid());
}

#[test]
fn present_typ_and_tags() {
    let kbt = present_with(|o| {
        o.typ = Typ::Value(ContentType::Text("application/kb+cwt".into()));
        o.tags = vec![];
    });
    assert!(elements(&kbt).0.is_empty());
    let r = verify(&kbt);
    assert!(r.is_valid(), "{r:?}");
    assert_eq!(
        B.parse(&kbt).unwrap().typ(),
        Some(ContentType::Text("application/kb+cwt".into()))
    );
}

#[test]
fn present_errors() {
    let issuer = token(SD_ISSUER);
    let o = fig26_opts();
    assert_eq!(
        present(&B, &issuer, &public(&sd_holder()), &o, None).unwrap_err(),
        CoseError::NoPrivateKey
    );
    let mut bad = fig26_opts();
    bad.selection = Selection::Indices(vec![7]);
    assert_eq!(
        present(&B, &issuer, &sd_holder(), &bad, None).unwrap_err(),
        CoseError::DisclosureIndex(7)
    );
    let mut wrong_alg = fig26_opts();
    wrong_alg.alg = Alg::Ed25519;
    assert!(matches!(
        present(&B, &issuer, &sd_holder(), &wrong_alg, None),
        Err(CoseError::KeyNotSuitable { .. })
    ));
}

// ------------------------------------------------------------ plain CWT

#[test]
fn plain_cwt_in_an_sd_kbt() {
    let issuer = key_for(Alg::Ed25519, 1);
    let holder = key_for(Alg::ES256, 2);
    let claims = map(vec![
        (int(1), text("https://issuer.example")),
        (int(2), text("https://holder.example")),
        (int(8), cnf_for(&holder)),
    ]);
    let cwt = issue(
        &B,
        &claims,
        &issuer,
        &IssueOptions::new(Alg::Ed25519),
        &mut FixedSalts::new(vec![]),
        None,
    )
    .unwrap();
    assert!(cwt.disclosures.is_empty());
    let mut o = PresentOptions::new(Alg::ES256);
    o.aud = Some(SD_AUD.into());
    o.iat = Some(SD_NOW);
    let kbt = present(&B, &cwt.bytes, &holder, &o, None).unwrap();
    assert_eq!(kcwt_of(&kbt), cwt.bytes, "the CWT is embedded verbatim");
    let opts = KbtOptions {
        now: SD_NOW,
        skew: 60,
        expected_aud: Some(SD_AUD.into()),
        ..KbtOptions::default()
    };
    let r = verify_kbt(&B, &kbt, Some(&issuer), &opts).unwrap();
    assert!(r.is_valid(), "{r:?}");
    assert!(r.sd.as_ref().unwrap().matched.is_empty());
    assert_eq!(r.kbt_signature, Ok(Alg::ES256));
    assert_eq!(r.issuer_signature, Ok(Alg::Ed25519));
}

#[test]
fn present_normalizes_cwt_tags_to_18() {
    let a3 = token(RFC8392_A3);
    let key = key_for(Alg::ES256, 2);
    let mut o = PresentOptions::new(Alg::ES256);
    o.aud = Some("x".into());
    o.iat = Some(1);
    for name in [RFC8392_A3, RFC8392_A3_TAG61, RFC8392_A3_UNTAGGED] {
        let kbt = present(&B, &token(name), &key, &o, None).unwrap();
        assert_eq!(kcwt_of(&kbt), a3, "{name}");
    }
}

#[test]
fn plain_cwt_without_cnf() {
    // RFC 8392 A.3 has no cnf: the KBT can be built but not checked.
    let key = key_for(Alg::ES256, 2);
    let mut o = PresentOptions::new(Alg::ES256);
    o.aud = Some("x".into());
    o.iat = Some(1_443_944_944);
    let kbt = present(&B, &token(RFC8392_A3), &key, &o, None).unwrap();
    let opts = KbtOptions {
        now: 1_443_944_944,
        skew: 60,
        ..KbtOptions::default()
    };
    let r = verify_kbt(&B, &kbt, Some(&rfc8392_key()), &opts).unwrap();
    assert_eq!(r.issuer_signature, Ok(Alg::ES256));
    assert!(r.cnf.is_none());
    assert!(matches!(r.kbt_signature, Err(CoseError::Cnf(_))));
    assert!(!r.is_valid());
}

// ------------------------------------------------------------ cnf forms

#[test]
fn cnf_by_kid_and_thumbprint() {
    let holder = key_for(Alg::ES256, 2);
    let mut holder_with_kid = public(&holder);
    holder_with_kid.kid = Some(Kid::Bytes(b"holder-1".to_vec()));
    let ckt = thumbprint(&holder, ThumbprintKind::Cose, HashAlg::Sha256);
    for cnf in [
        map(vec![(int(3), bs(b"holder-1"))]),
        map(vec![(int(5), bs(&ckt))]),
    ] {
        let issuer = key_for(Alg::ES256, 1);
        let claims = map(vec![
            (int(1), text("i")),
            (int(8), cnf.clone()),
            (tbr(int(500)), tru()),
        ]);
        let sd = issue(
            &B,
            &claims,
            &issuer,
            &IssueOptions::new(Alg::ES256),
            &mut FixedSalts::new(vec![vec![1; 16]]),
            None,
        )
        .unwrap();
        let mut o = PresentOptions::new(Alg::ES256);
        o.aud = Some(SD_AUD.into());
        o.iat = Some(SD_NOW);
        let kbt = present(&B, &sd.bytes, &holder, &o, None).unwrap();

        let mut opts = KbtOptions {
            now: SD_NOW,
            skew: 60,
            ..KbtOptions::default()
        };
        let r = verify_kbt(&B, &kbt, Some(&issuer), &opts).unwrap();
        assert_eq!(r.kbt_signature, Err(CoseError::NoKey));
        assert!(!r.is_valid());

        opts.holder_keys = vec![public(&key_for(Alg::ES256, 9)), holder_with_kid.clone()];
        let r = verify_kbt(&B, &kbt, Some(&issuer), &opts).unwrap();
        assert_eq!(r.kbt_signature, Ok(Alg::ES256));
        assert!(r.is_valid(), "{r:?}");
        assert!(matches!(
            r.cnf,
            Some(Ok(Cnf::Kid(_))) | Some(Ok(Cnf::Thumbprint(_)))
        ));
    }
}

#[test]
fn kbt_signed_by_the_wrong_key() {
    let mut o = fig26_opts();
    o.selection = Selection::All;
    let kbt = present(&B, &token(SD_ISSUER), &key_for(Alg::ES256, 4), &o, None).unwrap();
    let r = verify(&kbt);
    assert_eq!(r.kbt_signature, Err(CoseError::InvalidSignature));
    assert_eq!(r.issuer_signature, Ok(Alg::ES384));
    assert!(!r.is_valid());
}

#[test]
fn wrong_issuer_key() {
    let kbt = token(SD_KBT);
    let r = verify_kbt(&B, &kbt, Some(&public(&key_for(Alg::ES384, 1))), &kopts()).unwrap();
    assert_eq!(r.issuer_signature, Err(CoseError::InvalidSignature));
    assert_eq!(r.kbt_signature, Ok(Alg::ES256));
    assert!(!r.is_valid());
}

// ------------------------------------------------------------ findings

#[test]
fn aud_findings() {
    let r = check(present_with(|o| o.aud = None));
    assert!(has(&r, &KbtFinding::AudMissing), "{:?}", r.findings);
    let r = check(present_with(|o| {
        o.aud = Some("https://other.example".into())
    }));
    assert!(has(&r, &KbtFinding::AudMismatch));
    assert!(!r.is_valid());

    // No expectation: any aud passes.
    let kbt = present_with(|o| o.aud = Some("https://other.example".into()));
    let mut opts = kopts();
    opts.expected_aud = None;
    let r = verify_kbt(&B, &kbt, Some(&sd_issuer()), &opts).unwrap();
    assert!(r.is_valid(), "{r:?}");
}

#[test]
fn sd_cwt_aud_must_match_too() {
    let (sd, issuer) = custom_sd_cwt(vec![(int(3), text("https://someone.else"))]);
    let mut o = PresentOptions::new(Alg::ES256);
    o.aud = Some(SD_AUD.into());
    o.iat = Some(SD_NOW);
    let kbt = present(&B, &sd, &sd_holder(), &o, None).unwrap();
    let mut opts = kopts();
    opts.expected_cnonce = None;
    let r = verify_kbt(&B, &kbt, Some(&issuer), &opts).unwrap();
    assert!(has(&r, &KbtFinding::AudMismatch), "{:?}", r.findings);
}

#[test]
fn iat_cti_and_time_without_iat() {
    let r = check(present_with(|o| o.iat = None));
    assert!(has(&r, &KbtFinding::NoIatOrCti), "{:?}", r.findings);

    let r = check(present_with(|o| {
        o.iat = None;
        o.cti = Some(Cow::Borrowed(b"1"));
        o.extra_claims = vec![(int(4), int(SD_NOW + 100))];
    }));
    assert!(has(&r, &KbtFinding::TimeWithoutIat), "{:?}", r.findings);
    assert!(!has(&r, &KbtFinding::NoIatOrCti));
}

#[test]
fn iss_and_sub_forbidden_in_kbt() {
    let r = check(present_with(|o| {
        o.extra_claims = vec![(int(1), text("holder")), (int(2), text("holder"))];
    }));
    assert!(has(&r, &KbtFinding::IssPresent), "{:?}", r.findings);
    assert!(has(&r, &KbtFinding::SubPresent));
    assert!(!r.is_valid());
}

#[test]
fn cnonce_findings() {
    let r = check(present_with(|o| o.cnonce = None));
    assert!(has(&r, &KbtFinding::CnonceMissing), "{:?}", r.findings);
    let r = check(present_with(|o| o.cnonce = Some(Cow::Borrowed(b"other"))));
    assert!(has(&r, &KbtFinding::CnonceMismatch));
    // Not expected: absent is fine.
    let kbt = present_with(|o| o.cnonce = None);
    let mut opts = kopts();
    opts.expected_cnonce = None;
    assert!(
        verify_kbt(&B, &kbt, Some(&sd_issuer()), &opts)
            .unwrap()
            .is_valid()
    );
}

#[test]
fn typ_findings() {
    let r = check(present_with(|o| o.typ = Typ::Omit));
    assert!(has(&r, &KbtFinding::TypMissing), "{:?}", r.findings);
    let r = check(present_with(|o| o.typ = Typ::Value(ContentType::Uint(293))));
    assert!(has(&r, &KbtFinding::TypUnexpected(ContentType::Uint(293))));
    assert!(!r.is_valid());
}

#[test]
fn cwt_claims_header_forbidden_in_kbt() {
    let r = check(present_with(|o| {
        o.protected_extra = vec![(int(15), map(vec![(int(1), text("x"))]))];
    }));
    assert!(has(&r, &KbtFinding::CwtClaimsHeader), "{:?}", r.findings);
}

/// (KBT iat, extra KBT claims, clock, rules expected to fail)
type TimeCase = (
    Option<i64>,
    Vec<(Item<'static>, Item<'static>)>,
    i64,
    Vec<TimeRule>,
);

#[test]
fn kbt_time_rules_against_sd_cwt() {
    // SD-CWT: nbf 1725243900, iat 1725244200, exp 1725330600.
    let sd_exp = 1_725_330_600;
    let cases: Vec<TimeCase> = vec![
        (
            Some(1_725_244_100),
            vec![],
            1_725_244_100,
            vec![TimeRule::KbtIatBeforeSdIat],
        ),
        (
            Some(1_725_243_800),
            vec![],
            1_725_243_800,
            vec![TimeRule::KbtIatBeforeSdIat, TimeRule::KbtIatBeforeSdNbf],
        ),
        (
            Some(sd_exp),
            vec![],
            sd_exp - 100,
            vec![TimeRule::KbtIatNotBeforeSdExp],
        ),
        (
            Some(SD_KBT_IAT),
            vec![(int(4), int(sd_exp + 1))],
            SD_NOW,
            vec![TimeRule::KbtExpAfterSdExp],
        ),
        (
            Some(SD_KBT_IAT),
            vec![(int(5), int(1_725_243_800))],
            SD_NOW,
            vec![TimeRule::KbtNbfBeforeSdNbf],
        ),
        (
            Some(SD_KBT_IAT),
            vec![(int(5), int(SD_KBT_IAT + 1))],
            SD_NOW,
            vec![TimeRule::KbtNbfAfterIat],
        ),
        (
            Some(SD_KBT_IAT),
            vec![(int(4), int(SD_KBT_IAT))],
            SD_KBT_IAT - 1,
            vec![TimeRule::KbtIatNotBeforeExp],
        ),
        (
            Some(SD_KBT_IAT),
            vec![(int(5), int(sd_exp))],
            SD_NOW,
            vec![TimeRule::KbtNbfNotBeforeSdExp],
        ),
    ];
    for (iat, extra, now, rules) in cases {
        let kbt = present_with(|o| {
            o.iat = iat;
            o.extra_claims = extra;
        });
        let mut opts = kopts();
        opts.now = now;
        let r = verify_kbt(&B, &kbt, Some(&sd_issuer()), &opts).unwrap();
        for rule in &rules {
            assert!(
                has(&r, &KbtFinding::Time(*rule)),
                "{rule:?} missing from {:?}",
                r.findings
            );
        }
        assert!(!r.is_valid());
    }
    // Figure 26 itself breaks none.
    let r = check(token(SD_KBT));
    assert!(!r.findings.iter().any(|f| matches!(f, KbtFinding::Time(_))));
}

#[test]
fn sd_cwt_internal_time_rules() {
    for (claims, rule) in [
        (
            vec![(int(5), int(200)), (int(6), int(100))],
            TimeRule::SdNbfAfterIat,
        ),
        (
            vec![(int(4), int(100)), (int(6), int(100))],
            TimeRule::SdIatNotBeforeExp,
        ),
        (
            vec![(int(4), int(100)), (int(5), int(100))],
            TimeRule::SdNbfNotBeforeExp,
        ),
    ] {
        let (sd, issuer) = custom_sd_cwt(claims);
        let mut o = PresentOptions::new(Alg::ES256);
        o.aud = Some(SD_AUD.into());
        o.iat = Some(150);
        let kbt = present(&B, &sd, &sd_holder(), &o, None).unwrap();
        let opts = KbtOptions {
            now: 150,
            skew: 60,
            ..KbtOptions::default()
        };
        let r = verify_kbt(&B, &kbt, Some(&issuer), &opts).unwrap();
        assert!(
            has(&r, &KbtFinding::Time(rule)),
            "{rule:?}: {:?}",
            r.findings
        );
    }
}

#[test]
fn clock_findings() {
    let kbt = token(SD_KBT);
    // After the SD-CWT expired.
    let mut opts = kopts();
    opts.now = 1_725_330_600 + 61;
    let r = verify_kbt(&B, &kbt, Some(&sd_issuer()), &opts).unwrap();
    assert!(
        has(
            &r,
            &KbtFinding::SdCwtClock(TimeStatus::Expired(NumericDate::Int(1_725_330_600)))
        ),
        "{:?}",
        r.findings
    );
    // Before the KBT was issued (beyond skew).
    let mut opts = kopts();
    opts.now = SD_KBT_IAT - 61;
    let r = verify_kbt(&B, &kbt, Some(&sd_issuer()), &opts).unwrap();
    assert!(has(
        &r,
        &KbtFinding::KbtClock(TimeStatus::IssuedInFuture(NumericDate::Int(SD_KBT_IAT)))
    ));
    // Within skew: fine.
    let mut opts = kopts();
    opts.now = SD_KBT_IAT - 60;
    let r = verify_kbt(&B, &kbt, Some(&sd_issuer()), &opts).unwrap();
    assert!(r.is_valid(), "{:?}", r.findings);
}

#[test]
fn max_age() {
    let kbt = token(SD_KBT);
    let mut opts = kopts();
    opts.max_age = Some(300);
    opts.now = SD_KBT_IAT + 300;
    assert!(
        verify_kbt(&B, &kbt, Some(&sd_issuer()), &opts)
            .unwrap()
            .is_valid()
    );
    opts.now = SD_KBT_IAT + 301;
    let r = verify_kbt(&B, &kbt, Some(&sd_issuer()), &opts).unwrap();
    assert!(has(&r, &KbtFinding::Stale), "{:?}", r.findings);
}

#[test]
fn empty_sd_claims_is_invalid() {
    let issuer = token(SD_ISSUER);
    let msg = B.parse(&issuer).unwrap();
    let mut parts = Sign1Parts::from_sign1(&msg).unwrap();
    parts.unprotected = map(vec![(int(17), arr(vec![]))]);
    let inner = B.assemble(&parts);
    let payload = map(vec![(int(3), text(SD_AUD)), (int(6), int(SD_KBT_IAT))]);
    let kbt = manual_kbt(&inner, typ294(), &payload, &sd_holder());
    let mut opts = kopts();
    opts.expected_cnonce = None;
    let r = verify_kbt(&B, &kbt, Some(&sd_issuer()), &opts).unwrap();
    assert!(has(&r, &KbtFinding::EmptySdClaims), "{:?}", r.findings);
    assert_eq!(r.issuer_signature, Ok(Alg::ES384));
    assert_eq!(r.kbt_signature, Ok(Alg::ES256));
    assert!(!r.is_valid());
}

#[test]
fn indefinite_length_is_invalid() {
    let inner = kcwt_of(&token(SD_KBT));
    let mut payload = map(vec![(int(3), text(SD_AUD)), (int(6), int(SD_KBT_IAT))]);
    payload.width = Width::Indefinite;
    let kbt = manual_kbt(&inner, typ294(), &payload, &sd_holder());
    let mut opts = kopts();
    opts.expected_cnonce = None;
    let r = verify_kbt(&B, &kbt, Some(&sd_issuer()), &opts).unwrap();
    assert_eq!(r.kbt_signature, Ok(Alg::ES256));
    assert!(has(&r, &KbtFinding::IndefiniteLength), "{:?}", r.findings);
    assert!(!r.is_valid());
}

#[test]
fn kcwt_that_is_not_a_sign1() {
    let parts = Sign1Parts {
        tags: vec![18],
        protected: Cow::Owned(enc(&map(vec![
            (int(1), int(-7)),
            (int(13), bs(&[0])),
            (int(16), int(294)),
        ]))),
        unprotected: map(vec![]),
        payload: Some(Cow::Owned(enc(&map(vec![(int(3), text(SD_AUD))])))),
        signature: Cow::Borrowed(&[]),
    };
    let kbt = B
        .sign(&parts, &sd_holder(), &SignOptions::new(Alg::ES256), None)
        .unwrap();
    let r = verify(&kbt);
    assert!(has(&r, &KbtFinding::KcwtNotSign1), "{:?}", r.findings);
    assert!(r.sd_cwt.is_none());
    assert!(r.issuer_signature.is_err());
    assert!(!r.is_valid());
}

#[test]
fn kbt_with_application_kb_cwt_text_typ_is_fine() {
    let inner = kcwt_of(&token(SD_KBT));
    let payload = map(vec![
        (int(3), text(SD_AUD)),
        (int(6), int(SD_KBT_IAT)),
        (int(39), bs(&h(SD_CNONCE))),
    ]);
    let kbt = manual_kbt(
        &inner,
        vec![(int(16), text("application/kb+cwt"))],
        &payload,
        &sd_holder(),
    );
    let r = verify(&kbt);
    assert!(r.is_valid(), "{:?}", r.findings);
}

#[test]
fn sd_cwt_parsed_from_kbt_matches_standalone() {
    let kbt = token(SD_KBT);
    let r = verify(&kbt);
    let inner = kcwt_of(&kbt);
    let alone = parse_sd_cwt(&B, &inner).unwrap();
    let embedded = r.sd_cwt.as_ref().unwrap();
    assert_eq!(embedded.disclosures.len(), alone.disclosures.len());
    for (a, b) in embedded.disclosures.iter().zip(&alone.disclosures) {
        assert_eq!(a.digest, b.digest);
        assert_eq!(
            a.bytes.span, b.bytes.span,
            "spans are relative to the SD-CWT"
        );
    }
}
