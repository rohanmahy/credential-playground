//! Lint facts (SPEC §6 "Conformance lint"; RFC 9052 §3, §3.1, §9;
//! sd-cwt-08 §4, §5.1, §5.4, §6.1, §8.1).

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
use tokenator_cbor::{FindingKind as CborKind, Item, Span, Width, decode};
use tokenator_cose::edit::{EquivalentEncoding, TamperOp, tamper};
use tokenator_cose::lint::{Finding, FindingKind, KeyRole, LintOptions, Severity, lint};
use tokenator_cose::sd::encode_disclosure;
use tokenator_cose::{Alg, ContentType, DeclaredAlg, Label, Part, Sign1Backend, Sign1Parts};
use tokenator_crypto::KeyMismatch;
use tokenator_keys::params;

fn run(bytes: &[u8]) -> Vec<Finding> {
    lint(&B, bytes, &LintOptions::default()).unwrap()
}

fn kinds(f: &[Finding]) -> Vec<FindingKind> {
    f.iter().map(|f| f.kind.clone()).collect()
}

fn find(f: &[Finding], pred: impl Fn(&Finding) -> bool) -> &Finding {
    f.iter()
        .find(|x| pred(x))
        .unwrap_or_else(|| panic!("not found in {f:#?}"))
}

fn is_encoding(f: &Finding, k: CborKind) -> bool {
    matches!(&f.kind, FindingKind::Encoding { kind, .. } if *kind == k)
}

fn assemble(protected: &[u8], unprotected: Item<'_>, payload: &[u8]) -> Vec<u8> {
    B.assemble(&Sign1Parts {
        tags: vec![18],
        protected: Cow::Owned(protected.to_vec()),
        unprotected,
        payload: Some(Cow::Owned(payload.to_vec())),
        signature: Cow::Borrowed(&[]),
    })
    .unwrap()
}

fn es256() -> Vec<u8> {
    h("a10126")
}

fn sd_prot() -> Vec<u8> {
    enc(&map(vec![
        (int(1), int(-7)),
        (int(16), int(293)),
        (int(170), int(-16)),
    ]))
}

// ------------------------------------------------------------ clean inputs

#[test]
fn fixtures_are_clean() {
    for name in SIGN1_FIXTURES {
        let f = run(&token(name));
        assert!(f.is_empty(), "{name}: {f:#?}");
    }
    for n in [44, 65, 87] {
        let bytes = hexs(&rfc9964(n)["sign1"]);
        assert!(run(&bytes).is_empty(), "ML-DSA-{n}");
    }
}

#[test]
fn signer_key_that_fits() {
    let opts = LintOptions {
        signer: Some(params(&rfc8392_key())),
    };
    assert!(lint(&B, &token(RFC8392_A3), &opts).unwrap().is_empty());
}

#[test]
fn lint_fails_only_when_unparseable() {
    assert!(lint(&B, &[0xff], &LintOptions::default()).is_err());
    assert!(lint(&B, &token(RFC8392_A4), &LintOptions::default()).is_err());
    assert!(lint(&B, &h("84 01 02 03 04"), &LintOptions::default()).is_ok());
}

// ------------------------------------------------------------ encodings

#[test]
fn non_preferred_in_payload_is_warn() {
    // payload {0x18 0x01: "x"}
    let payload = h("a1 1801 6178");
    let bytes = assemble(&es256(), map(vec![]), &payload);
    let f = run(&bytes);
    let x = find(&f, |f| is_encoding(f, CborKind::NonPreferredArgument));
    assert_eq!(x.severity, Severity::Warn);
    assert_eq!(x.part, Part::Payload);
    // d2 84 43 a10126 a0 45 | a1 1801 ...: the key head is at 9..11.
    assert_eq!(
        x.span,
        Some(Span {
            start: 9,
            end: 11,
            head_len: 2
        })
    );
    let FindingKind::Encoding {
        preferred_bytes, ..
    } = &x.kind
    else {
        unreachable!()
    };
    assert_eq!(preferred_bytes, &[0x01]);
}

#[test]
fn non_preferred_in_unprotected_is_info() {
    let unprotected = map(vec![(Item::int(4).with_width(Width::U8), bs(b"k"))]);
    let bytes = assemble(&es256(), unprotected, &h("a0"));
    let f = run(&bytes);
    let x = find(&f, |f| is_encoding(f, CborKind::NonPreferredArgument));
    assert_eq!(x.severity, Severity::Info);
    assert_eq!(x.part, Part::Unprotected);
}

#[test]
fn protected_head_vs_contents() {
    let a3 = token(RFC8392_A3);
    let wide_head = tamper(
        &B,
        &a3,
        &TamperOp::ProtectedEquivalent(EquivalentEncoding::WideBstrHead),
    )
    .unwrap();
    let f = run(&wide_head);
    let x = find(&f, |f| is_encoding(f, CborKind::NonPreferredArgument));
    assert_eq!(
        (x.severity, x.part.clone()),
        (Severity::Info, Part::Protected)
    );
    assert_eq!(x.span.map(|s| (s.start, s.end)), Some((2, 4)));

    let wide_ints = tamper(
        &B,
        &a3,
        &TamperOp::ProtectedEquivalent(EquivalentEncoding::WideIntegers),
    )
    .unwrap();
    let f = run(&wide_ints);
    let found: Vec<&Finding> = f
        .iter()
        .filter(|f| is_encoding(f, CborKind::NonPreferredArgument))
        .collect();
    assert_eq!(found.len(), 2, "{f:#?}");
    for x in found {
        assert_eq!(
            (x.severity, x.part.clone()),
            (Severity::Warn, Part::Protected)
        );
    }
    // d2 84 45 | a1 1801 3806: absolute spans of the two heads.
    let spans: Vec<_> = f
        .iter()
        .filter_map(|f| f.span.map(|s| (s.start, s.end)))
        .collect();
    assert!(
        spans.contains(&(4, 6)) && spans.contains(&(6, 8)),
        "{spans:?}"
    );

    let indefinite = tamper(
        &B,
        &a3,
        &TamperOp::ProtectedEquivalent(EquivalentEncoding::IndefiniteMap),
    )
    .unwrap();
    let f = run(&indefinite);
    let x = find(&f, |f| is_encoding(f, CborKind::IndefiniteLength));
    assert_eq!(
        (x.severity, x.part.clone()),
        (Severity::Warn, Part::Protected)
    );
}

#[test]
fn map_key_order_is_info() {
    let payload = enc(&map(vec![(int(2), int(0)), (int(1), int(0))]));
    let f = run(&assemble(&es256(), map(vec![]), &payload));
    let x = find(&f, |f| is_encoding(f, CborKind::MapKeyOrder));
    assert_eq!(
        (x.severity, x.part.clone()),
        (Severity::Info, Part::Payload)
    );
}

#[test]
fn indefinite_lengths() {
    // Unprotected of a plain CWT: Info. Of an SD-CWT: Warn (sd-cwt §5.1).
    let mut unprotected = map(vec![(int(4), bs(b"k"))]);
    unprotected.width = Width::Indefinite;
    let f = run(&assemble(&es256(), unprotected.clone(), &h("a0")));
    let x = find(&f, |f| is_encoding(f, CborKind::IndefiniteLength));
    assert_eq!(x.severity, Severity::Info);
    let f = run(&assemble(&sd_prot(), unprotected, &h("a0")));
    let x = find(&f, |f| is_encoding(f, CborKind::IndefiniteLength));
    assert_eq!(x.severity, Severity::Warn);
}

#[test]
fn disclosure_encodings_are_warn() {
    // A disclosure with a non-preferred value, and one with a wide bstr head.
    let d0 = [h("82 50"), vec![0; 16], h("1801")].concat();
    let d1 = encode_disclosure(&[1; 16], Some(&int(2)), None).unwrap();
    let mut wide = vec![0x58, u8::try_from(d1.len()).unwrap()];
    wide.extend(&d1);
    let unprotected = map(vec![(
        int(17),
        arr(vec![bs(&d0), decode(&wide).unwrap().into_owned()]),
    )]);
    let f = run(&assemble(&sd_prot(), unprotected, &h("a0")));
    let x = find(&f, |f| f.part == Part::Disclosure(0));
    assert!(is_encoding(x, CborKind::NonPreferredArgument));
    assert_eq!(x.severity, Severity::Warn);
    let x = find(&f, |f| f.part == Part::Disclosure(1));
    assert!(is_encoding(x, CborKind::NonPreferredArgument));
    assert_eq!(x.severity, Severity::Warn);
}

#[test]
fn findings_inside_kcwt_have_absolute_spans() {
    // Re-sign the issuer example's payload with a non-preferred iss key,
    // present it, and lint the KBT.
    let issuer = sd_issuer();
    let sd = token(SD_ISSUER);
    let mut payload = payload_of(&sd);
    assert_eq!(&payload[..2], h("aa01"));
    payload.splice(1..2, h("1801"));
    let opts = tokenator_cose::edit::ResignOptions {
        payload: tokenator_cose::edit::Edit::Bytes(Cow::Owned(payload)),
        ..Default::default()
    };
    let resigned = tokenator_cose::edit::resign(&B, &sd, &issuer, &opts, None).unwrap();
    let mut p = tokenator_cose::kbt::PresentOptions::new(Alg::ES256);
    p.aud = Some(SD_AUD.into());
    p.iat = Some(SD_KBT_IAT);
    let kbt = tokenator_cose::kbt::present(&B, &resigned, &sd_holder(), &p, None).unwrap();
    let f = run(&kbt);
    let x = find(&f, |f| is_encoding(f, CborKind::NonPreferredArgument));
    assert_eq!(x.part, Part::Kcwt(Box::new(Part::Payload)));
    assert_eq!(x.severity, Severity::Warn);
    let s = x.span.unwrap();
    assert_eq!(&kbt[s.start..s.end], h("1801"));
}

// ------------------------------------------------------------ maps and headers

#[test]
fn duplicate_map_keys() {
    let payload = h("a2 01 6161 1801 6162");
    let bytes = assemble(&es256(), map(vec![]), &payload);
    let f = run(&bytes);
    let x = find(&f, |f| f.kind == FindingKind::DuplicateMapKey);
    assert_eq!(
        (x.severity, x.part.clone()),
        (Severity::Warn, Part::Payload)
    );
    // d2 84 43 a10126 a0 47 | a2 01 6161 1801: the second key is at 12..14.
    assert_eq!(x.span.map(|s| (s.start, s.end)), Some((12, 14)));

    let unprotected = map(vec![(int(4), bs(b"a")), (int(4), bs(b"b"))]);
    let f = run(&assemble(&es256(), unprotected, &h("a0")));
    assert!(kinds(&f).contains(&FindingKind::DuplicateMapKey));
}

#[test]
fn label_in_both_buckets() {
    let bytes = assemble(&es256(), map(vec![(int(1), int(-7))]), &h("a0"));
    assert!(kinds(&run(&bytes)).contains(&FindingKind::LabelInBothBuckets(Label::Int(1))));
}

#[test]
fn alg_findings() {
    let f = run(&assemble(b"", map(vec![]), &h("a0")));
    assert!(kinds(&f).contains(&FindingKind::MissingAlg));

    let prot = enc(&map(vec![(int(1), int(-999))]));
    let f = run(&assemble(&prot, map(vec![]), &h("a0")));
    assert!(kinds(&f).contains(&FindingKind::UnsupportedAlg(DeclaredAlg::UnknownCose(-999))));

    let f = run(&assemble(b"", map(vec![(int(1), int(-7))]), &h("a0")));
    assert!(kinds(&f).contains(&FindingKind::AlgNotProtected));
    assert!(!kinds(&f).contains(&FindingKind::MissingAlg));
}

#[test]
fn signer_alg_key_mismatch() {
    let opts = LintOptions {
        signer: Some(params(&key_for(Alg::Ed25519, 1))),
    };
    let f = lint(&B, &token(RFC8392_A3), &opts).unwrap();
    let x = find(&f, |f| matches!(f.kind, FindingKind::AlgKeyMismatch { .. }));
    let FindingKind::AlgKeyMismatch { role, mismatches } = &x.kind else {
        unreachable!()
    };
    assert_eq!(*role, KeyRole::Signer);
    assert!(matches!(
        mismatches.as_slice(),
        [KeyMismatch::KeyType { .. }]
    ));
    assert_eq!(x.severity, Severity::Warn);
}

#[test]
fn draft_issuer_key_declares_esp384() {
    // sd-cwt-08 C.2 declares alg -51 (ESP384) but the examples say ES384.
    let opts = LintOptions {
        signer: Some(params(&sd_issuer())),
    };
    let f = lint(&B, &token(SD_ISSUER), &opts).unwrap();
    let x = find(&f, |f| matches!(f.kind, FindingKind::AlgKeyMismatch { .. }));
    assert_eq!(
        x.kind,
        FindingKind::AlgKeyMismatch {
            role: KeyRole::Signer,
            mismatches: vec![KeyMismatch::DeclaredAlg {
                alg: Alg::ES384,
                declared: DeclaredAlg::UnknownCose(-51),
            }],
        }
    );
}

#[test]
fn cnf_key_vs_kbt_alg() {
    // A KBT claiming ES384 while the cnf key is P-256.
    let inner = decode(&kcwt_of(&token(SD_KBT))).unwrap().into_owned();
    let prot = enc(&map(vec![
        (int(1), int(-35)),
        (int(13), inner),
        (int(16), int(294)),
    ]));
    let payload = payload_of(&token(SD_KBT));
    let f = run(&assemble(&prot, map(vec![]), &payload));
    let x = find(&f, |f| matches!(f.kind, FindingKind::AlgKeyMismatch { .. }));
    let FindingKind::AlgKeyMismatch { role, mismatches } = &x.kind else {
        unreachable!()
    };
    assert_eq!(*role, KeyRole::Cnf);
    assert!(matches!(mismatches.as_slice(), [KeyMismatch::Curve { .. }]));
}

#[test]
fn crit_findings() {
    let crit_unprot = map(vec![(int(2), arr(vec![int(1)]))]);
    let f = run(&assemble(&es256(), crit_unprot, &h("a0")));
    assert!(kinds(&f).contains(&FindingKind::CritNotProtected));

    let prot = enc(&map(vec![(int(1), int(-7)), (int(2), arr(vec![]))]));
    let f = run(&assemble(&prot, map(vec![]), &h("a0")));
    assert!(kinds(&f).contains(&FindingKind::CritMalformed));

    let prot = enc(&map(vec![(int(1), int(-7)), (int(2), int(1))]));
    let f = run(&assemble(&prot, map(vec![]), &h("a0")));
    assert!(kinds(&f).contains(&FindingKind::CritMalformed));

    let prot = enc(&map(vec![(int(1), int(-7)), (int(2), arr(vec![int(99)]))]));
    let f = run(&assemble(&prot, map(vec![]), &h("a0")));
    assert!(kinds(&f).contains(&FindingKind::CritMissingLabel(Label::Int(99))));

    let prot = enc(&map(vec![
        (int(1), int(-7)),
        (int(2), arr(vec![int(99), text("x")])),
        (int(99), int(0)),
        (text("x"), int(0)),
    ]));
    let f = run(&assemble(&prot, map(vec![]), &h("a0")));
    assert!(kinds(&f).contains(&FindingKind::CritNotUnderstood(Label::Int(99))));
    assert!(kinds(&f).contains(&FindingKind::CritNotUnderstood(Label::Text("x".into()))));

    // Understood labels are fine.
    let prot = enc(&map(vec![
        (int(1), int(-7)),
        (int(2), arr(vec![int(16)])),
        (int(16), int(61)),
    ]));
    let f = run(&assemble(&prot, map(vec![]), &h("a0")));
    assert!(
        !f.iter().any(|f| matches!(
            f.kind,
            FindingKind::CritMalformed
                | FindingKind::CritMissingLabel(_)
                | FindingKind::CritNotUnderstood(_)
                | FindingKind::CritNotProtected
        )),
        "{f:#?}"
    );
}

#[test]
fn typ_findings() {
    // An SD-CWT (sd_alg present) without typ.
    let prot = enc(&map(vec![(int(1), int(-7)), (int(170), int(-16))]));
    let f = run(&assemble(&prot, map(vec![]), &h("a0")));
    assert!(kinds(&f).contains(&FindingKind::TypMissing));

    let prot = enc(&map(vec![
        (int(1), int(-7)),
        (int(16), int(294)),
        (int(170), int(-16)),
    ]));
    let f = run(&assemble(&prot, map(vec![]), &h("a0")));
    assert!(kinds(&f).contains(&FindingKind::TypUnexpected(ContentType::Uint(294))));

    for ok in ["application/sd-cwt", "application/example+sd-cwt"] {
        let prot = enc(&map(vec![
            (int(1), int(-7)),
            (int(16), text(ok)),
            (int(170), int(-16)),
        ]));
        let f = run(&assemble(&prot, map(vec![]), &h("a0")));
        assert!(
            !f.iter().any(|f| matches!(
                f.kind,
                FindingKind::TypMissing | FindingKind::TypUnexpected(_)
            )),
            "{ok}: {f:#?}"
        );
    }

    // A KBT without typ.
    let inner = decode(&kcwt_of(&token(SD_KBT))).unwrap().into_owned();
    let prot = enc(&map(vec![(int(1), int(-7)), (int(13), inner)]));
    let f = run(&assemble(&prot, map(vec![]), &payload_of(&token(SD_KBT))));
    let x = find(&f, |f| f.kind == FindingKind::TypMissing);
    assert_eq!(x.part, Part::Protected);
}

#[test]
fn empty_protected_must_be_zero_length() {
    let f = run(&assemble(&h("a0"), map(vec![(int(1), int(-7))]), &h("a0")));
    assert!(kinds(&f).contains(&FindingKind::EmptyProtectedNotZeroLength));
    let f = run(&assemble(b"", map(vec![(int(1), int(-7))]), &h("a0")));
    assert!(!kinds(&f).contains(&FindingKind::EmptyProtectedNotZeroLength));
}

#[test]
fn salt_length() {
    let d = encode_disclosure(&[1; 8], Some(&int(2)), None).unwrap();
    let unprotected = map(vec![(int(17), arr(vec![bs(&d)]))]);
    let f = run(&assemble(&sd_prot(), unprotected, &h("a0")));
    let x = find(&f, |f| f.kind == FindingKind::SaltLength(8));
    assert_eq!(x.part, Part::Disclosure(0));
}
