//! issue → redact → present → verify for every algorithm, with nested
//! redaction, decoys, and every SD hash.

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_cbor::Item;
use tokenator_cose::kbt::{KbtOptions, PresentOptions, Selection, present, verify_kbt};
use tokenator_cose::sd::{
    IssueOptions, MatchMode, RngSalts, SdAlg, issue, match_disclosures, parse_sd_cwt,
};
use tokenator_cose::{Alg, HashAlg, Sign1Backend, VerifyOptions};

const NOW: i64 = 1_800_000_000;

/// Claims with a nested redaction, element and key decoys, and the
/// holder's cnf.
///
/// ```text
/// { 1: "https://issuer.example", 2: "https://holder.example",
///   4: NOW+3600, 5: NOW-60, 6: NOW-60, 8: {1: COSE_Key},
///   58(500): true,
///   501: [58(1), 2, 62(1)],
///   58(502): {58("a"): 1, "b": 2, 62(2): null} }
/// ```
fn claims<'a>(holder: &tokenator_cose::Key) -> Item<'a> {
    map(vec![
        (int(1), text("https://issuer.example")),
        (int(2), text("https://holder.example")),
        (int(4), int(NOW + 3600)),
        (int(5), int(NOW - 60)),
        (int(6), int(NOW - 60)),
        (int(8), cnf_for(holder)),
        (tbr(int(500)), tru()),
        (int(501), arr(vec![tbr(int(1)), int(2), decoy(1)])),
        (
            tbr(int(502)),
            map(vec![
                (tbr(text("a")), int(1)),
                (text("b"), int(2)),
                (decoy(2), null()),
            ]),
        ),
    ])
}

fn processed_all<'a>(holder: &tokenator_cose::Key) -> Item<'a> {
    map(vec![
        (int(1), text("https://issuer.example")),
        (int(2), text("https://holder.example")),
        (int(4), int(NOW + 3600)),
        (int(5), int(NOW - 60)),
        (int(6), int(NOW - 60)),
        (int(8), cnf_for(holder)),
        (int(501), arr(vec![int(1), int(2)])),
        (int(500), tru()),
        (
            int(502),
            map(vec![(text("b"), int(2)), (text("a"), int(1))]),
        ),
    ])
}

fn round_trip(alg: Alg, hash: HashAlg, seed: u8) {
    let issuer = key_for(alg, 1);
    let holder = key_for(alg, 2);
    let mut opts = IssueOptions::new(alg);
    opts.sd_alg = Some(hash);
    let mut salt_rng = rng(seed);
    let mut sig_rng = rng(seed.wrapping_add(100));
    let issued = issue(
        &B,
        &claims(&holder),
        &issuer,
        &opts,
        &mut RngSalts::new(&mut salt_rng),
        Some(&mut sig_rng),
    )
    .unwrap_or_else(|e| panic!("{alg:?}: {e:?}"));
    // 500, 1, decoy 1, "a", decoy 2, 502.
    assert_eq!(issued.disclosures.len(), 6, "{alg:?}");

    // Holder validation.
    let sd = parse_sd_cwt(&B, &issued.bytes).unwrap();
    assert_eq!(sd.sd_alg, SdAlg::Known(hash));
    assert_eq!(
        B.verify(&sd.sign1, &public(&issuer), &VerifyOptions::default()),
        Ok(alg),
        "{alg:?}"
    );
    let report = match_disclosures(&sd);
    assert!(report.is_valid(MatchMode::Holder), "{alg:?}: {report:?}");
    assert_eq!(
        enc(report.processed.as_ref().unwrap()),
        enc(&processed_all(&holder)),
        "{alg:?}"
    );

    // Present everything, then a subset.
    for (selection, undisclosed) in [(Selection::All, 0), (Selection::Indices(vec![0]), 3)] {
        let mut p = PresentOptions::new(alg);
        p.selection = selection;
        p.aud = Some("https://verifier.example".into());
        p.iat = Some(NOW);
        p.cnonce = Some(b"nonce".to_vec().into());
        let mut kbt_rng = rng(seed.wrapping_add(200));
        let kbt = present(&B, &issued.bytes, &holder, &p, Some(&mut kbt_rng))
            .unwrap_or_else(|e| panic!("{alg:?}: {e:?}"));
        let kopts = KbtOptions {
            now: NOW,
            skew: 60,
            expected_aud: Some("https://verifier.example".into()),
            expected_cnonce: Some(b"nonce".to_vec().into()),
            max_age: Some(300),
            holder_keys: vec![],
        };
        let r = verify_kbt(&B, &kbt, Some(&public(&issuer)), &kopts).unwrap();
        assert!(r.is_valid(), "{alg:?}: {r:?}");
        assert_eq!(r.issuer_signature, Ok(alg));
        assert_eq!(r.kbt_signature, Ok(alg));
        assert_eq!(
            r.sd.as_ref().unwrap().undisclosed.len(),
            undisclosed,
            "{alg:?}"
        );
    }
}

#[test]
fn round_trip_every_alg() {
    for (i, alg) in Alg::ALL.into_iter().enumerate() {
        round_trip(alg, HashAlg::Sha256, u8::try_from(i).unwrap());
    }
}

#[test]
fn round_trip_every_sd_hash() {
    for hash in [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512] {
        round_trip(Alg::Ed25519, hash, 42);
    }
}

#[test]
fn issuer_and_holder_with_different_algs() {
    let issuer = key_for(Alg::MlDsa44, 1);
    let holder = key_for(Alg::ES384, 2);
    let issued = issue(
        &B,
        &claims(&holder),
        &issuer,
        &IssueOptions::new(Alg::MlDsa44),
        &mut RngSalts::new(&mut rng(1)),
        None,
    )
    .unwrap();
    let mut p = PresentOptions::new(Alg::ES384);
    p.aud = Some("v".into());
    p.iat = Some(NOW);
    let kbt = present(&B, &issued.bytes, &holder, &p, None).unwrap();
    let kopts = KbtOptions {
        now: NOW,
        skew: 60,
        ..KbtOptions::default()
    };
    let r = verify_kbt(&B, &kbt, Some(&issuer), &kopts).unwrap();
    assert!(r.is_valid(), "{r:?}");
    assert_eq!(r.issuer_signature, Ok(Alg::MlDsa44));
    assert_eq!(r.kbt_signature, Ok(Alg::ES384));
}

#[test]
fn seeded_issuance_is_reproducible() {
    let issuer = key_for(Alg::Ed25519, 1);
    let holder = key_for(Alg::Ed25519, 2);
    let run = || {
        issue(
            &B,
            &claims(&holder),
            &issuer,
            &IssueOptions::new(Alg::Ed25519),
            &mut RngSalts::new(&mut rng(3)),
            None,
        )
        .unwrap()
        .bytes
    };
    assert_eq!(run(), run());
}

#[test]
fn re_presenting_a_kbt_inner_token() {
    // A verifier-side SD-CWT taken from a KBT can be presented again by
    // the holder with fewer disclosures.
    let kbt = token(SD_KBT);
    let inner = kcwt_of(&kbt);
    let mut p = PresentOptions::new(Alg::ES256);
    p.selection = Selection::Indices(vec![2]);
    p.aud = Some(SD_AUD.into());
    p.iat = Some(SD_KBT_IAT);
    let again = present(&B, &inner, &sd_holder(), &p, None).unwrap();
    let kopts = KbtOptions {
        now: SD_NOW,
        skew: 60,
        ..KbtOptions::default()
    };
    let r = verify_kbt(&B, &again, Some(&sd_issuer()), &kopts).unwrap();
    assert!(r.is_valid(), "{r:?}");
    assert_eq!(r.sd.as_ref().unwrap().matched.len(), 1);
}
