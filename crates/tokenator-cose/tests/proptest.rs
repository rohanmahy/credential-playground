//! Parsers and manipulation primitives never panic (SPEC §11), on random
//! bytes and on mutated or truncated valid tokens.

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
use proptest::prelude::*;
use tokenator_cose::edit::{DisclosureOp, EquivalentEncoding, TamperOp, edit_disclosures, tamper};
use tokenator_cose::kbt::{KbtOptions, Selection, disclose, verify_kbt};
use tokenator_cose::lint::{LintOptions, lint};
use tokenator_cose::sd::{match_disclosures, parse_sd_cwt};
use tokenator_cose::{Sign1Backend, VerifyOptions};

fn fixtures() -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = SIGN1_FIXTURES.iter().map(|n| token(n)).collect();
    v.push(token(RFC8392_A4));
    v.push(token(RFC8392_A5));
    v.push(token(RFC8392_A7));
    v.push(token(RFC8392_A1));
    v
}

/// Random bytes, or a fixture with some bytes replaced and maybe truncated.
fn input() -> impl Strategy<Value = Vec<u8>> {
    let n = fixtures().len();
    prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..300),
        (
            0..n,
            proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..4),
            proptest::option::of(any::<prop::sample::Index>()),
        )
            .prop_map(|(i, edits, cut)| {
                let mut b = fixtures().swap_remove(i);
                for (at, byte) in edits {
                    let at = at.index(b.len());
                    b[at] = byte;
                }
                if let Some(cut) = cut {
                    b.truncate(cut.index(b.len() + 1));
                }
                b
            }),
    ]
}

fn exercise(bytes: &[u8]) {
    if let Ok(msg) = B.parse(bytes) {
        let _ = (msg.alg(), msg.kid(), msg.typ(), msg.crit(), msg.kind());
        let _ = (
            msg.protected_header(),
            msg.payload_bytes(),
            msg.payload_item(),
        );
        let _ = B.verify(&msg, &rfc8392_key(), &VerifyOptions::default());
    }
    if let Ok(sd) = parse_sd_cwt(&B, bytes) {
        let r = match_disclosures(&sd);
        let _ = r.is_valid(tokenator_cose::sd::MatchMode::Holder);
    }
    let opts = KbtOptions {
        now: SD_NOW,
        skew: 60,
        expected_aud: Some(SD_AUD.into()),
        ..KbtOptions::default()
    };
    if let Ok(r) = verify_kbt(&B, bytes, Some(&sd_issuer()), &opts) {
        let _ = r.is_valid();
    }
    let _ = lint(&B, bytes, &LintOptions::default());
    let _ = disclose(&B, bytes, &Selection::Indices(vec![0, 0]));
    let _ = edit_disclosures(
        &B,
        bytes,
        &[
            DisclosureOp::Duplicate(0),
            DisclosureOp::Move { from: 0, to: 1 },
            DisclosureOp::Forge {
                salt: Cow::Borrowed(&[0; 16]),
                value: None,
                key: None,
            },
        ],
    );
    for op in [
        TamperOp::SwapAlg(-7),
        TamperOp::RemoveAlg,
        TamperOp::StripSignature,
        TamperOp::FlipSignatureBit(0),
        TamperOp::FlipBit { offset: 3, bit: 2 },
        TamperOp::SetKid(Cow::Borrowed(b"k")),
        TamperOp::RemoveKid,
        TamperOp::Truncate(5),
        TamperOp::SetTags(vec![61, 18]),
        TamperOp::ProtectedEquivalent(EquivalentEncoding::WideBstrHead),
        TamperOp::ProtectedEquivalent(EquivalentEncoding::WideIntegers),
        TamperOp::ProtectedEquivalent(EquivalentEncoding::IndefiniteMap),
    ] {
        let _ = tamper(&B, bytes, &op);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn never_panics(bytes in input()) {
        exercise(&bytes);
    }
}

#[test]
fn every_fixture_and_every_truncation() {
    for f in fixtures() {
        for cut in 0..=f.len() {
            exercise(&f[..cut]);
        }
    }
}

#[test]
fn deep_nesting_does_not_overflow() {
    // A COSE_Sign1 whose payload is 1000 nested arrays, and an SD-CWT
    // payload with deeply nested maps.
    let mut payload = vec![0x81; 1000];
    payload.push(0x00);
    let mut bytes = h("d2 84 40 a0 5903e9");
    bytes.extend(&payload);
    bytes.push(0x40);
    exercise(&bytes);

    let mut deep = Vec::new();
    for _ in 0..500 {
        deep.extend([0xa1, 0x01]);
    }
    deep.push(0x00);
    let mut bytes = h("d2 84 40 a1 11 81 40 5903e9");
    bytes.extend(&deep);
    bytes.push(0x40);
    exercise(&bytes);
}
