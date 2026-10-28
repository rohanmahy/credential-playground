//! Every disclosure-matching report category (SPEC §6 "SD", sd-cwt-08 §7,
//! §9 step 8, Appendix G) and SD structural diagnostics.

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
use tokenator_cbor::Item;
use tokenator_cose::kbt::{Selection, disclose};
use tokenator_cose::sd::{
    DisclosureContent, Forbidden, ForbiddenReason, KeyCollision, MalformedDisclosure, MatchMode,
    SdAlg, SdReport, encode_disclosure, match_disclosures, parse_sd_cwt,
};
use tokenator_cose::{Bucket, DiagnosticKind, HashAlg, Label, Part, Sign1Backend, Sign1Parts};

const SALT: [u8; 16] = [0x5a; 16];

/// An (unsigned) SD-CWT with the given protected header, payload, and
/// `sd_claims` elements (already items, so non-bstr elements are possible).
fn token_with(
    protected: &Item<'_>,
    payload: &Item<'_>,
    sd_claims: Option<Vec<Item<'_>>>,
) -> Vec<u8> {
    let unprotected = match sd_claims {
        Some(items) => map(vec![(int(17), arr(items))]),
        None => map(vec![]),
    };
    B.assemble(&Sign1Parts {
        tags: vec![18],
        protected: Cow::Owned(enc(protected)),
        unprotected,
        payload: Some(Cow::Owned(enc(payload))),
        signature: Cow::Borrowed(&[]),
    })
}

fn sd_protected<'a>() -> Item<'a> {
    map(vec![
        (int(1), int(-7)),
        (int(16), int(293)),
        (int(170), int(-16)),
    ])
}

/// SD-CWT whose payload and disclosures are given; sd_alg SHA-256.
fn simple_token(payload: &Item<'_>, disclosures: &[Vec<u8>]) -> Vec<u8> {
    let items = disclosures.iter().map(|d| bs(d)).collect();
    token_with(&sd_protected(), payload, Some(items))
}

fn digest(contents: &[u8]) -> Vec<u8> {
    sha256(&bstr_item(contents))
}

/// The report borrows from `bytes`, not from the parsed SD-CWT.
fn report(bytes: &[u8]) -> SdReport<'_> {
    match_disclosures(&parse_sd_cwt(&B, bytes).unwrap())
}

fn claim(value: Item<'_>, key: Item<'_>) -> Vec<u8> {
    encode_disclosure(&SALT, Some(&value), Some(&key))
}

fn element(value: Item<'_>) -> Vec<u8> {
    encode_disclosure(&SALT, Some(&value), None)
}

fn redacted_keys<'a>(digests: &[Vec<u8>]) -> (Item<'a>, Item<'a>) {
    (simple(59), arr(digests.iter().map(|d| bs(d)).collect()))
}

// ------------------------------------------------------------ unmatched / duplicates

#[test]
fn unmatched_disclosure() {
    let fx = token(SD_ISSUER);
    let mut ds = disclosures_of(&fx);
    ds.push(claim(text("forged"), int(999)));
    let payload = tokenator_cbor::decode(&payload_of(&fx))
        .unwrap()
        .into_owned();
    let bytes = simple_token(&payload, &ds);
    let r = report(&bytes);
    assert_eq!(r.unmatched, [5]);
    assert_eq!(r.matched.len(), 5);
    assert!(!r.is_valid(MatchMode::Verifier));
    assert!(!r.is_valid(MatchMode::Holder));
}

#[test]
fn duplicate_disclosure() {
    let d = claim(tru(), int(500));
    let payload = map(vec![(int(1), text("i")), redacted_keys(&[digest(&d)])]);
    let bytes = simple_token(&payload, &[d.clone(), d]);
    let r = report(&bytes);
    assert_eq!(r.matched.len(), 1);
    assert_eq!(r.duplicate_disclosures, [1]);
    assert!(r.unmatched.is_empty());
    assert!(!r.is_valid(MatchMode::Verifier));
}

#[test]
fn duplicate_digests() {
    let d = claim(tru(), int(500));
    let dg = digest(&d);
    let payload = map(vec![
        (int(1), text("i")),
        redacted_keys(&[dg.clone(), dg.clone()]),
    ]);
    let tok = simple_token(&payload, std::slice::from_ref(&d));
    let r = report(&tok);
    assert_eq!(r.duplicate_digests, std::slice::from_ref(&dg));
    assert!(!r.is_valid(MatchMode::Verifier));

    // The same digest as a key and as an element.
    let payload = map(vec![
        (int(1), arr(vec![tag(60, bs(&dg))])),
        redacted_keys(std::slice::from_ref(&dg)),
    ]);
    let tok = simple_token(&payload, &[d]);
    let r = report(&tok);
    assert_eq!(r.duplicate_digests, std::slice::from_ref(&dg));

    // Undisclosed duplicates count too.
    let payload = map(vec![redacted_keys(&[vec![1; 32], vec![1; 32]])]);
    let tok = simple_token(&payload, &[]);
    let r = report(&tok);
    assert_eq!(r.duplicate_digests, [vec![1; 32]]);
}

// ------------------------------------------------------------ undisclosed

#[test]
fn undisclosed_digests_in_document_order() {
    let payload = map(vec![
        (
            int(1),
            arr(vec![tag(60, bs(&[1; 32])), int(5), tag(60, bs(&[2; 32]))]),
        ),
        redacted_keys(&[vec![3; 32]]),
    ]);
    // No sd_claims at all: an empty sd_claims array is invalid (§9 step 2).
    let tok = token_with(&sd_protected(), &payload, None);
    let r = report(&tok);
    let got: Vec<_> = r
        .undisclosed
        .iter()
        .map(|s| (s.digest[0], s.position))
        .collect();
    assert_eq!(got, [(1, 0), (2, 2), (3, 0)]);
    assert!(r.is_valid(MatchMode::Verifier));
    assert!(!r.is_valid(MatchMode::Holder));
    // Removed from the processed claims.
    assert_eq!(
        enc(r.processed.as_ref().unwrap()),
        enc(&map(vec![(int(1), arr(vec![int(5)]))]))
    );
}

#[test]
fn disclosure_order_does_not_matter() {
    let fx = token(SD_NESTED_ISSUER);
    let reversed = disclose(&B, &fx, &Selection::Indices((0..15).rev().collect())).unwrap();
    let a = report(&fx);
    let b = report(&reversed);
    assert!(b.is_valid(MatchMode::Holder), "{b:?}");
    assert_eq!(
        enc(a.processed.as_ref().unwrap()),
        enc(b.processed.as_ref().unwrap())
    );
}

// ------------------------------------------------------------ forbidden

#[test]
fn never_redacted_claims_are_forbidden_at_top_level() {
    for key in [1, 3, 4, 5, 6, 7, 8, 39] {
        let d = claim(text("x"), int(key));
        let payload = map(vec![redacted_keys(&[digest(&d)])]);
        let tok = simple_token(&payload, &[d]);
        let r = report(&tok);
        assert_eq!(
            r.forbidden,
            [Forbidden {
                disclosure: 0,
                reason: ForbiddenReason::NeverRedactedClaim(key)
            }],
            "claim {key}"
        );
        assert!(!r.is_valid(MatchMode::Verifier));
    }
    // sub (2) may be redacted; and below the top level anything goes.
    for (payload_key, key) in [(None, 2), (Some(503), 1)] {
        let d = claim(text("x"), int(key));
        let rk = redacted_keys(&[digest(&d)]);
        let payload = match payload_key {
            None => map(vec![rk]),
            Some(k) => map(vec![(int(k), map(vec![rk]))]),
        };
        let tok = simple_token(&payload, &[d]);
        let r = report(&tok);
        assert!(r.forbidden.is_empty(), "{key}: {:?}", r.forbidden);
        assert!(r.is_valid(MatchMode::Holder));
    }
}

#[test]
fn pre_issuance_tags_in_disclosures_are_forbidden() {
    for t in [58u64, 62] {
        let d = claim(arr(vec![tag(t, int(1))]), int(500));
        let payload = map(vec![redacted_keys(&[digest(&d)])]);
        let tok = simple_token(&payload, &[d]);
        let r = report(&tok);
        assert_eq!(
            r.forbidden,
            [Forbidden {
                disclosure: 0,
                reason: ForbiddenReason::PreIssuanceTag(t)
            }]
        );
    }
}

#[test]
fn kind_mismatch_is_forbidden() {
    // A claim disclosure whose digest is an array element.
    let d = claim(tru(), int(500));
    let payload = map(vec![(int(1), arr(vec![tag(60, bs(&digest(&d)))]))]);
    let tok = simple_token(&payload, &[d]);
    let r = report(&tok);
    assert_eq!(
        r.forbidden,
        [Forbidden {
            disclosure: 0,
            reason: ForbiddenReason::KindMismatch
        }]
    );
    // An element disclosure whose digest is a redacted claim key.
    let d = element(int(7));
    let payload = map(vec![redacted_keys(&[digest(&d)])]);
    let tok = simple_token(&payload, &[d]);
    let r = report(&tok);
    assert_eq!(r.forbidden[0].reason, ForbiddenReason::KindMismatch);
    // A decoy fits either kind.
    let dk = encode_disclosure(&[1; 16], None, None);
    let de = encode_disclosure(&[2; 16], None, None);
    let payload = map(vec![
        (int(1), arr(vec![tag(60, bs(&digest(&de)))])),
        redacted_keys(&[digest(&dk)]),
    ]);
    let tok = simple_token(&payload, &[dk, de]);
    let r = report(&tok);
    assert!(r.forbidden.is_empty());
    assert!(r.is_valid(MatchMode::Holder));
}

// ------------------------------------------------------------ malformed

#[test]
fn each_malformed_disclosure() {
    let cases: Vec<(Item<'static>, MalformedDisclosure)> = vec![
        (int(1), MalformedDisclosure::NotBytes),
        (bs(&[0xff]), MalformedDisclosure::NotCbor),
        (bs(&h("8001")), MalformedDisclosure::NotCbor),
        (bs(&h("a0")), MalformedDisclosure::NotArray),
        (bs(&h("80")), MalformedDisclosure::WrongLength(0)),
        (
            bs(&enc(&arr(vec![bs(&SALT), int(1), int(2), int(3)]))),
            MalformedDisclosure::WrongLength(4),
        ),
        (
            bs(&enc(&arr(vec![int(1), int(2)]))),
            MalformedDisclosure::SaltNotBytes,
        ),
        (
            bs(&enc(&arr(vec![bs(&SALT), int(1), bs(b"k")]))),
            MalformedDisclosure::KeyNotLabel,
        ),
        (
            bs(&enc(&arr(vec![bs(&SALT), int(1), simple(59)]))),
            MalformedDisclosure::KeyNotLabel,
        ),
    ];
    for (item, kind) in cases {
        let payload = map(vec![(int(1), text("i"))]);
        let bytes = token_with(&sd_protected(), &payload, Some(vec![item]));
        let sd = parse_sd_cwt(&B, &bytes).unwrap();
        assert_eq!(
            sd.disclosures[0].content,
            DisclosureContent::Malformed(kind.clone()),
            "{kind:?}"
        );
        let r = match_disclosures(&sd);
        assert_eq!(r.malformed, [0], "{kind:?}");
        assert!(r.unmatched.is_empty(), "malformed is not also unmatched");
        assert!(!r.is_valid(MatchMode::Verifier));
    }
}

#[test]
fn not_bytes_disclosure_has_no_digest() {
    let payload = map(vec![(int(1), text("i"))]);
    let bytes = token_with(&sd_protected(), &payload, Some(vec![int(1)]));
    let sd = parse_sd_cwt(&B, &bytes).unwrap();
    assert_eq!(sd.disclosures[0].digest, None);
    // A malformed bstr still has a digest (it can be matched by bytes).
    let bytes = token_with(&sd_protected(), &payload, Some(vec![bs(&[0xff])]));
    let sd = parse_sd_cwt(&B, &bytes).unwrap();
    assert_eq!(sd.disclosures[0].digest, Some(digest(&[0xff])));
}

// ------------------------------------------------------------ collisions

#[test]
fn disclosed_key_collides_with_existing_key() {
    let d = claim(tru(), int(500));
    let payload = map(vec![
        (int(500), Item::new(tokenator_cbor::Value::Bool(false))),
        redacted_keys(&[digest(&d)]),
    ]);
    let tok = simple_token(&payload, &[d]);
    let r = report(&tok);
    assert_eq!(
        r.key_collisions,
        [KeyCollision {
            disclosure: 0,
            key: Label::Int(500)
        }]
    );
    assert!(!r.is_valid(MatchMode::Verifier));

    // Two disclosures with the same key in one map.
    let d1 = encode_disclosure(&[1; 16], Some(&int(1)), Some(&text("k")));
    let d2 = encode_disclosure(&[2; 16], Some(&int(2)), Some(&text("k")));
    let payload = map(vec![redacted_keys(&[digest(&d1), digest(&d2)])]);
    let tok = simple_token(&payload, &[d1, d2]);
    let r = report(&tok);
    assert_eq!(
        r.key_collisions,
        [KeyCollision {
            disclosure: 1,
            key: Label::Text("k".into())
        }]
    );
}

// ------------------------------------------------------------ sd_alg

#[test]
fn sd_alg_default_known_unsupported_invalid() {
    let d = claim(tru(), int(500));

    // Absent: SHA-256.
    let payload = map(vec![redacted_keys(&[digest(&d)])]);
    let prot = map(vec![(int(1), int(-7))]);
    let bytes = token_with(&prot, &payload, Some(vec![bs(&d)]));
    let r = report(&bytes);
    assert_eq!(r.sd_alg, SdAlg::Default);
    assert_eq!(SdAlg::Default.hash(), Some(HashAlg::Sha256));
    assert!(r.is_valid(MatchMode::Holder));

    // SHA-384 and SHA-512.
    for hash in [HashAlg::Sha384, HashAlg::Sha512] {
        let dg = tokenator_crypto::digest(hash, &bstr_item(&d));
        let payload = map(vec![redacted_keys(&[dg])]);
        let prot = map(vec![(int(1), int(-7)), (int(170), int(hash.cose_label()))]);
        let bytes = token_with(&prot, &payload, Some(vec![bs(&d)]));
        let sd = parse_sd_cwt(&B, &bytes).unwrap();
        assert_eq!(sd.sd_alg, SdAlg::Known(hash));
        assert_eq!(
            sd.disclosures[0].digest.as_ref().unwrap().len(),
            hash.output_len()
        );
        assert!(match_disclosures(&sd).is_valid(MatchMode::Holder));
    }

    // Unsupported and invalid: nothing can be matched.
    for (alg, want) in [
        (int(-999), SdAlg::Unsupported(-999)),
        (text("sha-256"), SdAlg::Invalid),
    ] {
        let prot = map(vec![(int(1), int(-7)), (int(170), alg)]);
        let bytes = token_with(&prot, &payload, Some(vec![bs(&d)]));
        let sd = parse_sd_cwt(&B, &bytes).unwrap();
        assert_eq!(sd.sd_alg, want);
        assert_eq!(want.hash(), None);
        assert_eq!(sd.disclosures[0].digest, None);
        let r = match_disclosures(&sd);
        assert_eq!(r.sd_alg, want);
        assert!(r.matched.is_empty());
        assert!(!r.is_valid(MatchMode::Verifier));
    }
}

// ------------------------------------------------------------ structure

#[test]
fn sd_structural_diagnostics() {
    let payload = map(vec![(int(1), text("i"))]);

    // Empty sd_claims.
    let bytes = token_with(&sd_protected(), &payload, Some(vec![]));
    let sd = parse_sd_cwt(&B, &bytes).unwrap();
    assert!(sd.disclosures.is_empty());
    assert!(
        sd.diagnostics
            .iter()
            .any(|d| d.kind == DiagnosticKind::EmptySdClaims)
    );
    assert!(!match_disclosures(&sd).is_valid(MatchMode::Verifier));

    // sd_claims not an array.
    let bytes = B.assemble(&Sign1Parts {
        tags: vec![18],
        protected: Cow::Owned(enc(&sd_protected())),
        unprotected: map(vec![(int(17), bs(b"x"))]),
        payload: Some(Cow::Owned(enc(&payload))),
        signature: Cow::Borrowed(&[]),
    });
    let sd = parse_sd_cwt(&B, &bytes).unwrap();
    assert!(
        sd.diagnostics
            .iter()
            .any(|d| d.kind == DiagnosticKind::NotArray && d.part == Part::Unprotected)
    );

    // sd_claims in the protected header, sd_alg in the unprotected header.
    let d = claim(tru(), int(500));
    let prot = map(vec![(int(1), int(-7)), (int(17), arr(vec![bs(&d)]))]);
    let bytes = B.assemble(&Sign1Parts {
        tags: vec![18],
        protected: Cow::Owned(enc(&prot)),
        unprotected: map(vec![(int(170), int(-16))]),
        payload: Some(Cow::Owned(enc(&map(vec![redacted_keys(&[digest(&d)])])))),
        signature: Cow::Borrowed(&[]),
    });
    let sd = parse_sd_cwt(&B, &bytes).unwrap();
    let kinds: Vec<_> = sd.diagnostics.iter().map(|d| d.kind.clone()).collect();
    assert!(
        kinds.contains(&DiagnosticKind::MisplacedSdHeader(17)),
        "{kinds:?}"
    );
    assert!(
        kinds.contains(&DiagnosticKind::MisplacedSdHeader(170)),
        "{kinds:?}"
    );
    assert_eq!(sd.sign1.header(17).map(|(b, _)| b), Some(Bucket::Protected));
    // A misplaced sd_alg is not used, and misplaced disclosures are not read.
    assert_eq!(sd.sd_alg, SdAlg::Default);
    assert!(sd.disclosures.is_empty());
}

#[test]
fn processed_is_none_without_a_claims_map() {
    for payload in [h("80"), h("ff"), vec![]] {
        let bytes = B.assemble(&Sign1Parts {
            tags: vec![18],
            protected: Cow::Owned(enc(&sd_protected())),
            unprotected: map(vec![]),
            payload: Some(Cow::Owned(payload)),
            signature: Cow::Borrowed(&[]),
        });
        let r = report(&bytes);
        assert!(r.processed.is_none());
    }
}

#[test]
fn plain_cwt_report_is_trivially_valid() {
    let bytes = token(RFC8392_A3);
    let r = report(&bytes);
    assert_eq!(r.sd_alg, SdAlg::Default);
    assert!(r.matched.is_empty() && r.undisclosed.is_empty());
    assert!(r.is_valid(MatchMode::Holder));
    assert_eq!(enc(r.processed.as_ref().unwrap()), token(RFC8392_A1));
}

#[test]
fn digest_of_a_non_preferred_bstr_head_is_over_received_bytes() {
    // The disclosure bstr uses a 2-byte length (0x59 0x00 0x23): its digest
    // covers those exact bytes, so it does not match the preferred digest.
    let d = claim(tru(), int(500));
    let mut wide = vec![0x59, 0x00, u8::try_from(d.len()).unwrap()];
    wide.extend(&d);
    let payload = map(vec![redacted_keys(&[digest(&d)])]);
    let bytes = token_with(
        &sd_protected(),
        &payload,
        Some(vec![tokenator_cbor::decode(&wide).unwrap().into_owned()]),
    );
    let sd = parse_sd_cwt(&B, &bytes).unwrap();
    assert_eq!(sd.disclosures[0].digest, Some(sha256(&wide)));
    let r = match_disclosures(&sd);
    assert_eq!(r.unmatched, [0]);
    assert_eq!(r.undisclosed.len(), 1);
}
