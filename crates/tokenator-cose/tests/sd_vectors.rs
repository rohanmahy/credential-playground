//! Every draft-ietf-spice-sd-cwt-08 example: signatures, disclosures,
//! digests, slots, and processed claims (§3.2, §10, §14.1, §14.2,
//! Appendix C, Appendix D).

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_cbor::{Item, Span, Value};
use tokenator_cose::kbt::{KbtOptions, verify_kbt};
use tokenator_cose::sd::{
    DisclosureContent, Match, MatchMode, PathSeg, SdAlg, SdCwt, SdReport, Slot, SlotKind,
    disclosure_digest, match_disclosures, parse_sd_cwt,
};
use tokenator_cose::{Alg, HashAlg, Label, Sign1Backend, VerifyOptions};

fn sd(bytes: &[u8]) -> SdCwt<'_> {
    parse_sd_cwt(&B, bytes).unwrap()
}

fn payload() -> Vec<PathSeg> {
    vec![PathSeg::Payload]
}

fn at(key: i64) -> Vec<PathSeg> {
    vec![PathSeg::Payload, PathSeg::Key(Label::Int(key))]
}

fn in_disclosure(i: usize) -> Vec<PathSeg> {
    vec![PathSeg::Disclosure(i)]
}

/// (container, position, kind) of each match, in disclosure order.
fn slots(r: &SdReport<'_>) -> Vec<(usize, Vec<PathSeg>, usize, SlotKind)> {
    r.matched
        .iter()
        .map(|m| {
            (
                m.disclosure,
                m.slot.container.clone(),
                m.slot.position,
                m.slot.kind,
            )
        })
        .collect()
}

fn sorted_undisclosed(r: &SdReport<'_>) -> Vec<Vec<u8>> {
    let mut v: Vec<_> = r.undisclosed.iter().map(|s| s.digest.clone()).collect();
    v.sort();
    v
}

fn assert_clean(r: &SdReport<'_>) {
    assert!(r.unmatched.is_empty(), "unmatched {:?}", r.unmatched);
    assert!(r.duplicate_disclosures.is_empty());
    assert!(r.duplicate_digests.is_empty());
    assert!(r.forbidden.is_empty(), "{:?}", r.forbidden);
    assert!(r.malformed.is_empty());
    assert!(r.key_collisions.is_empty());
}

fn kbt_opts() -> KbtOptions<'static> {
    KbtOptions {
        now: SD_NOW,
        skew: 60,
        expected_aud: Some(SD_AUD.into()),
        expected_cnonce: Some(h(SD_CNONCE).into()),
        ..KbtOptions::default()
    }
}

// ------------------------------------------------------------ signatures

#[test]
fn issuer_signatures_verify_with_c2_key() {
    let issuer = sd_issuer();
    for name in [SD_ISSUER, SD_NESTED_ISSUER, SD_DECOY] {
        let bytes = token(name);
        let msg = B.parse(&bytes).unwrap();
        assert_eq!(
            B.verify(&msg, &issuer, &VerifyOptions::default()),
            Ok(Alg::ES384),
            "{name}"
        );
        assert_eq!(
            B.verify(&msg, &public(&issuer), &VerifyOptions::default()),
            Ok(Alg::ES384)
        );
    }
}

#[test]
fn issuer_signature_values_match_the_draft() {
    assert!(hex::encode(signature_of(&token(SD_ISSUER))).starts_with("12bdb0136ed93db0"));
    assert!(hex::encode(signature_of(&token(SD_DECOY))).starts_with("a96d92f340e37ab5"));
    assert!(hex::encode(signature_of(&token(SD_KBT))).starts_with("ca38c411693201ce"));
}

#[test]
fn kbt_inner_and_outer_signatures() {
    for name in [SD_KBT, SD_NESTED_KBT] {
        let kbt = token(name);
        let msg = B.parse(&kbt).unwrap();
        assert_eq!(
            B.verify(&msg, &public(&sd_holder()), &VerifyOptions::default()),
            Ok(Alg::ES256),
            "{name}"
        );
        let inner = kcwt_of(&kbt);
        let msg = B.parse(&inner).unwrap();
        assert_eq!(
            B.verify(&msg, &sd_issuer(), &VerifyOptions::default()),
            Ok(Alg::ES384),
            "{name}"
        );
    }
}

#[test]
fn sd_kbt_inner_is_issuer_token_with_chosen_disclosures() {
    let issuer = token(SD_ISSUER);
    let inner = kcwt_of(&token(SD_KBT));
    assert_eq!(protected_of(&inner), protected_of(&issuer));
    assert_eq!(payload_of(&inner), payload_of(&issuer));
    assert_eq!(signature_of(&inner), signature_of(&issuer));
    let all = disclosures_of(&issuer);
    assert_eq!(
        disclosures_of(&inner),
        [all[0].clone(), all[1].clone(), all[3].clone()]
    );
}

// ------------------------------------------------------------ disclosures

#[test]
fn issuer_disclosures() {
    let bytes = token(SD_ISSUER);
    let s = sd(&bytes);
    assert_eq!(s.sd_alg, SdAlg::Known(HashAlg::Sha256));
    assert!(s.diagnostics.is_empty(), "{:?}", s.diagnostics);
    assert_eq!(s.disclosures.len(), 5);

    let d = &s.disclosures;
    let DisclosureContent::Claim { salt, value, key } = &d[0].content else {
        panic!("{:?}", d[0].content)
    };
    assert_eq!(&salt[..], h("bae611067bb823486797da1ebbb52f83"));
    assert_eq!(enc(value), enc(&text("ABCD-123456")));
    assert_eq!(enc(key), enc(&int(501)));

    let DisclosureContent::Element { salt, value } = &d[1].content else {
        panic!("{:?}", d[1].content)
    };
    assert_eq!(&salt[..], h("8de86a012b3043ae6e4457b9e1aaab80"));
    assert_eq!(enc(value), enc(&int(1_549_560_720)));

    let DisclosureContent::Element { value, .. } = &d[2].content else {
        panic!()
    };
    assert_eq!(enc(value), enc(&int(1_612_560_720)));

    let DisclosureContent::Claim { value, key, .. } = &d[3].content else {
        panic!()
    };
    assert_eq!(
        (enc(value), enc(key)),
        (enc(&text("ca")), enc(&text("region")))
    );

    let DisclosureContent::Claim { value, key, .. } = &d[4].content else {
        panic!()
    };
    assert_eq!(
        (enc(value), enc(key)),
        (enc(&text("94188")), enc(&text("postal_code")))
    );

    for (i, d) in d.iter().enumerate() {
        assert_eq!(d.index, i);
    }
}

#[test]
fn figure7_disclosure_bytes() {
    let bytes = token(SD_ISSUER);
    let s = sd(&bytes);
    let d0 = &s.disclosures[0];
    assert_eq!(
        &d0.bytes.raw[..],
        h("8350bae611067bb823486797da1ebbb52f836b414243442d3132333435361901f5")
    );
    // The bstr sits right after the sd_claims array head: 18([h'…'(0x58 0x2e …),
    // {17: [ …. Its span covers the 0x58 0x21 head.
    assert_eq!(d0.bytes.span.head_len, 2);
    assert_eq!(d0.bytes.span.end - d0.bytes.span.start, 35);
    assert_eq!(
        &bytes[d0.bytes.span.start..d0.bytes.span.end],
        bstr_item(&d0.bytes.raw)
    );
}

#[test]
fn digests_hash_the_encoded_bstr() {
    let bytes = token(SD_ISSUER);
    let s = sd(&bytes);
    let want = [
        "af375dc3fba1d082448642c00be7b2f7bb05c9d8fb61cfc230ddfdfb4616a693",
        "1b7fc8ecf4b1290712497d226c04b503b4aa126c603c83b75d2679c3c613f3fd",
        "64afccd3ad52da405329ad935de1fb36814ec48fdfd79e3a108ef858e291e146",
        "0d4b8c6123f287a1698ff2db15764564a976fb742606e8fd00e2140656ba0df3",
        "c0b7747f960fc2e201c4d47c64fee141b78e3ab768ce941863dc8914e8f5815f",
    ];
    for (d, w) in s.disclosures.iter().zip(want) {
        assert_eq!(
            d.digest.as_deref(),
            Some(&h(w)[..]),
            "disclosure {}",
            d.index
        );
        assert_eq!(disclosure_digest(HashAlg::Sha256, &d.bytes.raw), h(w));
    }
}

#[test]
fn figure8_erratum_hashes_contents_only() {
    // Figures 8 and 9 show d9df03da…, the hash of the contents without the
    // bstr head. The signed payload carries af375dc3… (decision 1).
    let contents = h("8350bae611067bb823486797da1ebbb52f836b414243442d3132333435361901f5");
    assert_eq!(
        sha256(&contents),
        h("d9df03da474fcb3c65771748e2e0608cf437504ecc24f450aaeacd40dd552b3f")
    );
    assert_ne!(
        disclosure_digest(HashAlg::Sha256, &contents),
        sha256(&contents)
    );
    let payload = payload_of(&token(SD_ISSUER));
    let needle = h("d9df03da474fcb3c65771748e2e0608cf437504ecc24f450aaeacd40dd552b3f");
    assert!(!payload.windows(32).any(|w| w == needle));
}

#[test]
fn decoy_disclosures() {
    let bytes = token(SD_DECOY);
    let s = sd(&bytes);
    assert_eq!(s.disclosures.len(), 4);
    assert!(matches!(
        s.disclosures[0].content,
        DisclosureContent::Element { .. }
    ));
    let DisclosureContent::Decoy { salt } = &s.disclosures[1].content else {
        panic!()
    };
    // Figure 19 shows this salt in upper case.
    assert_eq!(&salt[..], h("C1069BC056E234D64F58BAFF8A7B776B"));
    assert!(matches!(
        s.disclosures[2].content,
        DisclosureContent::Claim { .. }
    ));
    assert!(matches!(
        s.disclosures[3].content,
        DisclosureContent::Decoy { .. }
    ));
    let want = [
        "dc5f753b66acd89d78481039934a86cc14f9959c64c4037dea3f872b9a8453f1",
        "3f80963a1246b412d6567f2a5ca446fd19a01dd8cfc291bed69e8c575c5abfb8",
        "bd0fd88127b3071ff5433eef59a5e3c5f18341f25c5bd119c41fd34802a9797b",
        "eeec970897a5b9108f24f44751baedabb53a1f3d241ab6b60c9f309f114ecf88",
    ];
    for (d, w) in s.disclosures.iter().zip(want) {
        assert_eq!(d.digest.as_deref(), Some(&h(w)[..]));
    }
}

#[test]
fn nested_disclosure_digests_match_figure28_comments() {
    let bytes = token(SD_NESTED_KBT);
    let inner = kcwt_of(&bytes);
    let s = sd(&inner);
    let prefixes = [
        "20d9bb11", "2470fb91", "7257a869", "9d151abe", "af375dc3", "c24c646b", "ca6b8516",
    ];
    assert_eq!(s.disclosures.len(), 7);
    for (d, p) in s.disclosures.iter().zip(prefixes) {
        assert!(
            hex::encode(d.digest.as_ref().unwrap()).starts_with(p),
            "disclosure {}",
            d.index
        );
    }
}

// ------------------------------------------------------------ matching

#[test]
fn issuer_matching_and_slots() {
    let bytes = token(SD_ISSUER);
    let s = sd(&bytes);
    let r = match_disclosures(&s);
    assert_clean(&r);
    assert_eq!(r.sd_alg, SdAlg::Known(HashAlg::Sha256));
    assert!(r.undisclosed.is_empty());
    assert_eq!(
        slots(&r),
        [
            (0, payload(), 0, SlotKind::ClaimKey),
            (1, at(502), 0, SlotKind::ArrayElement),
            (2, at(502), 1, SlotKind::ArrayElement),
            (3, at(503), 0, SlotKind::ClaimKey),
            (4, at(503), 1, SlotKind::ClaimKey),
        ]
    );
    assert!(r.is_valid(MatchMode::Holder));
    assert!(r.is_valid(MatchMode::Verifier));
}

#[test]
fn slot_digest_and_span() {
    let bytes = token(SD_ISSUER);
    let s = sd(&bytes);
    let r = match_disclosures(&s);
    for Match { disclosure, slot } in &r.matched {
        let digest = s.disclosures[*disclosure].digest.clone().unwrap();
        assert_eq!(slot.digest, digest);
        // The span is the digest bstr item (inside tag 60 for elements).
        let pos = bytes.windows(32).position(|w| w == digest).unwrap();
        assert_eq!(
            slot.span,
            Span {
                start: pos - 2,
                end: pos + 32,
                head_len: 2
            }
        );
    }
}

#[test]
fn issuer_processed_claims() {
    let bytes = token(SD_ISSUER);
    let s = sd(&bytes);
    let r = match_disclosures(&s);
    assert_eq!(enc(r.processed.as_ref().unwrap()), enc(&issuer_processed()));
}

#[test]
fn sd_kbt_matching_withheld_claims() {
    let bytes = token(SD_KBT);
    let inner = kcwt_of(&bytes);
    let s = sd(&inner);
    let r = match_disclosures(&s);
    assert_clean(&r);
    assert_eq!(
        slots(&r),
        [
            (0, payload(), 0, SlotKind::ClaimKey),
            (1, at(502), 0, SlotKind::ArrayElement),
            (2, at(503), 0, SlotKind::ClaimKey),
        ]
    );
    let undisclosed: Vec<(Vec<PathSeg>, usize, SlotKind, Vec<u8>)> = r
        .undisclosed
        .iter()
        .map(|s| (s.container.clone(), s.position, s.kind, s.digest.clone()))
        .collect();
    assert_eq!(
        undisclosed,
        [
            (
                at(502),
                1,
                SlotKind::ArrayElement,
                h("64afccd3ad52da405329ad935de1fb36814ec48fdfd79e3a108ef858e291e146")
            ),
            (
                at(503),
                1,
                SlotKind::ClaimKey,
                h("c0b7747f960fc2e201c4d47c64fee141b78e3ab768ce941863dc8914e8f5815f")
            ),
        ]
    );
    assert!(r.is_valid(MatchMode::Verifier));
    assert!(!r.is_valid(MatchMode::Holder));

    let mut m = sd_standard_claims();
    m.push((int(500), tru()));
    m.push((int(502), arr(vec![int(1_549_560_720), int(1_674_004_740)])));
    m.push((
        int(503),
        map(vec![
            (text("country"), text("us")),
            (text("region"), text("ca")),
        ]),
    ));
    m.push((int(501), text("ABCD-123456")));
    assert_eq!(enc(r.processed.as_ref().unwrap()), enc(&map(m)));
}

fn record<'a>(date: i64, license: &'a str, location: Vec<(Item<'a>, Item<'a>)>) -> Item<'a> {
    map(vec![
        (int(500), tru()),
        (int(502), int(date)),
        (int(501), text(license)),
        (int(503), map(location)),
    ])
}

#[test]
fn nested_issuer_fully_disclosed() {
    let bytes = token(SD_NESTED_ISSUER);
    let s = sd(&bytes);
    assert_eq!(s.disclosures.len(), 15);
    let r = match_disclosures(&s);
    assert_clean(&r);
    assert!(r.undisclosed.is_empty());
    assert_eq!(r.matched.len(), 15);
    assert!(r.is_valid(MatchMode::Holder));

    let loc = |region: &'static str, post: &'static str| {
        vec![
            (int(1), text("us")),
            (int(2), text(region)),
            (int(3), text(post)),
        ]
    };
    let mut m = sd_standard_claims();
    m.push((
        int(504),
        arr(vec![
            record(1_549_560_720, "DCBA-101777", loc("co", "80302")),
            record(1_612_560_720, "EFGH-789012", loc("nv", "89155")),
            record(1_674_004_740, "ABCD-123456", loc("ca", "94188")),
        ]),
    ));
    // Figure 27 order, which is also the reconstruction order here.
    assert_eq!(enc(r.processed.as_ref().unwrap()), enc(&map(m)));
}

#[test]
fn nested_issuer_slots_inside_disclosures() {
    let bytes = token(SD_NESTED_ISSUER);
    let s = sd(&bytes);
    let r = match_disclosures(&s);
    // Post-order: 0 DCBA, 1 co, 2 80302, 3 Denver location, 4 record 2019, ...
    let got = slots(&r);
    assert_eq!(got[0], (0, in_disclosure(4), 0, SlotKind::ClaimKey));
    assert_eq!(got[1], (1, in_disclosure(3), 0, SlotKind::ClaimKey));
    assert_eq!(got[2], (2, in_disclosure(3), 1, SlotKind::ClaimKey));
    assert_eq!(got[3], (3, in_disclosure(4), 1, SlotKind::ClaimKey));
    assert_eq!(got[4], (4, at(504), 0, SlotKind::ArrayElement));
    assert_eq!(got[9], (9, at(504), 1, SlotKind::ArrayElement));
    assert_eq!(got[14], (14, at(504), 2, SlotKind::ArrayElement));
}

#[test]
fn nested_slot_spans_point_into_disclosures() {
    let bytes = token(SD_NESTED_ISSUER);
    let s = sd(&bytes);
    let r = match_disclosures(&s);
    let m = &r.matched[1]; // "co", whose digest sits in disclosure 3
    let d3 = &s.disclosures[3].bytes.span;
    assert!(m.slot.span.start > d3.start && m.slot.span.end <= d3.end);
    assert_eq!(
        &bytes[m.slot.span.start + 2..m.slot.span.end],
        m.slot.digest
    );
}

#[test]
fn nested_kbt_partial_disclosure() {
    let bytes = token(SD_NESTED_KBT);
    let inner = kcwt_of(&bytes);
    let s = sd(&inner);
    let r = match_disclosures(&s);
    assert_clean(&r);
    assert_eq!(
        slots(&r),
        [
            (0, at(504), 2, SlotKind::ArrayElement),
            (1, in_disclosure(3), 0, SlotKind::ClaimKey),
            (2, in_disclosure(6), 0, SlotKind::ClaimKey),
            (3, in_disclosure(0), 1, SlotKind::ClaimKey),
            (4, in_disclosure(0), 0, SlotKind::ClaimKey),
            (5, in_disclosure(6), 1, SlotKind::ClaimKey),
            (6, at(504), 0, SlotKind::ArrayElement),
        ]
    );
    let mut want = vec![
        h("0dfdc69d0efb65eec14bf28af78cd8f06cabfe8e2b1a0611ef8bca869ce35b61"),
        h("1b89717167f39d51eec08b13baeda570eff5d0aedaa1d7d0821185c33634a5a0"),
        h("49412884fa1e3787c17d1320bdd48f6e0e5365da010cde0571d4a7effd13cc2a"),
        h("cf397a08917528624ca3b332c9edcc54a72c9411dd5983f68017ce160f709f52"),
    ];
    want.sort();
    assert_eq!(sorted_undisclosed(&r), want);
    let top: Vec<&Slot> = r
        .undisclosed
        .iter()
        .filter(|s| s.container == at(504))
        .collect();
    assert_eq!(top.len(), 1);
    assert_eq!(top[0].position, 1);
    assert!(r.is_valid(MatchMode::Verifier));
    assert!(!r.is_valid(MatchMode::Holder));

    // Figure 29, in reconstruction order and with the fixture's 2023 date.
    let mut m = sd_standard_claims();
    m.push((
        int(504),
        arr(vec![
            record(1_549_560_720, "DCBA-101777", vec![(int(1), text("us"))]),
            record(
                1_674_004_740,
                "ABCD-123456",
                vec![(int(1), text("us")), (int(2), text("ca"))],
            ),
        ]),
    ));
    assert_eq!(enc(r.processed.as_ref().unwrap()), enc(&map(m)));
}

#[test]
fn decoy_matching() {
    let bytes = token(SD_DECOY);
    let s = sd(&bytes);
    let r = match_disclosures(&s);
    assert_clean(&r);
    assert!(r.undisclosed.is_empty());
    assert_eq!(
        slots(&r),
        [
            (0, at(98), 0, SlotKind::ArrayElement),
            (1, at(98), 1, SlotKind::ArrayElement),
            (2, payload(), 0, SlotKind::ClaimKey),
            (3, payload(), 1, SlotKind::ClaimKey),
        ]
    );
    assert!(r.is_valid(MatchMode::Holder));
    let mut m = sd_standard_claims();
    m.push((int(98), arr(vec![text("fr")])));
    m.push((int(500), tru()));
    assert_eq!(enc(r.processed.as_ref().unwrap()), enc(&map(m)));
}

#[test]
fn decoys_withheld_look_like_withheld_claims() {
    // A Verifier sees only the "fr" disclosure: the decoy and 500 digests
    // are both undisclosed.
    let bytes = token(SD_DECOY);
    let only_fr = tokenator_cose::kbt::disclose(
        &B,
        &bytes,
        &tokenator_cose::kbt::Selection::Indices(vec![0]),
    )
    .unwrap();
    let s = sd(&only_fr);
    let r = match_disclosures(&s);
    assert_eq!(r.undisclosed.len(), 3);
    let mut m = sd_standard_claims();
    m.push((int(98), arr(vec![text("fr")])));
    assert_eq!(enc(r.processed.as_ref().unwrap()), enc(&map(m)));
}

#[test]
fn processed_keeps_original_encodings() {
    // Every item of the issuer example is preferred, so the processed
    // claims re-encode to exactly the expected bytes, and an unredacted
    // item still borrows the input.
    let bytes = token(SD_ISSUER);
    let s = sd(&bytes);
    let r = match_disclosures(&s);
    let Value::Map(entries) = &r.processed.as_ref().unwrap().value else {
        panic!()
    };
    let Value::Text(iss) = &entries[0].1.value else {
        panic!()
    };
    assert!(matches!(iss, std::borrow::Cow::Borrowed(_)));
}

// ------------------------------------------------------------ verify_kbt

#[test]
fn verify_sd_kbt_fixture() {
    let bytes = token(SD_KBT);
    let r = verify_kbt(&B, &bytes, Some(&sd_issuer()), &kbt_opts()).unwrap();
    assert!(r.is_valid(), "{r:?}");
    assert_eq!(r.issuer_signature, Ok(Alg::ES384));
    assert_eq!(r.kbt_signature, Ok(Alg::ES256));
    assert!(r.findings.is_empty(), "{:?}", r.findings);
    let sd_report = r.sd.as_ref().unwrap();
    assert_eq!(sd_report.matched.len(), 3);
    assert_eq!(sd_report.undisclosed.len(), 2);
    let inner = r.sd_cwt.as_ref().unwrap();
    assert_eq!(inner.sign1.base, 9);
    assert_eq!(inner.sign1.bytes, &bytes[9..9 + inner.sign1.bytes.len()]);
    assert_eq!(inner.sign1.bytes, &kcwt_of(&bytes)[..]);
    assert!(matches!(
        r.cnf,
        Some(Ok(tokenator_cose::claims::Cnf::CoseKey(_)))
    ));
}

#[test]
fn verify_nested_kbt_fixture() {
    let bytes = token(SD_NESTED_KBT);
    let r = verify_kbt(&B, &bytes, Some(&sd_issuer()), &kbt_opts()).unwrap();
    assert!(r.is_valid(), "{r:?}");
    assert_eq!(r.sd.as_ref().unwrap().matched.len(), 7);
    assert_eq!(r.sd.as_ref().unwrap().undisclosed.len(), 4);
}

#[test]
fn verify_kbt_without_issuer_key() {
    let bytes = token(SD_KBT);
    let r = verify_kbt(&B, &bytes, None, &kbt_opts()).unwrap();
    assert_eq!(r.issuer_signature, Err(tokenator_cose::CoseError::NoKey));
    assert_eq!(r.kbt_signature, Ok(Alg::ES256));
    assert!(!r.is_valid());
}

#[test]
fn issuer_tokens_are_not_kbts() {
    for name in [SD_ISSUER, SD_NESTED_ISSUER, SD_DECOY, RFC8392_A3] {
        let bytes = token(name);
        assert_eq!(
            verify_kbt(&B, &bytes, Some(&sd_issuer()), &kbt_opts()).unwrap_err(),
            tokenator_cose::CoseError::NotKbt,
            "{name}"
        );
    }
}
