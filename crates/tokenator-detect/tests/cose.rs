//! COSE classification: COSE_Sign1, CWT (RFC 8392), SD-CWT and SD-KBT
//! (draft-ietf-spice-sd-cwt-08), tagged and untagged.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_cbor::Item;
use tokenator_detect::{Kind, Layer};

const SIGN1_KINDS: [Kind; 4] = [Kind::CoseSign1, Kind::Cwt, Kind::SdCwt, Kind::SdKbt];

fn assert_no_sign1(input: &[u8]) {
    let cands = run(input);
    for k in &SIGN1_KINDS {
        assert!(
            find(&cands, k).is_none(),
            "unexpected {k:?}: {}",
            summary(&cands)
        );
    }
}

// ------------------------------------------------------------------ RFC 8392 CWT

#[test]
fn rfc8392_a3_tag18_binary() {
    let input = token(CWT_TAG18);
    assert_eq!(input[0], 0xd2);
    let c = top(&input);
    assert_eq!(c.kind, Kind::Cwt);
    assert_eq!(c.layers, vec![Layer::CborTag(18)]);
    assert_eq!(c.payload_range, 1..input.len());
}

#[test]
fn rfc8392_a3_tag61_tag18_binary() {
    let input = token("derived-rfc8392-a3-tag61.cbor");
    let c = top(&input);
    assert_eq!(c.kind, Kind::Cwt);
    assert_eq!(c.layers, vec![Layer::CborTag(61), Layer::CborTag(18)]);
    assert_eq!(c.payload_range, 3..input.len());
}

#[test]
fn rfc8392_a3_untagged_binary() {
    let input = token("derived-rfc8392-a3-untagged.cbor");
    let c = top(&input);
    assert_eq!(c.kind, Kind::Cwt);
    assert!(c.layers.is_empty(), "{c:?}");
    assert_eq!(c.payload_range, 0..input.len());
}

#[test]
fn tag61_directly_around_untagged_sign1() {
    // 61([...]) without the inner 18 tag.
    let mut input = vec![0xd8, 0x3d];
    input.extend(cwt_untagged());
    let c = top(&input);
    assert_eq!(c.kind, Kind::Cwt);
    assert_eq!(c.layers, vec![Layer::CborTag(61)]);
    assert_eq!(c.payload_range, 2..input.len());
}

#[test]
fn self_described_cbor_tag_is_a_layer() {
    let mut input = vec![0xd9, 0xd9, 0xf7];
    input.extend(token(CWT_TAG18));
    let c = top(&input);
    assert_eq!(c.kind, Kind::Cwt);
    assert_eq!(c.layers, vec![Layer::CborTag(55799), Layer::CborTag(18)]);
    assert_eq!(c.payload_range, 4..input.len());
}

#[test]
fn rfc8392_a3_hex_text_with_mid_byte_line_breaks() {
    let input = token("rfc8392-a3-signed-cwt.hex");
    let c = top(&input);
    assert_eq!(c.kind, Kind::Cwt);
    assert_eq!(c.layers.first(), Some(&trim("", "\n")));
    assert!(
        c.layers.iter().any(|l| matches!(l, Layer::Hex { .. })),
        "{c:?}"
    );
    assert_eq!(c.layers.last(), Some(&Layer::CborTag(18)));
    assert_eq!(c.payload_range, 0..input.len() - 1);
}

// ------------------------------------------------------------------ COSE_Sign1 that is not a CWT

#[test]
fn rfc9052_c2_1_text_payload_is_cose_sign1() {
    let input = token("rfc9052-c2.1-sign1.cbor");
    let c = top(&input);
    assert_eq!(c.kind, Kind::CoseSign1);
    assert_eq!(c.layers, vec![Layer::CborTag(18)]);
    assert!(find(&run(&input), &Kind::Cwt).is_none());
}

#[test]
fn detached_payload_is_cose_sign1() {
    let input = sign1_tagged(sign1(vec![(int(1), int(-7))], vec![], null()));
    assert_eq!(top(&input).kind, Kind::CoseSign1);
}

#[test]
fn payload_that_is_a_cbor_array_is_cose_sign1() {
    let payload = bstr(&cbor(&arr(vec![int(1), int(2)])));
    let input = sign1_tagged(sign1(vec![(int(1), int(-7))], vec![], payload));
    assert_eq!(top(&input).kind, Kind::CoseSign1);
}

#[test]
fn empty_protected_header_is_still_sign1() {
    // protected = h'' is allowed; alg in the unprotected header.
    let item = sign1(vec![], vec![(int(1), int(-7))], wrapped(claims()));
    let input = sign1_tagged(item);
    let cands = run(&input);
    expect_kind(&cands, &Kind::Cwt);
}

#[test]
fn synthetic_untagged_cwt() {
    let input = cbor(&sign1(vec![(int(1), int(-7))], vec![], wrapped(claims())));
    let c = top(&input);
    assert_eq!(c.kind, Kind::Cwt);
    assert!(c.layers.is_empty());
}

// ------------------------------------------------------------------ SD-CWT / SD-KBT (draft-08)

#[test]
fn draft08_issuer_sd_cwt() {
    let input = token(SD_CWT);
    let c = top(&input);
    assert_eq!(c.kind, Kind::SdCwt);
    assert_eq!(c.layers, vec![Layer::CborTag(18)]);
    assert_eq!(c.payload_range, 1..input.len());
}

#[test]
fn draft08_nested_issuer_sd_cwt() {
    let c = top(&token("sd-cwt-08-nested-issuer-sd-cwt.cbor"));
    assert_eq!(c.kind, Kind::SdCwt);
    assert_eq!(c.layers, vec![Layer::CborTag(18)]);
}

#[test]
fn draft08_sd_kbt() {
    let input = token(SD_KBT);
    let c = top(&input);
    assert_eq!(c.kind, Kind::SdKbt);
    assert_eq!(c.layers, vec![Layer::CborTag(18)]);
    assert_eq!(c.payload_range, 1..input.len());
}

#[test]
fn draft08_nested_sd_kbt() {
    let c = top(&token("sd-cwt-08-nested-sd-kbt.cbor"));
    assert_eq!(c.kind, Kind::SdKbt);
}

#[test]
fn sd_kbt_outranks_sd_cwt_and_cwt_readings() {
    let cands = run(&token(SD_KBT));
    assert_outranks(&cands, &Kind::SdKbt, &Kind::SdCwt);
    assert_outranks(&cands, &Kind::SdKbt, &Kind::Cwt);
    assert_outranks(&cands, &Kind::SdKbt, &Kind::CoseSign1);
}

#[test]
fn sd_cwt_outranks_cwt_reading() {
    let cands = run(&token(SD_CWT));
    assert_outranks(&cands, &Kind::SdCwt, &Kind::Cwt);
    assert_outranks(&cands, &Kind::SdCwt, &Kind::CoseSign1);
}

#[test]
fn cwt_outranks_cose_sign1_reading() {
    let cands = run(&token(CWT_TAG18));
    assert_outranks(&cands, &Kind::Cwt, &Kind::CoseSign1);
}

#[test]
fn sd_alg_in_protected_header_alone_means_sd_cwt() {
    let item = sign1(
        vec![(int(1), int(-7)), (int(170), int(-16))],
        vec![],
        wrapped(claims()),
    );
    assert_eq!(top(&sign1_tagged(item)).kind, Kind::SdCwt);
}

#[test]
fn sd_claims_in_unprotected_header_alone_means_sd_cwt() {
    let disclosure = bstr(&cbor(&arr(vec![
        bstr(&[0xbb; 16]),
        tstr("ca"),
        tstr("region"),
    ])));
    let item = sign1(
        vec![(int(1), int(-7))],
        vec![(int(17), arr(vec![disclosure]))],
        wrapped(claims()),
    );
    assert_eq!(top(&sign1_tagged(item)).kind, Kind::SdCwt);
}

#[test]
fn redacted_claim_keys_in_payload_alone_means_sd_cwt() {
    let mut payload = claims();
    payload.push((Item::simple(59), arr(vec![bstr(&[0xaf; 32])])));
    let item = sign1(vec![(int(1), int(-7))], vec![], wrapped(payload));
    assert_eq!(top(&sign1_tagged(item)).kind, Kind::SdCwt);
}

#[test]
fn kcwt_in_protected_header_means_sd_kbt() {
    let inner = Item::tag(
        18,
        sign1(
            vec![(int(1), int(-35)), (int(170), int(-16))],
            vec![],
            wrapped(claims()),
        ),
    );
    let kbt_payload = vec![
        (int(3), tstr("https://verifier.example/app")),
        (int(6), int(1_725_244_237)),
    ];
    let item = sign1(
        vec![(int(1), int(-7)), (int(13), inner), (int(16), int(294))],
        vec![],
        wrapped(kbt_payload),
    );
    assert_eq!(top(&sign1_tagged(item)).kind, Kind::SdKbt);
}

#[test]
fn kbt_wrapping_a_plain_cwt_is_sd_kbt() {
    // SPEC §5 Present: a plain CWT is wrapped in an SD-KBT with no disclosures.
    let inner = Item::tag(
        18,
        sign1(vec![(int(1), int(-7))], vec![], wrapped(claims())),
    );
    let item = sign1(
        vec![(int(1), int(-7)), (int(13), inner)],
        vec![],
        wrapped(vec![(int(6), int(1))]),
    );
    assert_eq!(top(&sign1_tagged(item)).kind, Kind::SdKbt);
}

#[test]
fn sd_headers_in_wrong_place_still_classify_as_sign1_family() {
    // sd_claims in the protected header is unusual; it must still be a COSE kind.
    let disclosure = bstr(&cbor(&arr(vec![bstr(&[1; 16]), int(1)])));
    let item = sign1(
        vec![(int(1), int(-7)), (int(17), arr(vec![disclosure]))],
        vec![],
        wrapped(claims()),
    );
    let c = top(&sign1_tagged(item));
    assert!(matches!(c.kind, Kind::SdCwt | Kind::Cwt), "{c:?}");
}

// ------------------------------------------------------------------ negatives

#[test]
fn rfc8392_a4_cose_mac0_is_not_sign1() {
    assert_no_sign1(&token("rfc8392-a4-maced-cwt-tag61.cbor"));
}

#[test]
fn cose_sign_tag98_is_not_sign1() {
    let item = arr(vec![
        wrapped(vec![]),
        map(vec![]),
        wrapped(claims()),
        arr(vec![]),
    ]);
    assert_no_sign1(&cbor(&Item::tag(98, item)));
}

#[test]
fn protected_header_must_be_a_bstr() {
    let item = arr(vec![
        map(vec![(int(1), int(-7))]),
        map(vec![]),
        wrapped(claims()),
        bstr(&[0; 64]),
    ]);
    assert_no_sign1(&cbor(&item));
    assert_no_sign1(&cbor(&Item::tag(18, item)));
}

#[test]
fn wrong_array_lengths_are_not_sign1() {
    let three = arr(vec![
        wrapped(vec![(int(1), int(-7))]),
        map(vec![]),
        wrapped(claims()),
    ]);
    let five = arr(vec![
        wrapped(vec![(int(1), int(-7))]),
        map(vec![]),
        wrapped(claims()),
        bstr(&[0; 64]),
        bstr(&[]),
    ]);
    for item in [three, five] {
        assert_no_sign1(&cbor(&item));
        assert_no_sign1(&cbor(&Item::tag(18, item)));
    }
}

#[test]
fn unprotected_must_be_a_map_and_signature_a_bstr() {
    let bad_unprotected = arr(vec![
        wrapped(vec![(int(1), int(-7))]),
        arr(vec![]),
        wrapped(claims()),
        bstr(&[0; 64]),
    ]);
    let bad_signature = arr(vec![
        wrapped(vec![(int(1), int(-7))]),
        map(vec![]),
        wrapped(claims()),
        tstr("sig"),
    ]);
    for item in [bad_unprotected, bad_signature] {
        assert_no_sign1(&cbor(&Item::tag(18, item)));
    }
}

#[test]
fn tag18_around_a_non_array_is_not_sign1() {
    assert_no_sign1(&cbor(&Item::tag(18, map(claims()))));
    assert_no_sign1(&cbor(&Item::tag(18, bstr(b"hello"))));
}

#[test]
fn trailing_bytes_after_a_cwt_are_not_a_cwt() {
    let mut input = token(CWT_TAG18);
    input.extend([0x00, 0x01]);
    assert_no_sign1(&input);
}

#[test]
fn truncated_cwt_is_not_a_cwt() {
    let input = token(CWT_TAG18);
    assert_no_sign1(&input[..input.len() - 1]);
}
