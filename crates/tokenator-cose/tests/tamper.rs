//! Manipulation primitives (SPEC §5): tamper ops, raw assembly, re-signing
//! with unedited bytes kept, and disclosure edits.

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
use tokenator_cbor::{Item, Value, decode};
use tokenator_cose::edit::{
    DisclosureOp, Edit, EquivalentEncoding, ResignOptions, TamperOp, edit_disclosures, resign,
    tamper,
};
use tokenator_cose::kbt::{KbtOptions, verify_kbt};
use tokenator_cose::sd::{MatchMode, encode_disclosure, match_disclosures, parse_sd_cwt};
use tokenator_cose::{
    Alg, CoseError, DeclaredAlg, DiagnosticKind, Sign1Backend, Sign1Parts, SignOptions,
    VerifyOptions,
};

fn verify_a3(bytes: &[u8]) -> Result<Alg, CoseError> {
    let msg = B.parse(bytes)?;
    B.verify(&msg, &rfc8392_key(), &VerifyOptions::default())
}

fn verify_with(bytes: &[u8], alg: Alg, key: &tokenator_cose::Key) -> Result<Alg, CoseError> {
    let msg = B.parse(bytes)?;
    let opts = VerifyOptions {
        alg: Some(alg),
        ..VerifyOptions::default()
    };
    B.verify(&msg, key, &opts)
}

fn verify_issuer(bytes: &[u8]) -> Result<Alg, CoseError> {
    let msg = B.parse(bytes)?;
    B.verify(&msg, &sd_issuer(), &VerifyOptions::default())
}

fn t(bytes: &[u8], op: TamperOp<'_>) -> Vec<u8> {
    tamper(&B, bytes, &op).unwrap_or_else(|e| panic!("{op:?}: {e:?}"))
}

fn diff_bits(a: &[u8], b: &[u8]) -> u32 {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()
}

fn kbt_opts() -> KbtOptions<'static> {
    KbtOptions {
        now: SD_NOW,
        skew: 60,
        ..KbtOptions::default()
    }
}

// ------------------------------------------------------------ tamper

#[test]
fn originals_verify() {
    assert_eq!(verify_a3(&token(RFC8392_A3)), Ok(Alg::ES256));
    assert_eq!(verify_issuer(&token(SD_ISSUER)), Ok(Alg::ES384));
}

#[test]
fn swap_alg() {
    let a3 = token(RFC8392_A3);
    let out = t(&a3, TamperOp::SwapAlg(-35));
    assert_eq!(protected_of(&out), h("a1 01 3822"));
    assert!(matches!(
        verify_a3(&out),
        Err(CoseError::KeyNotSuitable {
            alg: Alg::ES384,
            ..
        })
    ));
    assert_eq!(
        verify_with(&out, Alg::ES256, &rfc8392_key()),
        Err(CoseError::InvalidSignature)
    );
    let out = t(&a3, TamperOp::SwapAlg(0));
    assert_eq!(
        verify_a3(&out),
        Err(CoseError::UnsupportedAlg(DeclaredAlg::UnknownCose(0)))
    );
    // Other protected entries keep their bytes and order.
    let sd = token(SD_ISSUER);
    let out = t(&sd, TamperOp::SwapAlg(-7));
    let want = [h("a4 01 26"), protected_of(&sd)[4..].to_vec()].concat();
    assert_eq!(protected_of(&out), want);
    assert_eq!(unprotected_of(&out), unprotected_of(&sd));
    assert_eq!(payload_of(&out), payload_of(&sd));
    assert_eq!(signature_of(&out), signature_of(&sd));
}

#[test]
fn remove_alg() {
    let out = t(&token(RFC8392_A3), TamperOp::RemoveAlg);
    assert_eq!(protected_of(&out), h("a0"));
    assert_eq!(verify_a3(&out), Err(CoseError::MissingAlg));
    assert_eq!(
        verify_with(&out, Alg::ES256, &rfc8392_key()),
        Err(CoseError::InvalidSignature)
    );
}

#[test]
fn strip_and_flip_signature() {
    let a3 = token(RFC8392_A3);
    let out = t(&a3, TamperOp::StripSignature);
    assert!(signature_of(&out).is_empty());
    assert_eq!(&out[..109], &a3[..109]);
    assert_eq!(out[109], 0x40);
    assert_eq!(verify_a3(&out), Err(CoseError::InvalidSignature));

    for bit in [0, 7, 8, 511] {
        let out = t(&a3, TamperOp::FlipSignatureBit(bit));
        assert_eq!(diff_bits(&out, &a3), 1, "bit {bit}");
        assert_eq!(verify_a3(&out), Err(CoseError::InvalidSignature));
    }
    let first = t(&a3, TamperOp::FlipSignatureBit(0));
    assert_eq!(first[111], a3[111] ^ 0x80);
    assert!(matches!(
        tamper(&B, &a3, &TamperOp::FlipSignatureBit(512)),
        Err(CoseError::NotApplicable(_))
    ));
}

#[test]
fn flip_any_bit() {
    let a3 = token(RFC8392_A3);
    // A bit inside the payload (offset 60 is the aud key).
    let out = t(&a3, TamperOp::FlipBit { offset: 60, bit: 7 });
    assert_eq!(out[60], a3[60] ^ 0x01);
    assert_eq!(diff_bits(&out, &a3), 1);
    assert_eq!(verify_a3(&out), Err(CoseError::InvalidSignature));
    // A bit in the unprotected kid does not affect the signature.
    let out = t(&a3, TamperOp::FlipBit { offset: 10, bit: 0 });
    assert_eq!(verify_a3(&out), Ok(Alg::ES256));
    // Out of range.
    for op in [
        TamperOp::FlipBit {
            offset: 175,
            bit: 0,
        },
        TamperOp::FlipBit { offset: 0, bit: 8 },
    ] {
        assert!(matches!(
            tamper(&B, &a3, &op),
            Err(CoseError::NotApplicable(_))
        ));
    }
}

#[test]
fn flip_bit_works_on_unparseable_results() {
    // Flipping the array head makes the token unparseable; tamper does not
    // care.
    let a3 = token(RFC8392_A3);
    let out = t(&a3, TamperOp::FlipBit { offset: 1, bit: 7 });
    assert_eq!(out[1], 0x85);
    assert!(B.parse(&out).is_err() || !B.parse(&out).unwrap().diagnostics.is_empty());
}

#[test]
fn set_and_remove_kid() {
    let a3 = token(RFC8392_A3);
    let out = t(&a3, TamperOp::SetKid(Cow::Borrowed(b"other")));
    let msg = B.parse(&out).unwrap();
    assert_eq!(msg.kid(), Some(&b"other"[..]));
    assert_eq!(verify_a3(&out), Ok(Alg::ES256), "kid is unprotected here");

    let out = t(&a3, TamperOp::RemoveKid);
    assert_eq!(unprotected_of(&out), h("a0"));
    assert_eq!(B.parse(&out).unwrap().kid(), None);
    assert_eq!(verify_a3(&out), Ok(Alg::ES256));

    // The SD-CWT kid is protected: removing it breaks the signature, and
    // setting an unprotected one puts the label in both buckets.
    let sd = token(SD_ISSUER);
    let out = t(&sd, TamperOp::RemoveKid);
    let p = decode(&protected_of(&out)).unwrap().into_owned();
    let Value::Map(entries) = &p.value else {
        panic!()
    };
    let keys: Vec<Vec<u8>> = entries.iter().map(|(k, _)| enc(k)).collect();
    assert_eq!(keys, [h("01"), h("10"), h("18aa")]);
    assert_eq!(verify_issuer(&out), Err(CoseError::InvalidSignature));

    let out = t(&sd, TamperOp::SetKid(Cow::Borrowed(b"other")));
    let msg = B.parse(&out).unwrap();
    assert!(
        msg.diagnostics
            .iter()
            .any(|d| matches!(d.kind, DiagnosticKind::LabelInBothBuckets(_)))
    );
    assert_eq!(verify_issuer(&out), Ok(Alg::ES384));
}

#[test]
fn truncate() {
    let a3 = token(RFC8392_A3);
    let out = t(&a3, TamperOp::Truncate(100));
    assert_eq!(out, &a3[..100]);
    assert!(matches!(B.parse(&out), Err(CoseError::Cbor(_))));
    assert_eq!(t(&a3, TamperOp::Truncate(175)), a3);
    assert!(matches!(
        tamper(&B, &a3, &TamperOp::Truncate(176)),
        Err(CoseError::NotApplicable(_))
    ));
}

#[test]
fn set_tags() {
    let a3 = token(RFC8392_A3);
    assert_eq!(
        t(&a3, TamperOp::SetTags(vec![])),
        token(RFC8392_A3_UNTAGGED)
    );
    assert_eq!(
        t(&a3, TamperOp::SetTags(vec![61, 18])),
        token(RFC8392_A3_TAG61)
    );
    let double = t(&a3, TamperOp::SetTags(vec![18, 18]));
    assert_eq!(&double[..2], h("d2d2"));
    let msg = B.parse(&double).unwrap();
    assert_eq!(msg.tags, [18, 18]);
    assert!(!msg.diagnostics.is_empty());
    assert_eq!(verify_a3(&double), Ok(Alg::ES256), "tags are not signed");
    let mac = t(&a3, TamperOp::SetTags(vec![17]));
    assert_eq!(
        B.parse(&mac).unwrap_err(),
        CoseError::UnsupportedStructure { tag: 17 }
    );
}

#[test]
fn protected_equivalent_encodings() {
    let a3 = token(RFC8392_A3);

    let out = t(
        &a3,
        TamperOp::ProtectedEquivalent(EquivalentEncoding::WideBstrHead),
    );
    assert_eq!(&out[..7], h("d2 84 5803 a10126"));
    assert_eq!(protected_of(&out), h("a10126"));
    assert_eq!(verify_a3(&out), Ok(Alg::ES256), "contents unchanged");

    let out = t(
        &a3,
        TamperOp::ProtectedEquivalent(EquivalentEncoding::WideIntegers),
    );
    assert_eq!(protected_of(&out), h("a1 1801 3806"));
    assert_eq!(
        B.parse(&out).unwrap().alg(),
        Some(DeclaredAlg::Known(Alg::ES256))
    );
    assert_eq!(verify_a3(&out), Err(CoseError::InvalidSignature));

    let out = t(
        &a3,
        TamperOp::ProtectedEquivalent(EquivalentEncoding::IndefiniteMap),
    );
    assert_eq!(protected_of(&out), h("bf 01 26 ff"));
    assert_eq!(
        B.parse(&out).unwrap().alg(),
        Some(DeclaredAlg::Known(Alg::ES256))
    );
    assert_eq!(verify_a3(&out), Err(CoseError::InvalidSignature));

    // Everything after the protected header is unchanged.
    for e in [
        EquivalentEncoding::WideBstrHead,
        EquivalentEncoding::WideIntegers,
        EquivalentEncoding::IndefiniteMap,
    ] {
        let out = t(&a3, TamperOp::ProtectedEquivalent(e));
        assert_eq!(&out[out.len() - 169..], &a3[6..], "{e:?}");
    }
}

#[test]
fn tamper_on_a_kbt_breaks_the_kbt_signature() {
    let kbt = token(SD_KBT);
    let r = verify_kbt(&B, &kbt, Some(&sd_issuer()), &kbt_opts()).unwrap();
    assert!(r.is_valid());
    let out = t(&kbt, TamperOp::FlipSignatureBit(3));
    let r = verify_kbt(&B, &out, Some(&sd_issuer()), &kbt_opts()).unwrap();
    assert_eq!(r.kbt_signature, Err(CoseError::InvalidSignature));
    assert_eq!(r.issuer_signature, Ok(Alg::ES384));
}

#[test]
fn tamper_errors() {
    assert!(matches!(
        tamper(&B, &[0xff], &TamperOp::StripSignature),
        Err(CoseError::Cbor(_))
    ));
    // Byte-level ops need no parse.
    assert_eq!(
        tamper(&B, &[0xff, 0x00], &TamperOp::Truncate(1)).unwrap(),
        [0xff]
    );
    assert_eq!(
        tamper(&B, &[0x00], &TamperOp::FlipBit { offset: 0, bit: 0 }).unwrap(),
        [0x80]
    );
}

// ------------------------------------------------------------ assemble

#[test]
fn assemble_from_raw_parts() {
    let a3 = token(RFC8392_A3);
    let msg = B.parse(&a3).unwrap();
    let mut p = Sign1Parts::from_sign1(&msg).unwrap();
    p.protected = Cow::Owned(h("a1013822"));
    let swapped = B.assemble(&p).unwrap();
    assert_eq!(swapped, t(&a3, TamperOp::SwapAlg(-35)));

    let mut p = Sign1Parts::from_sign1(&msg).unwrap();
    p.signature = Cow::Borrowed(&[]);
    assert_eq!(B.assemble(&p).unwrap(), t(&a3, TamperOp::StripSignature));

    let mut p = Sign1Parts::from_sign1(&msg).unwrap();
    p.unprotected = map(vec![(int(4), bs(b"x")), (int(4), bs(b"y"))]);
    let dup = B.assemble(&p).unwrap();
    assert_eq!(verify_a3(&dup), Ok(Alg::ES256));
}

// ------------------------------------------------------------ resign

#[test]
fn resign_unedited_changes_only_the_signature() {
    let a3 = token(RFC8392_A3);
    let out = resign(&B, &a3, &rfc8392_key(), &ResignOptions::default(), None).unwrap();
    assert_eq!(out.len(), a3.len());
    assert_eq!(&out[..111], &a3[..111]);
    assert_eq!(verify_a3(&out), Ok(Alg::ES256));
    // Tag-61 and untagged inputs keep their tags.
    for name in [RFC8392_A3_TAG61, RFC8392_A3_UNTAGGED] {
        let input = token(name);
        let out = resign(&B, &input, &rfc8392_key(), &ResignOptions::default(), None).unwrap();
        assert_eq!(
            &out[..input.len() - 64],
            &input[..input.len() - 64],
            "{name}"
        );
    }
}

#[test]
fn resign_keeps_non_preferred_heads() {
    // 18([h'a10126' (0x58 0x03), {4: h'6b6964' (0x58 0x03)}, payload with a
    // 2-byte length head, h''])
    let payload = token(RFC8392_A1);
    let mut bytes = h("d2 84 5803a10126 a1 04 58036b6964 590050");
    bytes.extend(&payload);
    bytes.push(0x40);
    let key = rfc8392_key();
    let out = resign(&B, &bytes, &key, &ResignOptions::default(), None).unwrap();
    let sig_at = bytes.len() - 1;
    assert_eq!(&out[..sig_at], &bytes[..sig_at]);
    assert_eq!(&out[sig_at..sig_at + 2], h("5840"));
    let msg = B.parse(&out).unwrap();
    assert_eq!(
        B.verify(&msg, &key, &VerifyOptions::default()),
        Ok(Alg::ES256)
    );
}

#[test]
fn resign_edited_payload_item_keeps_other_claims() {
    let a3 = token(RFC8392_A3);
    let payload = payload_of(&a3);
    let mut item = decode(&payload).unwrap().into_owned();
    let Value::Map(entries) = &mut item.value else {
        panic!()
    };
    entries[1].1 = text("alice"); // sub
    let opts = ResignOptions {
        payload: Edit::Item(item),
        ..ResignOptions::default()
    };
    let out = resign(&B, &a3, &rfc8392_key(), &opts, None).unwrap();
    let new_payload = payload_of(&out);
    // iss unchanged, sub replaced, the rest byte for byte.
    let want = [
        payload[..24].to_vec(),
        h("02 65616c696365"),
        payload[31..].to_vec(),
    ]
    .concat();
    assert_eq!(new_payload, want);
    assert_eq!(protected_of(&out), protected_of(&a3));
    assert_eq!(unprotected_of(&out), unprotected_of(&a3));
    assert_eq!(verify_a3(&out), Ok(Alg::ES256));
}

#[test]
fn resign_edited_protected_bytes_and_alg() {
    let a3 = token(RFC8392_A3);
    let ed = key_for(Alg::Ed25519, 1);
    let opts = ResignOptions {
        protected: Edit::Bytes(Cow::Owned(h("a10127"))),
        ..ResignOptions::default()
    };
    let out = resign(&B, &a3, &ed, &opts, None).unwrap();
    assert_eq!(protected_of(&out), h("a10127"));
    let msg = B.parse(&out).unwrap();
    assert_eq!(
        B.verify(&msg, &ed, &VerifyOptions::default()),
        Ok(Alg::EdDSA)
    );

    // An explicit alg that disagrees with the header.
    let opts = ResignOptions {
        alg: Some(Alg::Ed25519),
        ..ResignOptions::default()
    };
    let out = resign(&B, &a3, &ed, &opts, None).unwrap();
    assert_eq!(protected_of(&out), h("a10126"));
    assert!(matches!(
        verify_a3(&out),
        Err(CoseError::InvalidSignature) | Err(CoseError::KeyNotSuitable { .. })
    ));
    assert_eq!(verify_with(&out, Alg::Ed25519, &ed), Ok(Alg::Ed25519));
}

#[test]
fn resign_edited_protected_item_preserves_widths() {
    let a3 = token(RFC8392_A3);
    // {1: -7, 4: h'01' with a 1-byte length argument}
    let item: Item<'static> = decode(&h("a2 01 26 04 580101")).unwrap().into_owned();
    let opts = ResignOptions {
        protected: Edit::Item(item),
        ..ResignOptions::default()
    };
    let out = resign(&B, &a3, &rfc8392_key(), &opts, None).unwrap();
    assert_eq!(protected_of(&out), h("a2 01 26 04 580101"));
    assert_eq!(verify_a3(&out), Ok(Alg::ES256));
}

#[test]
fn resign_new_unprotected() {
    let a3 = token(RFC8392_A3);
    let opts = ResignOptions {
        unprotected: Some(map(vec![])),
        ..ResignOptions::default()
    };
    let out = resign(&B, &a3, &rfc8392_key(), &opts, None).unwrap();
    assert_eq!(unprotected_of(&out), h("a0"));
    assert_eq!(verify_a3(&out), Ok(Alg::ES256));
}

#[test]
fn resign_sd_cwt_keeps_disclosures() {
    let sd = token(SD_ISSUER);
    let out = resign(&B, &sd, &sd_issuer(), &ResignOptions::default(), None).unwrap();
    assert_eq!(disclosures_of(&out), disclosures_of(&sd));
    assert_eq!(protected_of(&out), protected_of(&sd));
    assert_eq!(payload_of(&out), payload_of(&sd));
    assert_eq!(verify_issuer(&out), Ok(Alg::ES384));
}

#[test]
fn resign_errors() {
    let a3 = token(RFC8392_A3);
    let no_alg = ResignOptions {
        protected: Edit::Bytes(Cow::Borrowed(&[])),
        ..ResignOptions::default()
    };
    assert_eq!(
        resign(&B, &a3, &rfc8392_key(), &no_alg, None).unwrap_err(),
        CoseError::MissingAlg
    );
    assert_eq!(
        resign(
            &B,
            &a3,
            &public(&rfc8392_key()),
            &ResignOptions::default(),
            None
        )
        .unwrap_err(),
        CoseError::NoPrivateKey
    );
    let unknown = ResignOptions {
        protected: Edit::Bytes(Cow::Owned(h("a1 01 390000"))),
        ..ResignOptions::default()
    };
    assert_eq!(
        resign(&B, &a3, &rfc8392_key(), &unknown, None).unwrap_err(),
        CoseError::UnsupportedAlg(DeclaredAlg::UnknownCose(-1))
    );
}

#[test]
fn resign_detached() {
    let key = key_for(Alg::ES256, 1);
    let bytes = h("d2 84 43a10126 a0 f6 40");
    assert_eq!(
        resign(&B, &bytes, &key, &ResignOptions::default(), None).unwrap_err(),
        CoseError::DetachedPayload
    );
    let opts = ResignOptions {
        detached_payload: Some(Cow::Borrowed(b"content")),
        ..ResignOptions::default()
    };
    let out = resign(&B, &bytes, &key, &opts, None).unwrap();
    assert_eq!(&out[..8], &bytes[..8], "still detached");
    let msg = B.parse(&out).unwrap();
    let v = VerifyOptions {
        detached_payload: Some(b"content"),
        ..VerifyOptions::default()
    };
    assert_eq!(B.verify(&msg, &key, &v), Ok(Alg::ES256));
}

#[test]
fn resign_with_external_aad_and_pss() {
    let key = key_for(Alg::PS256, 1);
    let prot = enc(&map(vec![(int(1), int(-37))]));
    let start = B
        .sign(
            &Sign1Parts {
                tags: vec![18],
                protected: Cow::Owned(prot),
                unprotected: map(vec![]),
                payload: Some(Cow::Borrowed(b"x")),
                signature: Cow::Borrowed(&[]),
            },
            &key,
            &SignOptions::new(Alg::PS256),
            Some(&mut rng(1)),
        )
        .unwrap();
    let opts = ResignOptions {
        external_aad: Cow::Borrowed(b"aad"),
        ..ResignOptions::default()
    };
    assert!(matches!(
        resign(&B, &start, &key, &opts, None),
        Err(CoseError::Crypto(_))
    ));
    let out = resign(&B, &start, &key, &opts, Some(&mut rng(2))).unwrap();
    let msg = B.parse(&out).unwrap();
    let v = VerifyOptions {
        external_aad: b"aad",
        ..VerifyOptions::default()
    };
    assert_eq!(B.verify(&msg, &key, &v), Ok(Alg::PS256));
}

// ------------------------------------------------------------ edit disclosures

fn sd_report_after(ops: &[DisclosureOp<'_>]) -> (Vec<u8>, usize, usize, Vec<usize>, Vec<usize>) {
    let sd = token(SD_ISSUER);
    let out = edit_disclosures(&B, &sd, ops).unwrap();
    assert_eq!(protected_of(&out), protected_of(&sd));
    assert_eq!(payload_of(&out), payload_of(&sd));
    assert_eq!(signature_of(&out), signature_of(&sd));
    assert_eq!(verify_issuer(&out), Ok(Alg::ES384), "{ops:?}");
    let (matched, undisclosed, unmatched, dups) = {
        let parsed = parse_sd_cwt(&B, &out).unwrap();
        let r = match_disclosures(&parsed);
        (
            r.matched.len(),
            r.undisclosed.len(),
            r.unmatched.clone(),
            r.duplicate_disclosures.clone(),
        )
    };
    (out, matched, undisclosed, unmatched, dups)
}

#[test]
fn edit_select_remove_move() {
    let all = disclosures_of(&token(SD_ISSUER));

    let (out, ..) = sd_report_after(&[DisclosureOp::Select(vec![0, 1, 3])]);
    assert_eq!(out, kcwt_of(&token(SD_KBT)));

    let (out, matched, undisclosed, ..) = sd_report_after(&[DisclosureOp::Remove(4)]);
    assert_eq!(disclosures_of(&out), all[..4]);
    assert_eq!((matched, undisclosed), (4, 1));

    let (out, matched, ..) = sd_report_after(&[DisclosureOp::Move { from: 0, to: 4 }]);
    assert_eq!(disclosures_of(&out), [&all[1..], &all[..1]].concat());
    assert_eq!(matched, 5);

    let (out, ..) = sd_report_after(&[
        DisclosureOp::Remove(0),
        DisclosureOp::Remove(0),
        DisclosureOp::Remove(0),
        DisclosureOp::Remove(0),
        DisclosureOp::Remove(0),
    ]);
    assert_eq!(
        unprotected_of(&out),
        h("a0"),
        "sd_claims removed when empty"
    );
}

#[test]
fn edit_duplicate_append_replace_forge() {
    let (_, matched, _, _, dups) = sd_report_after(&[DisclosureOp::Duplicate(0)]);
    assert_eq!((matched, dups), (5, vec![5]));

    let forged = encode_disclosure(&[9; 16], Some(&text("forged")), Some(&int(501))).unwrap();
    let (out, _, _, unmatched, _) =
        sd_report_after(&[DisclosureOp::Append(Cow::Owned(forged.clone()))]);
    assert_eq!(unmatched, [5]);
    assert_eq!(disclosures_of(&out)[5], forged);

    let (_, matched, undisclosed, unmatched, _) = sd_report_after(&[DisclosureOp::Replace {
        index: 0,
        bytes: Cow::Owned(forged.clone()),
    }]);
    assert_eq!((matched, undisclosed, unmatched), (4, 1, vec![0]));

    let (out, _, _, unmatched, _) = sd_report_after(&[DisclosureOp::Forge {
        salt: Cow::Owned(vec![9; 16]),
        value: Some(text("forged")),
        key: Some(int(501)),
    }]);
    assert_eq!(unmatched, [5]);
    assert_eq!(disclosures_of(&out)[5], forged);

    // A decoy disclosure without a digest in the payload.
    let (out, _, _, unmatched, _) = sd_report_after(&[DisclosureOp::Forge {
        salt: Cow::Owned(vec![8; 16]),
        value: None,
        key: None,
    }]);
    assert_eq!(unmatched, [5]);
    assert_eq!(
        disclosures_of(&out)[5],
        encode_disclosure(&[8; 16], None, None).unwrap()
    );
}

#[test]
fn edit_ops_apply_in_order() {
    let all = disclosures_of(&token(SD_ISSUER));
    let (out, ..) = sd_report_after(&[
        DisclosureOp::Select(vec![4, 3]),
        DisclosureOp::Duplicate(1),
        DisclosureOp::Remove(0),
    ]);
    assert_eq!(disclosures_of(&out), [all[3].clone(), all[3].clone()]);
}

#[test]
fn edit_disclosure_errors() {
    let sd = token(SD_ISSUER);
    for op in [
        DisclosureOp::Remove(5),
        DisclosureOp::Duplicate(9),
        DisclosureOp::Select(vec![0, 5]),
        DisclosureOp::Move { from: 0, to: 5 },
        DisclosureOp::Replace {
            index: 5,
            bytes: Cow::Borrowed(&[]),
        },
    ] {
        assert!(
            matches!(
                edit_disclosures(&B, &sd, std::slice::from_ref(&op)),
                Err(CoseError::DisclosureIndex(_))
            ),
            "{op:?}"
        );
    }
    // A token without sd_claims can still get disclosures appended.
    let a3 = token(RFC8392_A3);
    let out = edit_disclosures(&B, &a3, &[DisclosureOp::Append(Cow::Borrowed(&[0x80]))]).unwrap();
    assert_eq!(disclosures_of(&out), [vec![0x80]]);
    assert_eq!(verify_a3(&out), Ok(Alg::ES256));
}

#[test]
fn edit_disclosures_inside_kbt_then_resign() {
    let kbt = token(SD_KBT);
    let out = edit_disclosures(&B, &kbt, &[DisclosureOp::Remove(2)]).unwrap();
    let r = verify_kbt(&B, &out, Some(&sd_issuer()), &kbt_opts()).unwrap();
    assert_eq!(r.issuer_signature, Ok(Alg::ES384));
    assert_eq!(r.kbt_signature, Err(CoseError::InvalidSignature));
    assert_eq!(disclosures_of(&kcwt_of(&out)).len(), 2);

    // Edit & re-sign with the holder key repairs it.
    let fixed = resign(&B, &out, &sd_holder(), &ResignOptions::default(), None).unwrap();
    let r = verify_kbt(&B, &fixed, Some(&sd_issuer()), &kbt_opts()).unwrap();
    assert!(r.is_valid(), "{r:?}");
    assert!(r.sd.as_ref().unwrap().is_valid(MatchMode::Verifier));
}
