//! COSE_Sign1 parsing: RFC 8392 Appendix A, RFC 9052 C.2.1, RFC 9964 A.2,
//! spans, partial results, header accessors, token kinds.

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_cbor::{Span, Value, decode};
use tokenator_cose::{
    Bucket, ContentType, CoseError, DeclaredAlg, DiagnosticKind, Label, Part, Payload,
    Sign1Backend, TokenKind,
};
use tokenator_crypto::Alg;

fn span(start: usize, end: usize, head_len: usize) -> Span {
    Span {
        start,
        end,
        head_len,
    }
}

fn kinds(msg: &tokenator_cose::Sign1<'_>) -> Vec<(Part, DiagnosticKind)> {
    msg.diagnostics
        .iter()
        .map(|d| (d.part.clone(), d.kind.clone()))
        .collect()
}

// ------------------------------------------------------------ RFC 8392 A.3

#[test]
fn rfc8392_a3_parts_and_spans() {
    let bytes = token(RFC8392_A3);
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(msg.bytes, &bytes[..]);
    assert_eq!(msg.base, 0);
    assert_eq!(msg.tags, [18]);
    assert_eq!(msg.span, span(1, 175, 1));
    assert!(msg.diagnostics.is_empty(), "{:?}", msg.diagnostics);

    let p = msg.protected.as_ref().unwrap();
    assert_eq!(p.span, span(2, 6, 1));
    assert_eq!(p.content_offset(), 3);
    assert_eq!(&p.raw[..], h("a10126"));
    let hdr = p.decoded.as_ref().unwrap().as_ref().unwrap();
    assert_eq!(enc(hdr), h("a10126"));

    let u = msg.unprotected.as_ref().unwrap();
    assert_eq!((u.span.start, u.span.end), (6, 27));

    let Payload::Attached(pl) = &msg.payload else {
        panic!("{:?}", msg.payload)
    };
    assert_eq!(pl.span, span(27, 109, 2));
    assert_eq!(&pl.raw[..], token(RFC8392_A1));
    assert_eq!(msg.payload_bytes(), Some(&token(RFC8392_A1)[..]));

    let sig = msg.signature.as_ref().unwrap();
    assert_eq!(sig.span, span(109, 175, 2));
    assert_eq!(&sig.raw[..], &bytes[111..]);
}

#[test]
fn rfc8392_a3_borrows_input() {
    let bytes = token(RFC8392_A3);
    let msg = B.parse(&bytes).unwrap();
    let raw = &msg.protected.as_ref().unwrap().raw;
    assert!(matches!(raw, std::borrow::Cow::Borrowed(_)));
    assert!(std::ptr::eq(raw.as_ptr(), bytes[3..].as_ptr()));
}

#[test]
fn rfc8392_a3_headers() {
    let bytes = token(RFC8392_A3);
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(msg.alg(), Some(DeclaredAlg::Known(Alg::ES256)));
    assert_eq!(msg.kid(), Some(&b"AsymmetricECDSA256"[..]));
    assert_eq!(msg.header(4).map(|(b, _)| b), Some(Bucket::Unprotected));
    assert_eq!(msg.header(1).map(|(b, _)| b), Some(Bucket::Protected));
    assert!(msg.header(16).is_none());
    assert_eq!(msg.typ(), None);
    assert_eq!(msg.content_type(), None);
    assert_eq!(msg.crit(), None);
    assert_eq!(
        enc(msg.protected_header().unwrap()),
        h("a10126"),
        "the decoded protected map"
    );
}

#[test]
fn rfc8392_a3_payload_is_a1_claims() {
    let bytes = token(RFC8392_A3);
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(enc(msg.payload_item().unwrap()), token(RFC8392_A1));
    assert_eq!(msg.kind(), TokenKind::Cwt);
}

#[test]
fn rfc8392_a3_untagged_and_tag61() {
    let tagged = token(RFC8392_A3);
    let untagged = token(RFC8392_A3_UNTAGGED);
    let m = B.parse(&untagged).unwrap();
    assert!(m.tags.is_empty());
    assert_eq!(m.span, span(0, 174, 1));
    assert_eq!(m.protected.as_ref().unwrap().span, span(1, 5, 1));
    assert_eq!(m.kind(), TokenKind::Cwt);

    let t61 = token(RFC8392_A3_TAG61);
    let m = B.parse(&t61).unwrap();
    assert_eq!(m.tags, [61, 18]);
    assert_eq!(m.span, span(3, 177, 1));
    assert!(m.diagnostics.is_empty(), "{:?}", m.diagnostics);
    assert_eq!(
        m.signature.unwrap().raw,
        B.parse(&tagged).unwrap().signature.unwrap().raw
    );
}

#[test]
fn item_round_trips_input() {
    for name in SIGN1_FIXTURES {
        let bytes = token(name);
        let msg = B.parse(&bytes).unwrap();
        assert_eq!(enc(&msg.item), bytes, "{name}");
    }
}

#[test]
fn rfc8392_unsupported_structures() {
    for (name, tag) in [(RFC8392_A4, 17), (RFC8392_A5, 16), (RFC8392_A7, 17)] {
        let bytes = token(name);
        assert_eq!(
            B.parse(&bytes).unwrap_err(),
            CoseError::UnsupportedStructure { tag },
            "{name}"
        );
    }
    for tag in [96u8, 97, 98] {
        // 96/97/98([h'', {}, h'', []]) with a one-byte tag head
        let bytes = [0xd8, tag, 0x84, 0x40, 0xa0, 0x40, 0x80];
        assert_eq!(
            B.parse(&bytes).unwrap_err(),
            CoseError::UnsupportedStructure {
                tag: u64::from(tag)
            }
        );
    }
}

#[test]
fn rfc8392_a1_claims_are_not_sign1() {
    assert_eq!(
        B.parse(&token(RFC8392_A1)).unwrap_err(),
        CoseError::NotSign1
    );
}

// ------------------------------------------------------------ RFC 9052, RFC 9964

#[test]
fn rfc9052_c21_sign1_with_text_payload() {
    let bytes = token(RFC9052_C21);
    assert_eq!(bytes.len(), 98);
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(msg.tags, [18]);
    assert_eq!(msg.kid(), Some(&b"11"[..]));
    assert_eq!(msg.alg(), Some(DeclaredAlg::Known(Alg::ES256)));
    assert_eq!(msg.payload_bytes(), Some(&b"This is the content."[..]));
    assert!(msg.payload_item().is_none());
    assert_eq!(msg.kind(), TokenKind::Sign1);
    assert_eq!(
        &msg.signature.unwrap().raw[..],
        h(
            "8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36"
        )
    );
}

#[test]
fn rfc9964_cose_examples_parse() {
    for (n, alg, label) in [
        (44, Alg::MlDsa44, -48),
        (65, Alg::MlDsa65, -49),
        (87, Alg::MlDsa87, -50),
    ] {
        let v = rfc9964(n);
        let bytes = hexs(&v["sign1"]);
        let msg = B.parse(&bytes).unwrap();
        assert_eq!(msg.alg(), Some(DeclaredAlg::Known(alg)), "ML-DSA-{n}");
        assert_eq!(tokenator_crypto::alg_to_cose(alg), label);
        assert_eq!(msg.header(4).map(|(b, _)| b), Some(Bucket::Protected));
        assert_eq!(msg.kid().map(<[u8]>::len), Some(32));
        assert_eq!(
            msg.payload_bytes(),
            Some(&b"hello post quantum signatures"[..])
        );
        assert_eq!(&msg.signature.unwrap().raw[..], hexs(&v["raw_signature"]));
        assert_eq!(enc(msg.unprotected.as_ref().unwrap()), [0xa0]);
    }
}

// ------------------------------------------------------------ edge shapes

#[test]
fn detached_payload() {
    // 18([h'a10126', {}, nil, h''])
    let bytes = h("d2 84 43a10126 a0 f6 40");
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(
        msg.payload,
        Payload::Detached {
            span: span(7, 8, 1)
        }
    );
    assert_eq!(msg.payload_bytes(), None);
    assert_eq!(msg.kind(), TokenKind::Sign1);
    assert!(msg.diagnostics.is_empty());
    assert!(msg.signature.unwrap().raw.is_empty());
}

#[test]
fn zero_length_protected_is_empty_map() {
    // [h'', {}, h'', h'']
    let bytes = h("84 40 a0 40 40");
    let msg = B.parse(&bytes).unwrap();
    let p = msg.protected.as_ref().unwrap();
    assert!(p.raw.is_empty());
    assert!(p.decoded.is_none());
    assert_eq!(enc(msg.protected_header().unwrap()), [0xa0]);
    assert_eq!(msg.alg(), None);
    assert!(msg.diagnostics.is_empty());
}

#[test]
fn indefinite_length_payload_is_concatenated() {
    // [h'', {}, (_ h'a0'), h'']
    let bytes = h("84 40 a0 5f41a0ff 40");
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(msg.payload_bytes(), Some(&[0xa0][..]));
    assert_eq!(msg.kind(), TokenKind::Cwt);
}

#[test]
fn non_preferred_heads_keep_raw_contents() {
    // 18([h'a10126' with a 1-byte length argument, {}, h'a0' as 0x58 0x01, h''])
    let bytes = h("d2 84 5803a10126 a0 5801a0 40");
    let msg = B.parse(&bytes).unwrap();
    let p = msg.protected.as_ref().unwrap();
    assert_eq!(p.span, span(2, 7, 2));
    assert_eq!(p.content_offset(), 4);
    assert_eq!(&p.raw[..], h("a10126"));
    assert_eq!(msg.payload_bytes(), Some(&[0xa0][..]));
}

#[test]
fn other_header_accessors() {
    // [<<{1: -7, 2: [16, "x"], 3: "application/cwt", 16: 61}>>, {}, h'', h'']
    let prot = enc(&map(vec![
        (int(1), int(-7)),
        (int(2), arr(vec![int(16), text("x")])),
        (int(3), text("application/cwt")),
        (int(16), int(61)),
    ]));
    let bytes = enc(&arr(vec![bs(&prot), map(vec![]), bs(b""), bs(b"")]));
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(
        msg.crit(),
        Some(vec![Label::Int(16), Label::Text("x".into())])
    );
    assert_eq!(
        msg.content_type(),
        Some(ContentType::Text("application/cwt".into()))
    );
    assert_eq!(msg.typ(), Some(ContentType::Uint(61)));
}

#[test]
fn unknown_and_text_alg() {
    for (alg, want) in [
        (int(-999), DeclaredAlg::UnknownCose(-999)),
        (text("ES256"), DeclaredAlg::UnknownJose("ES256".into())),
    ] {
        let prot = enc(&map(vec![(int(1), alg)]));
        let bytes = enc(&arr(vec![bs(&prot), map(vec![]), bs(b""), bs(b"")]));
        assert_eq!(B.parse(&bytes).unwrap().alg(), Some(want));
    }
}

#[test]
fn alg_from_unprotected_when_not_protected() {
    let bytes = enc(&arr(vec![
        bs(b""),
        map(vec![(int(1), int(-8))]),
        bs(b""),
        bs(b""),
    ]));
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(msg.alg(), Some(DeclaredAlg::Known(Alg::EdDSA)));
    assert_eq!(msg.header(1).map(|(b, _)| b), Some(Bucket::Unprotected));
}

#[test]
fn token_kinds() {
    assert_eq!(B.parse(&token(SD_ISSUER)).unwrap().kind(), TokenKind::SdCwt);
    assert_eq!(
        B.parse(&token(SD_NESTED_ISSUER)).unwrap().kind(),
        TokenKind::SdCwt
    );
    assert_eq!(B.parse(&token(SD_DECOY)).unwrap().kind(), TokenKind::SdCwt);
    assert_eq!(B.parse(&token(SD_KBT)).unwrap().kind(), TokenKind::SdKbt);
    assert_eq!(
        B.parse(&token(SD_NESTED_KBT)).unwrap().kind(),
        TokenKind::SdKbt
    );

    // A claims payload with only sd_alg in the protected header.
    let prot = enc(&map(vec![(int(1), int(-7)), (int(170), int(-16))]));
    let bytes = enc(&arr(vec![bs(&prot), map(vec![]), bs(&[0xa0]), bs(b"")]));
    assert_eq!(B.parse(&bytes).unwrap().kind(), TokenKind::SdCwt);

    // Only a redacted element in the payload: {1: [60(h'00')]}
    let payload = enc(&map(vec![(int(1), arr(vec![tag(60, bs(&[0]))]))]));
    let bytes = enc(&arr(vec![bs(b""), map(vec![]), bs(&payload), bs(b"")]));
    assert_eq!(B.parse(&bytes).unwrap().kind(), TokenKind::SdCwt);
}

#[test]
fn sd_issuer_headers() {
    let bytes = token(SD_ISSUER);
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(msg.alg(), Some(DeclaredAlg::Known(Alg::ES384)));
    assert_eq!(msg.kid(), Some(SD_ISSUER_KID));
    assert_eq!(msg.typ(), Some(ContentType::Uint(293)));
    assert_eq!(msg.header(170).map(|(b, _)| b), Some(Bucket::Protected));
    assert_eq!(msg.header(17).map(|(b, _)| b), Some(Bucket::Unprotected));
    assert_eq!(&msg.protected.unwrap().raw[..], protected_of(&bytes));
}

#[test]
fn sd_kbt_headers() {
    let bytes = token(SD_KBT);
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(msg.alg(), Some(DeclaredAlg::Known(Alg::ES256)));
    assert_eq!(msg.typ(), Some(ContentType::Uint(294)));
    let (bucket, kcwt) = msg.header(13).unwrap();
    assert_eq!(bucket, Bucket::Protected);
    assert!(matches!(kcwt.value, Value::Tag(18, _)));
    assert_eq!(enc(kcwt), kcwt_of(&bytes));
    assert_eq!(enc(msg.unprotected.as_ref().unwrap()), [0xa0]);
}

// ------------------------------------------------------------ partial results

#[test]
fn wrong_arity_is_partial() {
    // [h'a10126', {}, h'']
    let bytes = h("83 43a10126 a0 40");
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(
        kinds(&msg),
        [(Part::Envelope, DiagnosticKind::WrongArity(3))]
    );
    assert_eq!(msg.alg(), Some(DeclaredAlg::Known(Alg::ES256)));
    assert_eq!(msg.payload_bytes(), Some(&[][..]));
    assert!(msg.signature.is_none());

    let bytes = h("85 40 a0 40 40 40");
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(
        kinds(&msg),
        [(Part::Envelope, DiagnosticKind::WrongArity(5))]
    );
    assert!(msg.signature.is_some());

    let msg = B.parse(&[0x80]).unwrap();
    assert_eq!(
        kinds(&msg),
        [(Part::Envelope, DiagnosticKind::WrongArity(0))]
    );
    assert!(msg.protected.is_none());
    assert_eq!(msg.payload, Payload::Malformed);
}

#[test]
fn protected_not_bytes() {
    // [{1: -7}, {}, h'', h'']
    let bytes = h("84 a10126 a0 40 40");
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(kinds(&msg), [(Part::Protected, DiagnosticKind::NotBytes)]);
    assert_eq!(msg.diagnostics[0].span, Some(span(1, 4, 1)));
    assert!(msg.protected.is_none());
    assert!(msg.protected_header().is_none());
    assert!(msg.signature.is_some());
}

#[test]
fn protected_undecodable() {
    // [h'ff', {}, h'', h'']
    let bytes = h("84 41ff a0 40 40");
    let msg = B.parse(&bytes).unwrap();
    assert!(matches!(
        kinds(&msg).as_slice(),
        [(Part::Protected, DiagnosticKind::Undecodable(_))]
    ));
    let p = msg.protected.as_ref().unwrap();
    assert!(matches!(p.decoded, Some(Err(_))));
    assert_eq!(&p.raw[..], [0xff]);
    assert!(msg.protected_header().is_none());
}

#[test]
fn protected_not_a_map() {
    // [<<1>>, {}, h'', h'']
    let bytes = h("84 4101 a0 40 40");
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(kinds(&msg), [(Part::Protected, DiagnosticKind::NotMap)]);
    assert!(msg.protected_header().is_none());
}

#[test]
fn unprotected_not_a_map() {
    let bytes = h("84 40 80 40 40");
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(kinds(&msg), [(Part::Unprotected, DiagnosticKind::NotMap)]);
    assert!(msg.unprotected.is_none());
}

#[test]
fn payload_and_signature_not_bytes() {
    let msg_bytes = h("84 40 a0 01 40");
    let msg = B.parse(&msg_bytes).unwrap();
    assert_eq!(kinds(&msg), [(Part::Payload, DiagnosticKind::NotBytes)]);
    assert_eq!(msg.payload, Payload::Malformed);

    let msg_bytes = h("84 40 a0 40 01");
    let msg = B.parse(&msg_bytes).unwrap();
    assert_eq!(kinds(&msg), [(Part::Signature, DiagnosticKind::NotBytes)]);
    assert!(msg.signature.is_none());
}

#[test]
fn several_diagnostics_in_document_order() {
    let bytes = h("84 01 02 03 04");
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(
        kinds(&msg),
        [
            (Part::Protected, DiagnosticKind::NotBytes),
            (Part::Unprotected, DiagnosticKind::NotMap),
            (Part::Payload, DiagnosticKind::NotBytes),
            (Part::Signature, DiagnosticKind::NotBytes),
        ]
    );
}

#[test]
fn label_in_both_buckets() {
    // [<<{1: -7}>>, {1: -7}, h'', h'']
    let bytes = h("84 43a10126 a10126 40 40");
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(
        kinds(&msg),
        [(
            Part::Unprotected,
            DiagnosticKind::LabelInBothBuckets(Label::Int(1))
        )]
    );
}

#[test]
fn unexpected_outer_tag() {
    // 1([h'', {}, h'', h''])
    let bytes = h("c1 84 40 a0 40 40");
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(msg.tags, [1]);
    assert_eq!(
        kinds(&msg),
        [(Part::Envelope, DiagnosticKind::UnexpectedTag(1))]
    );

    // 61(1([...]))
    let bytes = h("d83d c1 84 40 a0 40 40");
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(msg.tags, [61, 1]);
    assert_eq!(
        kinds(&msg),
        [(Part::Envelope, DiagnosticKind::UnexpectedTag(1))]
    );
}

#[test]
fn tag61_around_untagged_array() {
    let bytes = h("d83d 84 40 a0 40 40");
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(msg.tags, [61]);
}

#[test]
fn hard_errors() {
    assert!(matches!(B.parse(&[]), Err(CoseError::Cbor(_))));
    assert!(matches!(B.parse(&[0xff]), Err(CoseError::Cbor(_))));
    let mut trailing = token(RFC8392_A3);
    trailing.push(0);
    assert!(matches!(B.parse(&trailing), Err(CoseError::Cbor(_))));
    let mut short = token(RFC8392_A3);
    short.pop();
    assert!(matches!(B.parse(&short), Err(CoseError::Cbor(_))));
    assert_eq!(B.parse(&[0xa0]).unwrap_err(), CoseError::NotSign1);
    assert_eq!(B.parse(&[0xd2, 0x01]).unwrap_err(), CoseError::NotSign1);
    assert_eq!(B.parse(&[0x40]).unwrap_err(), CoseError::NotSign1);
}

#[test]
fn decoded_protected_spans_are_relative_to_raw() {
    let bytes = token(SD_ISSUER);
    let msg = B.parse(&bytes).unwrap();
    let p = msg.protected.as_ref().unwrap();
    let hdr = p.decoded.as_ref().unwrap().as_ref().unwrap();
    assert_eq!(hdr.span.start, 0);
    assert_eq!(hdr.span.end, p.raw.len());
    // Sanity: the payload decodes to the same item tokenator-cbor gives.
    assert_eq!(
        enc(msg.payload_item().unwrap()),
        enc(&decode(&payload_of(&bytes)).unwrap())
    );
}
