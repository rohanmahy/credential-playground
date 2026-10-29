//! Re-encode: outer layers, COSE tags, CBOR serializations, JOSE
//! serializations.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use base64ct::{Base64UrlUnpadded, Encoding};
use common::*;
use tokenator_core::{
    CborSerialization, DocRef, Document, Engine, EquivalentEncoding, ErrorCode, JoseSerialization,
    Kind, Layer, Nonce, ReencodeRequest, Reencoded, Status, TamperOp, TamperRequest,
    ValidateRequest, ViewOptions,
};

fn req(doc: &Document) -> ReencodeRequest {
    ReencodeRequest {
        doc: DocRef::from(doc),
        layers: vec![],
        cose_tags: None,
        cbor: CborSerialization::Preserve,
        deep: false,
        jose: None,
        view: ViewOptions::default(),
    }
}

fn run(e: &Engine, r: &ReencodeRequest) -> Reencoded {
    e.reencode(r).unwrap()
}

fn claims(e: &Engine, hex: &str) -> Document {
    render(e, Kind::CborClaims, &hexd(hex))
}

fn serialize(e: &Engine, doc: &Document, mode: CborSerialization) -> Vec<u8> {
    let mut r = req(doc);
    r.cbor = mode;
    run(e, &r).document.bytes.0
}

// ---------------------------------------------------------------- layers and tags

#[test]
fn preserve_with_no_changes_is_the_identity() {
    let e = engine();
    for name in COSE_FIXTURES {
        let doc = open_token(&e, name);
        let out = run(&e, &req(&doc));
        assert_eq!(out.output, doc.bytes, "{name}");
        assert_eq!(out.document.bytes, doc.bytes, "{name}");
        assert!(!out.document.signature_stale, "{name}");
    }
}

#[test]
fn cose_tags_can_be_dropped_and_added() {
    let e = engine();
    let doc = open_token(&e, CWT_TAGGED);
    let mut r = req(&doc);
    r.cose_tags = Some(vec![]);
    let out = run(&e, &r);
    assert_eq!(&out.output[..], &token(CWT_UNTAGGED)[..]);
    r.cose_tags = Some(vec![61, 18]);
    let out = run(&e, &r);
    assert_eq!(&out.output[..], &token(CWT_TAG61)[..]);
    assert_eq!(ids(&out.document), ids(&doc), "tags fold into the root");
    assert_status(
        &validate(&e, &out.document, vec![rfc8392_key()], RFC8392_NOW),
        "signature",
        Status::Pass,
    );
}

#[test]
fn outer_hex_and_base64url_layers() {
    let e = engine();
    let doc = open_token(&e, CWT_TAGGED);
    let raw = token(CWT_TAGGED);

    let mut r = req(&doc);
    r.layers = vec![Layer::Hex {
        upper: false,
        separator: None,
        wrap: None,
    }];
    let out = run(&e, &r);
    assert_eq!(out.output.0, hex::encode(&raw).into_bytes());
    assert_eq!(out.document.layers, r.layers);
    assert_eq!(out.document.bytes.0, raw);

    r.layers = vec![Layer::Base64Url {
        padded: false,
        wrap: None,
    }];
    let out = run(&e, &r);
    assert_eq!(
        out.output.0,
        Base64UrlUnpadded::encode_string(&raw).into_bytes()
    );
    // And it detects back to the same credential.
    let back = open(&e, &out.output);
    assert_eq!(back.kind, Kind::Cwt);
    assert_eq!(back.bytes.0, raw);
}

#[test]
fn bearer_header_around_a_jwt() {
    let e = engine();
    let doc = open_token(&e, "rfc7515-a3-jws-es256.txt");
    let mut r = req(&doc);
    r.layers = vec![
        Layer::AuthorizationHeader {
            prefix: "Authorization: ".into(),
        },
        Layer::BearerPrefix {
            prefix: "Bearer ".into(),
        },
    ];
    let out = run(&e, &r);
    let jwt = token_text("rfc7515-a3-jws-es256.txt");
    assert_eq!(
        out.output.0,
        format!("Authorization: Bearer {jwt}").into_bytes()
    );
}

#[test]
fn cbor_tag_layers_are_rejected_in_favor_of_cose_tags() {
    let e = engine();
    let doc = open_token(&e, CWT_UNTAGGED);
    let mut r = req(&doc);
    r.layers = vec![Layer::CborTag { tag: 18 }];
    assert_eq!(e.reencode(&r).unwrap_err().code, ErrorCode::InvalidInput);
}

// ---------------------------------------------------------------- CBOR serializations

#[test]
fn deterministic_sorts_map_keys_preferred_plus_keeps_order() {
    let e = engine();
    let doc = claims(&e, "a2 02 18 01 01 02");
    assert_eq!(
        serialize(&e, &doc, CborSerialization::Preserve),
        hexd("a2 02 18 01 01 02")
    );
    assert_eq!(
        serialize(&e, &doc, CborSerialization::PreferredPlus),
        hexd("a2 02 01 01 02")
    );
    assert_eq!(
        serialize(&e, &doc, CborSerialization::Deterministic),
        hexd("a2 01 02 02 01")
    );
}

#[test]
fn preferred_plus_fixes_nan_bignum_and_indefinite_lengths() {
    let e = engine();
    let cases = [
        ("a1 01 fa 7f c0 00 00", "a1 01 f9 7e 00"),
        ("a1 01 c2 41 01", "a1 01 01"),
        ("bf 01 02 ff", "a1 01 02"),
        ("a1 01 fb 3f f8 00 00 00 00 00 00", "a1 01 f9 3e 00"),
        ("a1 01 7f 61 61 61 62 ff", "a1 01 62 61 62"),
    ];
    for (input, expected) in cases {
        let doc = claims(&e, input);
        assert_eq!(
            serialize(&e, &doc, CborSerialization::PreferredPlus),
            hexd(expected),
            "{input}"
        );
    }
}

#[test]
fn preferred_plus_undoes_a_wide_protected_bstr_head() {
    let e = engine();
    let wide = e
        .tamper(&TamperRequest {
            doc: DocRef::from(&open_token(&e, CWT_TAGGED)),
            op: TamperOp::ReencodeProtected {
                how: EquivalentEncoding::WideBstrHead,
            },
            view: ViewOptions::default(),
        })
        .unwrap();
    let mut r = req(&wide);
    r.cbor = CborSerialization::PreferredPlus;
    let out = run(&e, &r);
    assert_eq!(&out.document.bytes[..], &token(CWT_TAGGED)[..]);
    assert!(!out.document.signature_stale, "only a bstr head changed");
    assert_status(
        &validate(&e, &out.document, vec![rfc8392_key()], RFC8392_NOW),
        "signature",
        Status::Pass,
    );
}

#[test]
fn deep_reaches_into_the_protected_header() {
    let e = engine();
    let wide = e
        .tamper(&TamperRequest {
            doc: DocRef::from(&open_token(&e, CWT_TAGGED)),
            op: TamperOp::ReencodeProtected {
                how: EquivalentEncoding::WideIntegers,
            },
            view: ViewOptions::default(),
        })
        .unwrap();
    let mut r = req(&wide);
    r.cbor = CborSerialization::PreferredPlus;
    // Outer only: the header contents (signed) are untouched.
    let outer = run(&e, &r);
    assert_eq!(
        raw_bytes(&outer.document, "protected"),
        raw_bytes(&wide, "protected")
    );
    // Deep: back to the original preferred header, which verifies again.
    r.deep = true;
    let deep = run(&e, &r);
    assert_eq!(&deep.document.bytes[..], &token(CWT_TAGGED)[..]);
    assert_status(
        &validate(&e, &deep.document, vec![rfc8392_key()], RFC8392_NOW),
        "signature",
        Status::Pass,
    );
}

#[test]
fn deep_on_conforming_tokens_changes_nothing() {
    let e = engine();
    for name in [CWT_TAGGED, SD_ISSUER, SD_KBT] {
        let doc = open_token(&e, name);
        let mut r = req(&doc);
        r.cbor = CborSerialization::PreferredPlus;
        r.deep = true;
        let out = run(&e, &r);
        assert_eq!(out.document.bytes, doc.bytes, "{name}");
        assert!(!out.document.signature_stale, "{name}");
    }
}

#[test]
fn deterministic_cwt_still_verifies_when_only_outer_maps_move() {
    let e = engine();
    let doc = open_token(&e, SD_ISSUER);
    let mut r = req(&doc);
    r.cbor = CborSerialization::Deterministic;
    let out = run(&e, &r);
    assert_status(
        &validate(&e, &out.document, vec![sd_issuer_key()], SD_NOW),
        "signature",
        Status::Pass,
    );
}

// ---------------------------------------------------------------- JOSE serializations

#[test]
fn compact_json_compact_round_trip() {
    let e = engine();
    for name in [
        "rfc7515-a3-jws-es256.txt",
        "rfc9901-s5.1-sd-jwt.txt",
        "rfc9901-s5.2-sd-jwt-kb.txt",
    ] {
        let doc = open_token(&e, name);
        for ser in [
            JoseSerialization::JsonFlattened,
            JoseSerialization::JsonGeneral,
        ] {
            let mut r = req(&doc);
            r.jose = Some(ser);
            let json = run(&e, &r).document;
            assert!(
                matches!(json.kind, Kind::JwsJson { .. } | Kind::SdJwtJson { .. }),
                "{name}: {:?}",
                json.kind
            );
            let mut back = req(&json);
            back.jose = Some(JoseSerialization::Compact);
            assert_eq!(run(&e, &back).document.bytes, doc.bytes, "{name} {ser:?}");
        }
    }
}

#[test]
fn json_serialization_keeps_kb_valid() {
    let e = engine();
    let doc = open_token(&e, "rfc9901-s5.2-sd-jwt-kb.txt");
    let mut r = req(&doc);
    r.jose = Some(JoseSerialization::JsonGeneral);
    let json = run(&e, &r).document;
    assert_eq!(
        json.kind,
        Kind::SdJwtJson {
            general: true,
            kb: true
        }
    );
    let mut v = ValidateRequest::new(DocRef::from(&json), RFC9901_NOW);
    v.keys = vec![rfc9901_issuer()];
    v.expected_aud = Some(RFC9901_AUD.into());
    v.expected_nonce = Some(Nonce::Text {
        value: RFC9901_NONCE.into(),
    });
    let report = e.validate(&v).unwrap();
    assert_status(&report, "signature", Status::Pass);
    assert_status(&report, "kb.sd_hash", Status::Pass);
}

#[test]
fn mismatched_options_are_rejected() {
    let e = engine();
    let jwt = open_token(&e, "rfc7515-a3-jws-es256.txt");
    let mut r = req(&jwt);
    r.cbor = CborSerialization::Deterministic;
    assert_eq!(e.reencode(&r).unwrap_err().code, ErrorCode::InvalidInput);
    let mut r = req(&jwt);
    r.cose_tags = Some(vec![]);
    assert_eq!(e.reencode(&r).unwrap_err().code, ErrorCode::InvalidInput);
    let cwt = open_token(&e, CWT_TAGGED);
    let mut r = req(&cwt);
    r.jose = Some(JoseSerialization::Compact);
    assert_eq!(e.reencode(&r).unwrap_err().code, ErrorCode::InvalidInput);
}
