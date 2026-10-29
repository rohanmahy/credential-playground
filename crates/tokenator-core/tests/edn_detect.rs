//! EDN text is classified by the CBOR it encodes (#44): COSE_Sign1 as a
//! CWT / SD-CWT / SD-KBT, COSE_Keys as keys, claims maps as EDN claim sets.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_core::{
    CborSerialization, DocRef, Kind, Layer, ReencodeRequest, Status, ViewOptions,
};

const SIGN1: &str = r#"18([<< {1: -7} >>, {}, << {1: "issuer", 4: 1893456000} >>, h'00'])"#;
const COSE_KEY: &str = "{1: 2, -1: 1, -2: h'58a9fe64819ebdcc06232cabcc5a1934175aabdfd3b2acc697dea8734096ba2b', -3: h'cbbeedf91bc01d1293b1219d21851fc1eb8ebf0aef0c3f90dc7bf92747d229b1'}";

fn kinds(text: &str) -> Vec<Kind> {
    engine()
        .detect(text.as_bytes())
        .into_iter()
        .map(|c| c.kind)
        .collect()
}

/// The EDN of a fixture, as the printer writes it.
fn edn_of(name: &str) -> String {
    let bytes = token(name);
    let item = tokenator_cbor::decode(&bytes).unwrap();
    tokenator_edn::print(&item, &tokenator_edn::PrintOptions::indented(2)).text
}

#[test]
fn edn_cose_sign1_detects_as_cwt_and_opens() {
    let e = engine();
    let cands = e.detect(SIGN1.as_bytes());
    let top = &cands[0];
    assert_eq!(top.kind, Kind::Cwt);
    assert_eq!(top.layers, [Layer::Edn, Layer::CborTag { tag: 18 }]);
    assert_eq!(top.breadcrumb, ["EDN", "COSE_Sign1 tag 18", "CWT"]);
    let doc = e
        .open(SIGN1.as_bytes(), top, &ViewOptions::default())
        .unwrap();
    assert_eq!(doc.kind, Kind::Cwt);
    assert_eq!(doc.bytes.0, edn(SIGN1), "the CBOR, tags included");
    assert_eq!(doc.layers, [Layer::Edn]);
    assert!(has_node(&doc, "payload/~e/4"));
}

#[test]
fn fixtures_written_as_edn_keep_their_kind() {
    let e = engine();
    for (name, kind) in [
        (CWT_TAGGED, Kind::Cwt),
        (CWT_UNTAGGED, Kind::Cwt),
        (CWT_TAG61, Kind::Cwt),
        ("rfc9052-c2.1-sign1.cbor", Kind::CoseSign1),
        (SD_ISSUER, Kind::SdCwt),
        (SD_KBT, Kind::SdKbt),
    ] {
        let text = edn_of(name);
        let cands = e.detect(text.as_bytes());
        assert_eq!(cands[0].kind, kind, "{name}");
        let doc = e
            .open(text.as_bytes(), &cands[0], &ViewOptions::default())
            .unwrap();
        assert_eq!(
            doc.bytes.0,
            token(name),
            "{name}: same bytes as the binary token"
        );
    }
    // An EDN SD-CWT validates like the binary one.
    let text = edn_of(SD_ISSUER);
    let doc = open(&e, text.as_bytes());
    let r = validate(&e, &doc, vec![sd_issuer_key()], SD_NOW);
    assert_status(&r, "signature", Status::Pass);
}

#[test]
fn edn_cose_keys_rank_above_claim_sets() {
    let k = kinds(COSE_KEY);
    assert_eq!(k[0], Kind::CoseKey);
    assert!(k.contains(&Kind::EdnClaims), "{k:?}");
    let set = format!("[{COSE_KEY}]");
    assert_eq!(kinds(&set)[0], Kind::CoseKeySet);
    // The key panel imports the EDN text directly.
    let e = engine();
    let cands = e.detect(COSE_KEY.as_bytes());
    assert!(
        e.open(COSE_KEY.as_bytes(), &cands[0], &ViewOptions::default())
            .is_err()
    );
}

#[test]
fn claim_maps_stay_edn_claim_sets_with_their_text() {
    let e = engine();
    let text = "{ / iss / 1: \"a\", 4: 1725330600 }\n";
    let cands = e.detect(text.as_bytes());
    assert_eq!(cands[0].kind, Kind::EdnClaims);
    assert!(!cands[0].layers.contains(&Layer::Edn));
    let doc = e
        .open(text.as_bytes(), &cands[0], &ViewOptions::default())
        .unwrap();
    assert_eq!(doc.bytes.0, text.as_bytes());
}

#[test]
fn edn_that_is_neither_gives_nothing() {
    assert!(kinds("[1, 2, 3]").is_empty());
    assert!(kinds("12(zzz)").is_empty());
    assert!(kinds("18([1, 2])").is_empty());
}

#[test]
fn reencode_can_write_edn() {
    let e = engine();
    let doc = open_token(&e, CWT_TAGGED);
    let out = e
        .reencode(&ReencodeRequest {
            doc: DocRef::from(&doc),
            layers: vec![Layer::Edn],
            cose_tags: None,
            cbor: CborSerialization::Preserve,
            deep: false,
            jose: None,
            view: ViewOptions::default(),
        })
        .unwrap();
    let text = String::from_utf8(out.output.0.clone()).unwrap();
    assert!(text.starts_with("18(["), "{text}");
    let back = open(&e, &out.output);
    assert_eq!(back.kind, Kind::Cwt);
    assert_eq!(back.bytes, doc.bytes);
    let mut bad = ReencodeRequest {
        doc: DocRef::from(&doc),
        layers: vec![
            Layer::Edn,
            Layer::Hex {
                upper: false,
                separator: None,
                wrap: None,
            },
        ],
        cose_tags: None,
        cbor: CborSerialization::Preserve,
        deep: false,
        jose: None,
        view: ViewOptions::default(),
    };
    assert!(e.reencode(&bad).is_err(), "EDN must be innermost");
    bad.layers = vec![
        Layer::Hex {
            upper: false,
            separator: None,
            wrap: None,
        },
        Layer::Edn,
    ];
    assert!(e.reencode(&bad).is_ok());
}
