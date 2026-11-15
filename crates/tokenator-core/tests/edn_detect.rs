//! EDN text is classified by the CBOR it encodes (#44): COSE_Sign1 as a
//! CWT / SD-CWT / SD-KBT, claims maps as EDN claim sets, and COSE_Keys as
//! keys for `detect_key` (but as EDN claim sets for `detect`).
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
fn edn_cose_keys_are_claim_sets_to_detect() {
    // SPEC §3: token detection never returns a key; a COSE_Key map is an
    // EDN claim set there, and a COSE_KeySet array is nothing.
    let k = kinds(COSE_KEY);
    assert_eq!(k.first(), Some(&Kind::EdnClaims));
    assert!(!k.iter().any(Kind::is_key), "{k:?}");
    assert!(kinds(&format!("[{COSE_KEY}]")).is_empty());
    let e = engine();
    let cands = e.detect(COSE_KEY.as_bytes());
    let doc = e
        .open(COSE_KEY.as_bytes(), &cands[0], &ViewOptions::default())
        .unwrap();
    assert_eq!(doc.kind, Kind::EdnClaims);
    assert_eq!(doc.bytes.0, COSE_KEY.as_bytes());
}

#[test]
fn edn_cose_keys_are_keys_to_detect_key() {
    let e = engine();
    let key_kinds = |text: &str| -> Vec<Kind> {
        e.detect_key(text.as_bytes())
            .into_iter()
            .map(|c| c.kind)
            .collect()
    };
    assert_eq!(key_kinds(COSE_KEY).first(), Some(&Kind::CoseKey));
    assert_eq!(
        key_kinds(&format!("[{COSE_KEY}]")).first(),
        Some(&Kind::CoseKeySet)
    );
    for text in [COSE_KEY, "{ / iss / 1: \"a\", 4: 1725330600 }", SIGN1] {
        assert!(key_kinds(text).iter().all(Kind::is_key), "{text}");
    }
    assert!(key_kinds(SIGN1).is_empty());
    // The key panel imports through the candidate (EDN → CBOR first), and
    // opening it as a document is refused.
    let c = e.detect_key(COSE_KEY.as_bytes()).remove(0);
    assert!(
        e.open(COSE_KEY.as_bytes(), &c, &ViewOptions::default())
            .is_err()
    );
    let keys = e
        .key_import(&tokenator_core::KeyImportRequest {
            bytes: COSE_KEY.as_bytes().to_vec().into(),
            format: None,
            candidate: Some(c),
        })
        .unwrap();
    assert_eq!(keys.len(), 1);
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

/// SPEC §3 "Detected as…": a JSON claim set can be read as EDN instead.
/// Every `json_claims` candidate of text input comes with an `edn_claims`
/// one, ranked below it, that opens as an EDN document.
#[test]
fn json_claim_sets_are_also_offered_as_edn() {
    let e = engine();
    let mut inputs: Vec<(String, Vec<u8>)> =
        ["rfc7519-s3.1-claims.json", "rfc9901-s5.1-input-claims.json"]
            .iter()
            .map(|n| (n.to_string(), token(n)))
            .collect();
    for n in [
        "rfc9901-a5-ec-p256-public.jwk.json",
        "rfc7517-a1-public.jwks.json",
    ] {
        inputs.push((n.to_string(), key_file(n)));
    }
    for text in ["{}", r#"{"iss":"x"}"#, " {\"a\": [1, 2.5, true, null]}\n"] {
        inputs.push((text.to_string(), text.as_bytes().to_vec()));
    }
    for (name, input) in inputs {
        let cands = e.detect(&input);
        assert_eq!(
            cands.first().map(|c| &c.kind),
            Some(&Kind::JsonClaims),
            "{name}"
        );
        let json = &cands[0];
        let edn = cands
            .iter()
            .find(|c| c.kind == Kind::EdnClaims)
            .unwrap_or_else(|| panic!("{name}: no EDN reading in {cands:?}"));
        assert!(edn.confidence < json.confidence, "{name}: {cands:?}");
        let doc = e
            .open(&input, edn, &ViewOptions::default())
            .unwrap_or_else(|err| panic!("{name}: {err}"));
        assert_eq!(doc.kind, Kind::EdnClaims, "{name}");
        assert!(!doc.signed, "{name}");
    }
}

#[test]
fn jws_json_and_token_containers_get_no_edn_reading() {
    let e = engine();
    let mut inputs: Vec<(String, Vec<u8>)> = [
        "rfc7515-a6-jws-json-general.json",
        "rfc7515-a7-jws-json-flattened.json",
        "rfc9901-s8.2-sd-jwt-json-flattened.json",
        "rfc9901-s8.2-sd-jwt-kb-json-flattened.json",
        "rfc9901-s8.3-sd-jwt-kb-json-general.json",
    ]
    .iter()
    .map(|n| (n.to_string(), token(n)))
    .collect();
    let sd = String::from_utf8(token("rfc9901-s5.1-sd-jwt.txt")).unwrap();
    let container = format!(r#"{{"credential": "{}", "state": "xyz"}}"#, sd.trim());
    inputs.push(("container".into(), container.into_bytes()));
    for (name, input) in inputs {
        let cands = e.detect(&input);
        assert!(
            !cands.iter().any(|c| c.kind == Kind::EdnClaims),
            "{name}: {cands:?}"
        );
    }
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
