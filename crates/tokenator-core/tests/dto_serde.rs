//! Wire shapes and serde round trips of the DTOs (TEST-PLAN §2).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokenator_core::*;

fn rt<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(v: &T) -> Value {
    let text = serde_json::to_string(v).unwrap();
    let back: T = serde_json::from_str(&text).unwrap();
    assert_eq!(&back, v, "{text}");
    serde_json::from_str(&text).unwrap()
}

fn sample_node() -> Node {
    Node {
        id: node_id("payload/~e/1"),
        kind: NodeKind::Text,
        label: "1".into(),
        annotation: Some(Annotation {
            name: "iss".into(),
            description: "Issuer".into(),
            value_name: None,
            spec: vec![SpecLink {
                text: "RFC 8392, Section 3.1.1".into(),
                url: Some("https://www.rfc-editor.org/rfc/rfc8392#section-3.1.1".into()),
            }],
        }),
        main: Some(TextRange {
            start: 10,
            end: 17,
            line_start: 2,
            line_end: 3,
        }),
        raw: Some(RawRange {
            start: 5,
            end: 12,
            row_start: 3,
            row_end: 4,
        }),
        key: Some(Box::new(Node {
            id: node_id("payload/~e/1/~k"),
            kind: NodeKind::Integer,
            label: "1".into(),
            annotation: None,
            main: None,
            raw: None,
            key: None,
            time: None,
            sd: None,
            children: vec![],
        })),
        time: Some(TimeHint {
            epoch: 1_444_064_944,
            rfc3339: "2015-10-05T17:09:04Z".into(),
            relative: Some("in 1 h".into()),
        }),
        sd: Some(SdMark::Slot {
            digest: "00ff".into(),
            disclosure: Some(2),
        }),
        children: vec![],
    }
}

fn sample_document() -> Document {
    Document {
        kind: Kind::SdCwt,
        layers: vec![Layer::Hex {
            upper: false,
            separator: Some(':'),
            wrap: Some(16),
        }],
        bytes: Bytes(vec![0xd2, 0x84]),
        signed: true,
        signature_stale: false,
        tree: Node {
            children: vec![sample_node()],
            ..sample_node()
        },
        main: Rendered {
            language: Language::Edn,
            text: "18([…])".into(),
            line_count: 1,
        },
        raw: RawView::Hex {
            bytes: Bytes(vec![0xd2, 0x84]),
            rows: vec![HexRow {
                node_id: NodeId::root(),
                kind: HexRowKind::Item,
                depth: 0,
                head: ByteRange { start: 0, end: 1 },
                payload: ByteRange { start: 1, end: 1 },
                description: "tag(18)".into(),
                comment: None,
            }],
        },
        disclosures: vec![DisclosureInfo {
            index: 0,
            node_id: node_id("unprotected/17/0"),
            digest: "ab".into(),
            salt: "cd".into(),
            claim: Some("501".into()),
            value: "\"x\"".into(),
            decoy: false,
            status: DisclosureStatus::Matched,
            slot: Some(node_id("payload/~e/simple(59)/0")),
        }],
        undisclosed: vec![SlotInfo {
            node_id: node_id("payload/~e/502/0"),
            digest: "ef".into(),
            array_element: true,
        }],
        diagnostics: vec![Diagnostic {
            severity: Severity::Warning,
            code: "cbor.trailing_bytes".into(),
            message: "1 byte left".into(),
            node_id: Some(node_id("payload")),
            main: None,
            raw: Some(ByteRange { start: 3, end: 4 }),
        }],
    }
}

#[test]
fn bytes_are_base64url_strings() {
    assert_eq!(rt(&Bytes(vec![0xd2, 0x84, 0x43])), json!("0oRD"));
    assert_eq!(rt(&Bytes(vec![])), json!(""));
    assert_eq!(rt(&Bytes(vec![0xfb, 0xff])), json!("-_8"));
    assert!(
        serde_json::from_str::<Bytes>("\"+/8=\"").is_err(),
        "not base64url"
    );
    assert!(serde_json::from_str::<Bytes>("[1, 2]").is_err());
}

#[test]
fn node_ids_are_plain_strings() {
    assert_eq!(rt(&node_id("payload/~e/iss")), json!("payload/~e/iss"));
    assert_eq!(rt(&NodeId::root()), json!(""));
}

#[test]
fn tagged_enums_use_type_and_snake_case() {
    assert_eq!(rt(&Kind::Jwt), json!({"type": "jwt"}));
    assert_eq!(
        rt(&Kind::SdJwt { kb: true }),
        json!({"type": "sd_jwt", "kb": true})
    );
    assert_eq!(
        rt(&Kind::SdJwtJson {
            general: true,
            kb: false
        }),
        json!({"type": "sd_jwt_json", "general": true, "kb": false})
    );
    assert_eq!(rt(&Kind::EdnClaims), json!({"type": "edn_claims"}));
    assert_eq!(
        rt(&Kind::Pem {
            labels: vec!["PUBLIC KEY".into()]
        }),
        json!({"type": "pem", "labels": ["PUBLIC KEY"]})
    );
    assert_eq!(
        rt(&Layer::CborTag { tag: 61 }),
        json!({"type": "cbor_tag", "tag": 61})
    );
    assert_eq!(
        rt(&Layer::JsonField {
            path: vec![JsonPathSegment::Key("vp".into()), JsonPathSegment::Index(0)]
        }),
        json!({"type": "json_field", "path": ["vp", 0]})
    );
    assert_eq!(
        rt(&Layer::Quotes { quote: '\'' }),
        json!({"type": "quotes", "quote": "'"})
    );
    assert_eq!(rt(&RawView::None), json!({"type": "none"}));
    assert_eq!(
        rt(&TamperOp::FlipBit {
            part: PartRef::Disclosure { index: 2 },
            bit: 7
        }),
        json!({"type": "flip_bit", "part": {"type": "disclosure", "index": 2}, "bit": 7})
    );
    assert_eq!(
        rt(&KeySeed::Seed {
            bytes: Bytes(vec![0; 2])
        }),
        json!({"type": "seed", "bytes": "AAA"})
    );
    assert_eq!(
        rt(&KeySpec::Rsa { bits: 2048 }),
        json!({"type": "rsa", "bits": 2048})
    );
    assert_eq!(
        rt(&KeyFormat::Pem {
            encoding: PemEncoding::Pkcs8MlDsaSeed
        }),
        json!({"type": "pem", "encoding": "pkcs8_ml_dsa_seed"})
    );
}

#[test]
fn unit_enums_are_snake_case_strings() {
    assert_eq!(rt(&Status::Pass), json!("pass"));
    assert_eq!(rt(&Category::KeyBinding), json!("key_binding"));
    assert_eq!(rt(&KeySelection::PanelUnmatched), json!("panel_unmatched"));
    assert_eq!(
        rt(&CborSerialization::PreferredPlus),
        json!("preferred_plus")
    );
    assert_eq!(
        rt(&JoseSerialization::JsonFlattened),
        json!("json_flattened")
    );
    assert_eq!(rt(&DateFormKind::DtTagged), json!("dt_tagged"));
    assert_eq!(rt(&ErrorCode::NothingToRedact), json!("nothing_to_redact"));
    assert_eq!(
        rt(&RegistryKind::CoseKeyTypeParam),
        json!("cose_key_type_param")
    );
    assert_eq!(rt(&HashName::Sha384), json!("sha384"));
    assert_eq!(
        rt(&DisclosureStatus::ForbiddenName),
        json!("forbidden_name")
    );
}

#[test]
fn untagged_unions() {
    assert_eq!(rt(&AlgValue::Name("none".into())), json!("none"));
    assert_eq!(rt(&AlgValue::Label(-7)), json!(-7));
    assert_eq!(rt(&RegistryLabel::Int(4)), json!(4));
    assert_eq!(rt(&RegistryLabel::Text("kid".into())), json!("kid"));
}

#[test]
fn defaults_fill_missing_fields() {
    let v: ViewOptions = serde_json::from_str("{}").unwrap();
    assert_eq!(v, ViewOptions::default());
    assert!(v.decoded_views && v.annotations);
    assert_eq!(v.indent, 2);

    let req: ValidateRequest =
        serde_json::from_value(json!({"doc": {"kind": {"type": "cwt"}, "bytes": "0oQ"}, "now": 5}))
            .unwrap();
    assert_eq!(req.skew, 60);
    assert!(req.keys.is_empty());

    let k: KeyRef = serde_json::from_value(json!({"bytes": "e30"})).unwrap();
    assert_eq!(k, KeyRef::new(b"{}".to_vec()));

    let r: RenderRequest =
        serde_json::from_value(json!({"doc": {"kind": {"type": "jwt"}, "bytes": ""}})).unwrap();
    assert!(r.layers.is_empty());

    let s: SdOptions = serde_json::from_str("{}").unwrap();
    assert_eq!(s, SdOptions::default());
    let h: HeaderOptions = serde_json::from_str("{}").unwrap();
    assert_eq!(h.typ, TypChoice::Auto);
    assert_eq!(h.kid, KidChoice::None);
}

#[test]
fn documents_round_trip() {
    let doc = sample_document();
    let v = rt(&doc);
    assert_eq!(v["kind"], json!({"type": "sd_cwt"}));
    assert_eq!(v["raw"]["type"], "hex");
    assert_eq!(v["tree"]["children"][0]["key"]["id"], "payload/~e/1/~k");
    assert_eq!(v["tree"]["children"][0]["sd"]["type"], "slot");
    assert_eq!(v["main"]["language"], "edn");
    let segs = RawView::Segments {
        segments: vec![Segment {
            node_id: node_id("protected"),
            label: "Protected header".into(),
            range: ByteRange { start: 0, end: 20 },
            text: "eyJhbGciOiJFUzI1NiJ9".into(),
            separator: Some(".".into()),
        }],
    };
    assert_eq!(rt(&segs)["segments"][0]["separator"], ".");
}

#[test]
fn reports_round_trip() {
    let report = ValidationReport {
        overall: Status::Warn,
        items: vec![
            CheckItem {
                id: "signature".into(),
                category: Category::Signature,
                status: Status::Pass,
                message: "verified".into(),
                node_ids: vec![node_id("signature")],
                raw: None,
                detail: Some(CheckDetail::Signature {
                    alg: Some("ES256".into()),
                    key_index: Some(0),
                    key_label: Some("issuer".into()),
                    selection: KeySelection::PanelKid,
                    untrusted: false,
                }),
            },
            CheckItem {
                id: "lint.encoding".into(),
                category: Category::Lint,
                status: Status::Info,
                message: "non-preferred".into(),
                node_ids: vec![],
                raw: Some(ByteRange { start: 2, end: 4 }),
                detail: Some(CheckDetail::Encoding {
                    finding: "non_preferred_argument".into(),
                    preferred_hex: "43".into(),
                }),
            },
        ],
        fetchable: vec![FetchHint {
            kind: FetchKind::KidUrl,
            url: "https://issuer.example/cose-key3".into(),
            reason: "kid is a URL".into(),
        }],
    };
    let v = rt(&report);
    assert_eq!(v["items"][0]["detail"]["type"], "signature");
    assert_eq!(v["items"][0]["detail"]["selection"], "panel_kid");
    assert_eq!(v["fetchable"][0]["kind"], "kid_url");
}

#[test]
fn requests_round_trip() {
    let doc = DocRef::new(Kind::JsonClaims, b"{}".to_vec());
    let key = KeyRef {
        bytes: Bytes(b"{}".to_vec()),
        format: Some(KeyFormat::Jwk),
        index: 1,
        role: Some(Role::Holder),
        label: Some("holder".into()),
    };
    rt(&IssueRequest {
        claims: doc.clone(),
        issuer: key.clone(),
        alg: Some("ES256".into()),
        header: HeaderOptions {
            typ: TypChoice::Value {
                value: "example+sd-jwt".into(),
            },
            kid: KidChoice::Value {
                kid: KidValue::Bytes {
                    value: Bytes(vec![1]),
                },
            },
            x5c: vec!["MII".into()],
            extra: Some("{}".into()),
            unprotected_extra: None,
        },
        sd: SdOptions {
            marks: vec![node_id("email")],
            decoys: vec![DecoyRequest {
                at: NodeId::root(),
                count: 2,
            }],
            sd_alg: Some(HashName::Sha512),
            fixed_salts: vec!["salt".into()],
            digest_order: DigestOrder::Creation,
            force_sd: true,
        },
        cnf: Some(CnfChoice::Key { key: key.clone() }),
        jose_serialization: JoseSerialization::JsonGeneral,
        cose_tags: Some(vec![61, 18]),
        randomness: Some(seed(1)),
        view: ViewOptions::default(),
    });
    rt(&PresentRequest {
        doc: doc.clone(),
        keep: vec![1, 0],
        holder: key.clone(),
        alg: None,
        aud: Some("a".into()),
        nonce: Some(Nonce::Bytes {
            value: Bytes(vec![9]),
        }),
        iat: 1_700_000_000,
        randomness: None,
        view: ViewOptions::default(),
    });
    rt(&ReencodeRequest {
        doc: doc.clone(),
        layers: vec![Layer::Base64Std {
            padded: true,
            wrap: Some(76),
        }],
        cose_tags: Some(vec![]),
        cbor: CborSerialization::Deterministic,
        deep: true,
        jose: Some(JoseSerialization::Compact),
        view: ViewOptions::default(),
    });
    rt(&EditDisclosuresRequest {
        doc: doc.clone(),
        ops: vec![
            DisclosureOp::Remove { index: 0 },
            DisclosureOp::Move { from: 1, to: 0 },
            DisclosureOp::Forge {
                salt: None,
                claim: Some("x".into()),
                value: Some("1".into()),
            },
            DisclosureOp::AddDecoy {
                at: node_id("payload/~e"),
                digest: None,
            },
        ],
        randomness: Some(seed(2)),
        view: ViewOptions::default(),
    });
    rt(&TamperRequest {
        doc: doc.clone(),
        op: TamperOp::SetKid {
            kid: Some(KidValue::Text { value: "k".into() }),
        },
        view: ViewOptions::default(),
    });
    rt(&KeyGenRequest {
        spec: KeySpec::MlDsa87,
        role: Some(Role::Issuer),
        seed: KeySeed::WellKnown,
        kid: Some(KidSource::CoseThumbprint {
            hash: HashName::Sha256,
        }),
    });
    rt(&DateTimeRequest {
        input: DateTimeInput::Edn {
            text: "1(0)".into(),
        },
        now: Some(0),
        local_offset_minutes: -330,
    });
    rt(&RegistryMergeRequest {
        base_snapshot: None,
        xml: Bytes(b"<x/>".to_vec()),
        which: RegistryId::Cose,
    });
    rt(&EditRequest {
        kind: Kind::Cwt,
        base: Bytes(vec![1]),
        text: "1".into(),
        view: ViewOptions::default(),
    });
}

#[test]
fn errors_serialize() {
    let err = EngineError::new(ErrorCode::NothingToRedact, "no claim is marked");
    assert_eq!(
        rt(&err),
        json!({"code": "nothing_to_redact", "message": "no claim is marked", "node_id": null})
    );
    assert!(err.to_string().contains("no claim is marked"));
}

#[test]
fn kind_helpers() {
    assert_eq!(Kind::Cwt.family(), Some(Family::Cose));
    assert_eq!(Kind::JsonClaims.family(), Some(Family::Jose));
    assert_eq!(Kind::Jwk.family(), None);
    assert!(Kind::CoseKeySet.is_key());
    assert!(Kind::SdKbt.is_signed());
    assert!(!Kind::EdnClaims.is_signed());
    assert_eq!(Kind::SdJwt { kb: true }.label(), "SD-JWT+KB");
    assert_eq!(Kind::SdKbt.label(), "SD-KBT");
}
