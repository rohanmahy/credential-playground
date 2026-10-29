//! Detection through the Engine: classification of every fixture, layers
//! kept outside `Document.bytes`, EDN confirmation, key routing.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use base64ct::{Base64UrlUnpadded, Encoding};
use common::*;
use tokenator_core::{ErrorCode, JsonPathSegment, Kind, Layer};

type KindCheck = fn(&Kind) -> bool;

fn top_kind(name: &str) -> Kind {
    top(&engine(), &token(name)).kind
}

#[test]
fn jose_compact_fixtures_classify() {
    let cases = [
        ("rfc7515-a1-jws-hs256.txt", Kind::Jwt),
        ("rfc7515-a2-jws-rs256.txt", Kind::Jwt),
        ("rfc7515-a3-jws-es256.txt", Kind::Jwt),
        ("rfc7515-a4-jws-es512-nonjson-payload.txt", Kind::JwsCompact),
        ("rfc7515-a5-unsecured-jws.txt", Kind::Jwt),
        ("rfc7519-s3.1-jwt-hs256.txt", Kind::Jwt),
        ("rfc7519-s6.1-unsecured-jwt.txt", Kind::Jwt),
        ("rfc9901-s5.1-issuer-signed-jwt.txt", Kind::Jwt),
        ("rfc9901-s5.1-sd-jwt.txt", Kind::SdJwt { kb: false }),
        ("rfc9901-s5.2-sd-jwt-kb.txt", Kind::SdJwt { kb: true }),
        ("rfc9901-a1-presentation.txt", Kind::SdJwt { kb: false }),
        ("rfc9901-a2-presentation.txt", Kind::SdJwt { kb: false }),
        ("rfc9901-a3-sd-jwt.txt", Kind::SdJwt { kb: false }),
        ("rfc9901-a3-sd-jwt-kb.txt", Kind::SdJwt { kb: true }),
        ("rfc9901-a4-sd-jwt.txt", Kind::SdJwt { kb: false }),
        ("rfc9901-a4-sd-jwt-kb.txt", Kind::SdJwt { kb: true }),
    ];
    for (name, kind) in cases {
        assert_eq!(top_kind(name), kind, "{name}");
    }
}

#[test]
fn jose_json_fixtures_classify() {
    let cases = [
        (
            "rfc7515-a6-jws-json-general.json",
            Kind::JwsJson { general: true },
        ),
        (
            "rfc7515-a7-jws-json-flattened.json",
            Kind::JwsJson { general: false },
        ),
        (
            "rfc9901-s8.2-sd-jwt-json-flattened.json",
            Kind::SdJwtJson {
                general: false,
                kb: false,
            },
        ),
        (
            "rfc9901-s8.2-sd-jwt-kb-json-flattened.json",
            Kind::SdJwtJson {
                general: false,
                kb: true,
            },
        ),
        (
            "rfc9901-s8.3-sd-jwt-kb-json-general.json",
            Kind::SdJwtJson {
                general: true,
                kb: true,
            },
        ),
    ];
    for (name, kind) in cases {
        assert_eq!(top_kind(name), kind, "{name}");
    }
}

#[test]
fn cose_fixtures_classify() {
    let cases = [
        (CWT_TAGGED, Kind::Cwt),
        (CWT_UNTAGGED, Kind::Cwt),
        (CWT_TAG61, Kind::Cwt),
        ("rfc9052-c2.1-sign1.cbor", Kind::CoseSign1),
        (SD_ISSUER, Kind::SdCwt),
        (SD_NESTED_ISSUER, Kind::SdCwt),
        (SD_DECOY, Kind::SdCwt),
        (SD_KBT, Kind::SdKbt),
        (SD_NESTED_KBT, Kind::SdKbt),
    ];
    for (name, kind) in cases {
        assert_eq!(top_kind(name), kind, "{name}");
    }
}

#[test]
fn unsupported_cose_structures_are_not_sign1() {
    let e = engine();
    for name in [
        "rfc8392-a4-maced-cwt-tag61.cbor",
        "rfc8392-a5-encrypted-cwt.cbor",
        "rfc8392-a7-maced-cwt-float.cbor",
    ] {
        for c in e.detect(&token(name)) {
            assert!(
                !matches!(
                    c.kind,
                    Kind::Cwt | Kind::CoseSign1 | Kind::SdCwt | Kind::SdKbt
                ),
                "{name}: {:?}",
                c.kind
            );
        }
    }
}

#[test]
fn claim_sets_classify_as_drafts() {
    assert_eq!(top_kind("rfc7519-s3.1-claims.json"), Kind::JsonClaims);
    assert_eq!(top_kind("rfc9901-s5.1-input-claims.json"), Kind::JsonClaims);
    assert_eq!(top_kind("rfc8392-a1-claims.cbor"), Kind::CborClaims);
    assert_eq!(top_kind("sd-cwt-08-fig4-claims.edn"), Kind::EdnClaims);
    for k in [Kind::JsonClaims, Kind::CborClaims, Kind::EdnClaims] {
        assert!(k.is_claims() && !k.is_signed() && !k.is_key());
    }
}

#[test]
fn keys_are_candidates_for_the_key_panel() {
    let e = engine();
    let cases: [(&str, KindCheck); 6] = [
        ("rfc7517-a1-public.jwks.json", |k| *k == Kind::JwkSet),
        ("rfc9901-a5-ec-p256-public.jwk.json", |k| *k == Kind::Jwk),
        ("rfc8392-a2.3-ec-p256.cosekey.cbor", |k| *k == Kind::CoseKey),
        ("rfc8152-c7.1-public.cosekeyset.cbor", |k| {
            *k == Kind::CoseKeySet
        }),
        ("sd-cwt-08-c1-holder-public.pem", |k| {
            *k == Kind::Pem {
                labels: vec!["PUBLIC KEY".into()],
            }
        }),
        ("rfc8410-s10.3-ed25519-private.pem", |k| {
            *k == Kind::Pem {
                labels: vec!["PRIVATE KEY".into()],
            }
        }),
    ];
    for (name, pred) in cases {
        let t = top(&e, &key_file(name));
        assert!(pred(&t.kind), "{name}: {:?}", t.kind);
        assert!(t.kind.is_key(), "{name}");
    }
}

#[test]
fn opening_a_key_kind_is_refused() {
    let e = engine();
    let input = key_file("rfc9901-a5-ec-p256-public.jwk.json");
    let c = top(&e, &input);
    let err = e.open(&input, &c, &view()).unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedKind);
}

#[test]
fn opening_with_a_foreign_candidate_fails_cleanly() {
    let e = engine();
    let c = top(&e, &token(CWT_TAGGED));
    assert!(e.open(b"not a token at all", &c, &view()).is_err());
}

#[test]
fn breadcrumb_ends_with_the_kind_label() {
    let e = engine();
    for name in JOSE_FIXTURES.iter().chain(COSE_FIXTURES.iter()) {
        for c in e.detect(&token(name)) {
            assert_eq!(
                c.breadcrumb.last().map(String::as_str),
                Some(c.kind.label()),
                "{name}"
            );
        }
    }
}

#[test]
fn compact_token_text_keeps_its_trim_layer_outside_bytes() {
    let e = engine();
    let input = token("rfc7515-a3-jws-es256.txt");
    let c = top(&e, &input);
    assert!(
        matches!(&c.layers[..], [Layer::Trim { trailing, .. }] if trailing == "\n"),
        "{:?}",
        c.layers
    );
    let doc = e.open(&input, &c, &view()).unwrap();
    assert_eq!(doc.layers, c.layers);
    assert_eq!(
        &doc.bytes[..],
        token_text("rfc7515-a3-jws-es256.txt").as_bytes()
    );
    assert_eq!(doc.kind, Kind::Jwt);
    assert!(doc.signed);
    assert!(!doc.signature_stale);
}

#[test]
fn cose_tags_stay_in_bytes_and_out_of_layers() {
    let e = engine();
    for name in [CWT_TAGGED, CWT_TAG61, CWT_UNTAGGED] {
        let input = token(name);
        let c = top(&e, &input);
        let doc = e.open(&input, &c, &view()).unwrap();
        assert_eq!(&doc.bytes[..], &input[..], "{name}");
        assert!(
            !doc.layers
                .iter()
                .any(|l| matches!(l, Layer::CborTag { .. })),
            "{name}: {:?}",
            doc.layers
        );
    }
}

#[test]
fn detect_reports_cose_tags_as_layers() {
    let e = engine();
    let c = top(&e, &token(CWT_TAGGED));
    assert_eq!(c.layers, [Layer::CborTag { tag: 18 }]);
    let c = top(&e, &token(CWT_TAG61));
    assert_eq!(
        c.layers,
        [Layer::CborTag { tag: 61 }, Layer::CborTag { tag: 18 }]
    );
}

#[test]
fn hex_text_unwraps_to_the_binary_token() {
    let e = engine();
    let input = token("rfc8392-a3-signed-cwt.hex");
    let c = top(&e, &input);
    assert_eq!(c.kind, Kind::Cwt);
    assert!(c.layers.iter().any(|l| matches!(l, Layer::Hex { .. })));
    assert!(
        c.breadcrumb
            .iter()
            .any(|b| b.to_lowercase().contains("hex"))
    );
    let doc = e.open(&input, &c, &view()).unwrap();
    assert_eq!(&doc.bytes[..], &token(CWT_TAGGED)[..]);
    assert!(doc.layers.iter().any(|l| matches!(l, Layer::Hex { .. })));
}

#[test]
fn base64url_cwt_unwraps() {
    let e = engine();
    let input = Base64UrlUnpadded::encode_string(&token(CWT_TAGGED));
    let doc = open(&e, input.as_bytes());
    assert_eq!(doc.kind, Kind::Cwt);
    assert_eq!(&doc.bytes[..], &token(CWT_TAGGED)[..]);
    assert!(matches!(doc.layers.first(), Some(Layer::Base64Url { .. })));
}

#[test]
fn authorization_header_is_peeled() {
    let e = engine();
    let jws = token_text("rfc7515-a3-jws-es256.txt");
    let input = format!("Authorization: Bearer {jws}");
    let doc = open(&e, input.as_bytes());
    assert_eq!(doc.kind, Kind::Jwt);
    assert_eq!(&doc.bytes[..], jws.as_bytes());
    assert!(matches!(
        &doc.layers[..2],
        [
            Layer::AuthorizationHeader { .. },
            Layer::BearerPrefix { .. }
        ]
    ));
}

#[test]
fn json_container_field_is_a_candidate() {
    let e = engine();
    let sd = token_text("rfc9901-s5.1-sd-jwt.txt");
    let input = format!(r#"{{"credential": "{sd}", "state": "xyz"}}"#);
    let cands = e.detect(input.as_bytes());
    let c = cands
        .iter()
        .find(|c| c.kind == Kind::SdJwt { kb: false })
        .expect("the SD-JWT field");
    assert_eq!(
        c.layers.first(),
        Some(&Layer::JsonField {
            path: vec![JsonPathSegment::Key("credential".into())]
        })
    );
    let doc = e.open(input.as_bytes(), c, &view()).unwrap();
    assert_eq!(&doc.bytes[..], sd.as_bytes());
    // The response itself is still offered as a claim set.
    assert!(cands.iter().any(|c| c.kind == Kind::JsonClaims));
}

#[test]
fn edn_candidates_are_confirmed_by_parsing() {
    let e = engine();
    let fig4 = token("sd-cwt-08-fig4-claims.edn");
    let c = top(&e, &fig4);
    assert_eq!(c.kind, Kind::EdnClaims);
    let doc = e.open(&fig4, &c, &view()).unwrap();
    assert_eq!(doc.kind, Kind::EdnClaims);
    assert!(!doc.signed);
    // The EDN text is the document; its comments are kept in the main pane.
    assert_eq!(&doc.bytes[..], &fig4[..]);
    assert!(doc.main.text.contains("/ iss /"));
}

#[test]
fn edn_lookalikes_that_do_not_parse_are_dropped() {
    let e = engine();
    for text in ["{1: zzz}", "[nope]", "{1 2}", "<<1, >>>", "12(zzz)"] {
        let cands = e.detect(text.as_bytes());
        assert!(
            !cands.iter().any(|c| c.kind == Kind::EdnClaims),
            "{text}: {cands:?}"
        );
    }
}

#[test]
fn simple_edn_maps_are_claim_sets() {
    let e = engine();
    for text in [
        r#"{1: "https://issuer.example", 2: "x"}"#,
        "{ / iss / 1: \"a\", 4: 1725330600 }",
        "{1: h'00', 58(500): true}",
    ] {
        let cands = e.detect(text.as_bytes());
        assert!(
            cands.iter().any(|c| c.kind == Kind::EdnClaims),
            "{text}: {cands:?}"
        );
    }
}

#[test]
fn edn_claims_are_never_reported_unconfirmed() {
    // The detect-level `EdnText` kind does not exist in core's `Kind`: every
    // EDN candidate core returns has parsed.
    let e = engine();
    for text in ["{1: 1}", "{1: zzz}", "[1, 2, 3]", "{_ 1: 2}"] {
        for c in e.detect(text.as_bytes()) {
            if c.kind == Kind::EdnClaims {
                tokenator_edn::parse(text).expect("confirmed EDN parses");
            }
        }
    }
}

#[test]
fn detect_is_deterministic_and_empty_on_nothing() {
    let e = engine();
    assert!(e.detect(b"").is_empty());
    assert!(e.detect(b"   \n").is_empty());
    for name in JOSE_FIXTURES.iter().chain(COSE_FIXTURES.iter()) {
        let a = e.detect(&token(name));
        let b = e.detect(&token(name));
        assert_eq!(json(&a), json(&b), "{name}");
        assert!(!a.is_empty(), "{name}");
        assert!(
            a.windows(2).all(|w| w[0].confidence >= w[1].confidence),
            "{name}: not sorted"
        );
    }
}
