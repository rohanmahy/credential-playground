//! `rewrap`, `unwrap_layers`, and `json_pointer`; rewrap is the inverse of
//! unwrapping for canonical inputs.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_detect::{Layer, PathSegment, UnwrapError, json_pointer, rewrap, unwrap_layers};

fn s(b: Vec<u8>) -> String {
    String::from_utf8(b).unwrap()
}

// ------------------------------------------------------------------ rewrap, one layer at a time

#[test]
fn no_layers_is_identity() {
    assert_eq!(rewrap(b"abc", &[]), b"abc");
    assert_eq!(unwrap_layers(b"abc", &[]).unwrap(), b"abc");
}

#[test]
fn rewrap_trim() {
    assert_eq!(s(rewrap(b"x", &[trim(" \t", "\r\n")])), " \tx\r\n");
}

#[test]
fn rewrap_quotes() {
    for q in ['"', '\'', '`'] {
        assert_eq!(
            s(rewrap(b"x", &[Layer::Quotes { quote: q }])),
            format!("{q}x{q}")
        );
    }
}

#[test]
fn rewrap_authorization_and_bearer() {
    let layers = [
        Layer::AuthorizationHeader {
            prefix: "authorization:  ".into(),
        },
        Layer::BearerPrefix {
            prefix: "bearer ".into(),
        },
    ];
    assert_eq!(s(rewrap(b"tok", &layers)), "authorization:  bearer tok");
}

#[test]
fn rewrap_url_encoded() {
    assert_eq!(
        s(rewrap(b"a+b/c=d~e.f-g_h %\"{}", &[Layer::UrlEncoded])),
        "a%2Bb%2Fc%3Dd~e.f-g_h%20%25%22%7B%7D"
    );
    assert_eq!(s(rewrap(&[0x00, 0xff], &[Layer::UrlEncoded])), "%00%FF");
}

#[test]
fn rewrap_json_field_object_path() {
    let l = field(&["credential"]);
    assert_eq!(s(rewrap(b"abc", &[l])), r#"{"credential":"abc"}"#);
    let l = field(&["vp_token", "pid"]);
    assert_eq!(s(rewrap(b"abc", &[l])), r#"{"vp_token":{"pid":"abc"}}"#);
}

#[test]
fn rewrap_json_field_array_path() {
    let l = Layer::JsonField {
        path: vec![PathSegment::Key("vp".into()), PathSegment::Index(1)],
    };
    assert_eq!(s(rewrap(b"abc", &[l])), r#"{"vp":[null,"abc"]}"#);
    let l = Layer::JsonField {
        path: vec![PathSegment::Index(0)],
    };
    assert_eq!(s(rewrap(b"abc", &[l])), r#"["abc"]"#);
}

#[test]
fn rewrap_json_field_escapes_key_and_value() {
    let l = field(&["a\"b\\c"]);
    assert_eq!(
        s(rewrap(b"x\"y\\z\n\x01", &[l])),
        r#"{"a\"b\\c":"x\"y\\z\n\u0001"}"#
    );
}

#[test]
fn rewrap_json_field_keeps_slash_and_non_ascii_unescaped() {
    let l = field(&["k"]);
    assert_eq!(s(rewrap("a/b+é".as_bytes(), &[l])), "{\"k\":\"a/b+é\"}");
}

#[test]
fn rewrap_base64() {
    assert_eq!(
        s(rewrap(
            b"abcd",
            &[Layer::Base64Url {
                padded: false,
                wrap: None
            }]
        )),
        "YWJjZA"
    );
    assert_eq!(
        s(rewrap(
            b"abcd",
            &[Layer::Base64Url {
                padded: true,
                wrap: None
            }]
        )),
        "YWJjZA=="
    );
    assert_eq!(
        s(rewrap(
            b"abcd",
            &[Layer::Base64Std {
                padded: true,
                wrap: None
            }]
        )),
        "YWJjZA=="
    );
    assert_eq!(
        s(rewrap(
            b"abcd",
            &[Layer::Base64Std {
                padded: false,
                wrap: None
            }]
        )),
        "YWJjZA"
    );
    let fb = [0xfb, 0xff, 0xbf];
    assert_eq!(
        s(rewrap(
            &fb,
            &[Layer::Base64Std {
                padded: true,
                wrap: None
            }]
        )),
        "+/+/"
    );
    assert_eq!(
        s(rewrap(
            &fb,
            &[Layer::Base64Url {
                padded: false,
                wrap: None
            }]
        )),
        "-_-_"
    );
    assert_eq!(
        s(rewrap(
            b"",
            &[Layer::Base64Std {
                padded: true,
                wrap: None
            }]
        )),
        ""
    );
}

#[test]
fn rewrap_base64_wrapped() {
    let data: Vec<u8> = (0u8..100).collect();
    let flat = b64std(&data);
    let out = s(rewrap(
        &data,
        &[Layer::Base64Std {
            padded: true,
            wrap: Some(64),
        }],
    ));
    assert_eq!(out, wrap(&flat, 64));
    assert!(!out.ends_with('\n'));
    let out = s(rewrap(
        &data,
        &[Layer::Base64Url {
            padded: false,
            wrap: Some(20),
        }],
    ));
    assert_eq!(out, wrap(&b64url(&data), 20));
}

#[test]
fn rewrap_hex() {
    let d = [0xa1, 0x01, 0x26];
    let hexl = |upper, separator, wrap| {
        [Layer::Hex {
            upper,
            separator,
            wrap,
        }]
    };
    assert_eq!(s(rewrap(&d, &hexl(false, None, None))), "a10126");
    assert_eq!(s(rewrap(&d, &hexl(true, None, None))), "A10126");
    assert_eq!(s(rewrap(&d, &hexl(true, Some(':'), None))), "A1:01:26");
    assert_eq!(s(rewrap(&d, &hexl(false, Some(' '), None))), "a1 01 26");
    assert_eq!(s(rewrap(&d, &hexl(false, Some(' '), Some(2)))), "a1 01\n26");
    assert_eq!(s(rewrap(&d, &hexl(false, None, Some(1)))), "a1\n01\n26");
}

#[test]
fn rewrap_cbor_tags_use_preferred_heads() {
    let inner = [0x80]; // []
    assert_eq!(rewrap(&inner, &[Layer::CborTag(18)]), h("d2 80"));
    assert_eq!(rewrap(&inner, &[Layer::CborTag(23)]), h("d7 80"));
    assert_eq!(rewrap(&inner, &[Layer::CborTag(24)]), h("d8 18 80"));
    assert_eq!(rewrap(&inner, &[Layer::CborTag(61)]), h("d8 3d 80"));
    assert_eq!(rewrap(&inner, &[Layer::CborTag(1004)]), h("d9 03 ec 80"));
    assert_eq!(rewrap(&inner, &[Layer::CborTag(55799)]), h("d9 d9 f7 80"));
    assert_eq!(
        rewrap(&inner, &[Layer::CborTag(65536)]),
        h("da 00 01 00 00 80")
    );
    assert_eq!(
        rewrap(&inner, &[Layer::CborTag(1 << 32)]),
        h("db 00 00 00 01 00 00 00 00 80")
    );
    assert_eq!(
        rewrap(&inner, &[Layer::CborTag(61), Layer::CborTag(18)]),
        h("d8 3d d2 80")
    );
}

#[test]
fn rewrap_applies_innermost_layer_first() {
    let layers = [
        Layer::BearerPrefix {
            prefix: "Bearer ".into(),
        },
        Layer::Base64Url {
            padded: false,
            wrap: None,
        },
        Layer::CborTag(18),
    ];
    // 18([]) = d2 80, base64url "0oA"
    assert_eq!(s(rewrap(&[0x80], &layers)), "Bearer 0oA");
}

#[test]
fn rewrap_full_stack() {
    let untagged = cwt_untagged();
    let layers = [
        trim("", "\n"),
        Layer::AuthorizationHeader {
            prefix: "Authorization: ".into(),
        },
        Layer::BearerPrefix {
            prefix: "Bearer ".into(),
        },
        Layer::Base64Url {
            padded: false,
            wrap: None,
        },
        Layer::CborTag(61),
        Layer::CborTag(18),
    ];
    let expected = format!(
        "Authorization: Bearer {}\n",
        b64url(&token("derived-rfc8392-a3-tag61.cbor"))
    );
    assert_eq!(s(rewrap(&untagged, &layers)), expected);
    assert_eq!(
        unwrap_layers(expected.as_bytes(), &layers).unwrap(),
        untagged
    );
}

// ------------------------------------------------------------------ unwrap_layers

#[test]
fn unwrap_each_layer() {
    let cases: Vec<(Vec<u8>, Vec<Layer>, Vec<u8>)> = vec![
        (b"  x\n".to_vec(), vec![trim("  ", "\n")], b"x".to_vec()),
        (
            b"'x'".to_vec(),
            vec![Layer::Quotes { quote: '\'' }],
            b"x".to_vec(),
        ),
        (
            b"Bearer x".to_vec(),
            vec![Layer::BearerPrefix {
                prefix: "Bearer ".into(),
            }],
            b"x".to_vec(),
        ),
        (
            b"Authorization: x".to_vec(),
            vec![Layer::AuthorizationHeader {
                prefix: "Authorization: ".into(),
            }],
            b"x".to_vec(),
        ),
        (
            b"a%2Bb%7e".to_vec(),
            vec![Layer::UrlEncoded],
            b"a+b~".to_vec(),
        ),
        (
            br#"{"a":{"b":"x"}}"#.to_vec(),
            vec![field(&["a", "b"])],
            b"x".to_vec(),
        ),
        (
            br#"{"a":["y","x\/A"]}"#.to_vec(),
            vec![Layer::JsonField {
                path: vec![PathSegment::Key("a".into()), PathSegment::Index(1)],
            }],
            b"x/A".to_vec(),
        ),
        (
            b"YWJjZA".to_vec(),
            vec![Layer::Base64Url {
                padded: false,
                wrap: None,
            }],
            b"abcd".to_vec(),
        ),
        (
            b"YWJj\nZA==".to_vec(),
            vec![Layer::Base64Std {
                padded: true,
                wrap: Some(4),
            }],
            b"abcd".to_vec(),
        ),
        (
            b"A1:01:26".to_vec(),
            vec![Layer::Hex {
                upper: true,
                separator: Some(':'),
                wrap: None,
            }],
            h("a10126"),
        ),
        (
            h("d8 3d d2 80"),
            vec![Layer::CborTag(61), Layer::CborTag(18)],
            h("80"),
        ),
    ];
    for (input, layers, expected) in cases {
        assert_eq!(
            unwrap_layers(&input, &layers).unwrap(),
            expected,
            "{:?} {layers:?}",
            String::from_utf8_lossy(&input)
        );
    }
}

#[test]
fn unwrap_errors_name_the_failing_layer() {
    let cases: Vec<(Vec<u8>, Vec<Layer>, usize)> = vec![
        (
            b"not base64!".to_vec(),
            vec![Layer::Base64Url {
                padded: false,
                wrap: None,
            }],
            0,
        ),
        (
            b"abc".to_vec(),
            vec![Layer::Hex {
                upper: false,
                separator: None,
                wrap: None,
            }],
            0,
        ),
        (
            b"zz".to_vec(),
            vec![Layer::Hex {
                upper: false,
                separator: None,
                wrap: None,
            }],
            0,
        ),
        (h("d2 80"), vec![Layer::CborTag(61)], 0),
        (
            h("d8 3d 80"),
            vec![Layer::CborTag(61), Layer::CborTag(18)],
            1,
        ),
        (h("80"), vec![Layer::CborTag(18)], 0),
        (br#"{"a":"x"}"#.to_vec(), vec![field(&["b"])], 0),
        (br#"{"a":1}"#.to_vec(), vec![field(&["a"])], 0),
        (b"not json".to_vec(), vec![field(&["a"])], 0),
        (b"x".to_vec(), vec![Layer::Quotes { quote: '"' }], 0),
        (
            b"Basic x".to_vec(),
            vec![Layer::BearerPrefix {
                prefix: "Bearer ".into(),
            }],
            0,
        ),
        (
            b"Bearer x".to_vec(),
            vec![
                Layer::BearerPrefix {
                    prefix: "Bearer ".into(),
                },
                Layer::Hex {
                    upper: false,
                    separator: None,
                    wrap: None,
                },
            ],
            1,
        ),
        (b"%zz".to_vec(), vec![Layer::UrlEncoded], 0),
    ];
    for (input, layers, idx) in cases {
        let err = unwrap_layers(&input, &layers).unwrap_err();
        assert_eq!(
            err.layer,
            idx,
            "{:?} {layers:?}: {err}",
            String::from_utf8_lossy(&input)
        );
        assert!(!err.reason.is_empty());
    }
}

#[test]
fn unwrap_error_display() {
    let e = UnwrapError {
        layer: 2,
        reason: "not base64",
    };
    assert_eq!(e.to_string(), "cannot unwrap layer 2: not base64");
}

#[test]
fn unwrap_cbor_tag_returns_the_inner_item_bytes_exactly() {
    let input = token(CWT_TAG18);
    assert_eq!(
        unwrap_layers(&input, &[Layer::CborTag(18)]).unwrap(),
        &input[1..]
    );
}

#[test]
fn unwrap_cbor_tag_with_trailing_bytes_fails() {
    let mut input = token(CWT_TAG18);
    input.push(0x00);
    assert!(unwrap_layers(&input, &[Layer::CborTag(18)]).is_err());
}

// ------------------------------------------------------------------ json_pointer

#[test]
fn json_pointer_rfc6901() {
    assert_eq!(json_pointer(&[]), "");
    assert_eq!(
        json_pointer(&[PathSegment::Key("credential".into())]),
        "/credential"
    );
    assert_eq!(
        json_pointer(&[PathSegment::Key("vp_token".into()), PathSegment::Index(0)]),
        "/vp_token/0"
    );
    assert_eq!(
        json_pointer(&[PathSegment::Key("a/b~c".into())]),
        "/a~1b~0c"
    );
    assert_eq!(json_pointer(&[PathSegment::Key(String::new())]), "/");
}

// ------------------------------------------------------------------ round trip

/// Canonical inputs: `rewrap(unwrap_layers(x)) == x` for the top candidate.
fn canonical_inputs() -> Vec<(&'static str, Vec<u8>)> {
    let jwt = token_text(JWT);
    let sd = token_text(SD_JWT);
    let kb = token_text(SD_JWT_KB);
    let cwt = token(CWT_TAG18);
    let cwt61 = token("derived-rfc8392-a3-tag61.cbor");
    let kbt = token(SD_KBT);
    let ck = key("rfc8392-a2.3-ec-p256.cosekey.cbor");
    vec![
        ("jwt", jwt.clone().into_bytes()),
        ("jwt file", token(JWT)),
        ("sd-jwt file", token(SD_JWT)),
        ("sd-jwt+kb file", token(SD_JWT_KB)),
        ("trimmed", format!(" \t{jwt}\r\n").into_bytes()),
        ("quoted", format!("\"{jwt}\"").into_bytes()),
        ("bearer", format!("Bearer {kb}").into_bytes()),
        (
            "auth bearer",
            format!("Authorization: Bearer {jwt}").into_bytes(),
        ),
        (
            "auth bearer b64 cwt",
            format!("Authorization: Bearer {}", b64url(&cwt61)).into_bytes(),
        ),
        (
            "json field",
            format!(r#"{{"credential":"{sd}"}}"#).into_bytes(),
        ),
        (
            "nested json field",
            format!(r#"{{"vp_token":{{"pid":"{kb}"}}}}"#).into_bytes(),
        ),
        (
            "json array field",
            format!(r#"{{"vp":[null,"{jwt}"]}}"#).into_bytes(),
        ),
        (
            "url-encoded b64 cwt",
            pct(b64std(&cwt).as_bytes()).into_bytes(),
        ),
        (
            "url-encoded json",
            pct(format!(r#"{{"credential":"{sd}"}}"#).as_bytes()).into_bytes(),
        ),
        ("b64url cwt", b64url(&cwt).into_bytes()),
        ("b64url padded cwt", b64url_pad(&cwt).into_bytes()),
        ("b64std cwt", b64std(&cwt).into_bytes()),
        ("b64std nopad cwt", b64std_nopad(&cwt).into_bytes()),
        (
            "b64std wrapped 64 kbt",
            wrap(&b64std(&kbt), 64).into_bytes(),
        ),
        (
            "b64std wrapped 76 kbt",
            wrap(&b64std(&kbt), 76).into_bytes(),
        ),
        ("hex", hex(&cwt).into_bytes()),
        ("HEX", hex_upper(&cwt).into_bytes()),
        (
            "hex colons",
            hex_layout(&cwt, true, Some(':'), None).into_bytes(),
        ),
        (
            "hex spaces wrapped",
            hex_layout(&cwt, false, Some(' '), Some(16)).into_bytes(),
        ),
        (
            "hex wrapped",
            hex_layout(&cwt, false, None, Some(32)).into_bytes(),
        ),
        ("hex cose key", hex(&ck).into_bytes()),
        ("binary tag18", cwt.clone()),
        ("binary tag61", cwt61.clone()),
        ("binary untagged", cwt_untagged()),
        ("binary sd-kbt", kbt.clone()),
        ("binary cose key", ck),
        (
            "json field b64 cwt",
            format!(r#"{{"cwt":"{}"}}"#, b64url(&cwt61)).into_bytes(),
        ),
        ("pem", key("sd-cwt-08-c1-holder-public.pem")),
        ("jwk", key("rfc9901-a5-ec-p256-public.jwk.json")),
    ]
}

#[test]
fn rewrap_inverts_unwrap_for_canonical_inputs() {
    for (name, input) in canonical_inputs() {
        let c = top(&input);
        let payload = unwrap_layers(&input, &c.layers).unwrap();
        assert_eq!(
            rewrap(&payload, &c.layers),
            input,
            "{name}: layers {:?}",
            c.layers
        );
    }
}

#[test]
fn rewrap_inverts_unwrap_for_every_candidate_of_simple_inputs() {
    // Inputs where every reading covers the whole input.
    for input in [
        token(SD_KBT),
        b64url(&token(CWT_TAG18)).into_bytes(),
        format!("Bearer {}", token_text(SD_JWT_KB)).into_bytes(),
    ] {
        for c in run(&input) {
            let payload = unwrap_layers(&input, &c.layers).unwrap();
            assert_eq!(rewrap(&payload, &c.layers), input, "{c:?}");
        }
    }
}

#[test]
fn reencode_by_swapping_layers() {
    // Re-encode use case: take the payload and wrap it differently.
    let input = b64url(&token("derived-rfc8392-a3-tag61.cbor"));
    let c = top(input.as_bytes());
    let payload = unwrap_layers(input.as_bytes(), &c.layers).unwrap();
    let as_hex = rewrap(
        &payload,
        &[
            Layer::Hex {
                upper: false,
                separator: None,
                wrap: None,
            },
            Layer::CborTag(18),
        ],
    );
    assert_eq!(s(as_hex), hex(&token(CWT_TAG18)));
    assert_eq!(rewrap(&payload, &[]), cwt_untagged());
}
