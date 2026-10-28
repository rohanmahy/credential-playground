//! Every unwrapping layer, alone and combined, with exact layer lists and
//! payload ranges.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_detect::{Kind, Layer, PathSegment};

fn jwt() -> String {
    token_text(JWT)
}

fn sd_jwt_kb() -> String {
    token_text(SD_JWT_KB)
}

const B64URL: Layer = Layer::Base64Url {
    padded: false,
    wrap: None,
};
const B64URL_PAD: Layer = Layer::Base64Url {
    padded: true,
    wrap: None,
};
const B64STD: Layer = Layer::Base64Std {
    padded: true,
    wrap: None,
};
const B64STD_NOPAD: Layer = Layer::Base64Std {
    padded: false,
    wrap: None,
};
const HEX: Layer = Layer::Hex {
    upper: false,
    separator: None,
    wrap: None,
};

fn quotes(q: char) -> Layer {
    Layer::Quotes { quote: q }
}

fn bearer(p: &str) -> Layer {
    Layer::BearerPrefix {
        prefix: p.to_owned(),
    }
}

fn auth(p: &str) -> Layer {
    Layer::AuthorizationHeader {
        prefix: p.to_owned(),
    }
}

fn path(segs: Vec<PathSegment>) -> Layer {
    Layer::JsonField { path: segs }
}

fn seg(k: &str) -> PathSegment {
    PathSegment::Key(k.to_owned())
}

fn assert_top(input: &[u8], kind: Kind, layers: &[Layer], range: std::ops::Range<usize>) {
    let cands = run(input);
    assert!(!cands.is_empty(), "no candidates");
    let c = &cands[0];
    assert_eq!(c.kind, kind, "{}", summary(&cands));
    assert_eq!(c.layers, layers, "{}", summary(&cands));
    assert_eq!(c.payload_range, range, "{}", summary(&cands));
}

// ------------------------------------------------------------------ text cleanup

#[test]
fn trim_whitespace() {
    let t = jwt();
    let input = format!(" \t\r\n{t}\r\n ");
    assert_top(
        input.as_bytes(),
        Kind::Jwt,
        &[trim(" \t\r\n", "\r\n ")],
        4..4 + t.len(),
    );
}

#[test]
fn exact_token_has_no_layers() {
    let t = jwt();
    assert_top(t.as_bytes(), Kind::Jwt, &[], 0..t.len());
}

#[test]
fn quotes_double_single_backtick() {
    let t = jwt();
    for q in ['"', '\'', '`'] {
        let input = format!("{q}{t}{q}");
        assert_top(input.as_bytes(), Kind::Jwt, &[quotes(q)], 1..1 + t.len());
    }
}

#[test]
fn mismatched_quotes_are_not_stripped() {
    let t = jwt();
    let input = format!("\"{t}'");
    let cands = run(input.as_bytes());
    assert!(
        !cands
            .iter()
            .any(|c| c.layers.contains(&quotes('"')) || c.layers.contains(&quotes('\''))),
        "{}",
        summary(&cands)
    );
}

#[test]
fn trim_then_quotes() {
    let t = jwt();
    let input = format!("  '{t}' \n");
    assert_top(
        input.as_bytes(),
        Kind::Jwt,
        &[trim("  ", " \n"), quotes('\'')],
        3..3 + t.len(),
    );
}

#[test]
fn bearer_prefix() {
    let t = jwt();
    let input = format!("Bearer {t}");
    assert_top(
        input.as_bytes(),
        Kind::Jwt,
        &[bearer("Bearer ")],
        7..input.len(),
    );
}

#[test]
fn bearer_prefix_is_case_insensitive_and_kept_verbatim() {
    let t = jwt();
    for p in ["bearer ", "BEARER ", "Bearer  ", "bEaReR\t"] {
        let input = format!("{p}{t}");
        assert_top(
            input.as_bytes(),
            Kind::Jwt,
            &[bearer(p)],
            p.len()..input.len(),
        );
    }
}

#[test]
fn bearer_without_separator_is_not_a_prefix() {
    let t = jwt();
    let input = format!("Bearer{t}");
    let cands = run(input.as_bytes());
    assert!(
        !cands.iter().any(|c| c
            .layers
            .iter()
            .any(|l| matches!(l, Layer::BearerPrefix { .. }))),
        "{}",
        summary(&cands)
    );
}

#[test]
fn authorization_header_with_bearer() {
    let t = jwt();
    let input = format!("Authorization: Bearer {t}");
    assert_top(
        input.as_bytes(),
        Kind::Jwt,
        &[auth("Authorization: "), bearer("Bearer ")],
        22..input.len(),
    );
}

#[test]
fn authorization_header_variants() {
    let t = jwt();
    for (h, b) in [
        ("authorization: ", "bearer "),
        ("AUTHORIZATION:", "Bearer "),
        ("Authorization:   ", "Bearer "),
    ] {
        let input = format!("{h}{b}{t}");
        assert_top(
            input.as_bytes(),
            Kind::Jwt,
            &[auth(h), bearer(b)],
            h.len() + b.len()..input.len(),
        );
    }
}

#[test]
fn authorization_header_without_scheme() {
    let t = jwt();
    let input = format!("Authorization: {t}");
    assert_top(
        input.as_bytes(),
        Kind::Jwt,
        &[auth("Authorization: ")],
        15..input.len(),
    );
}

#[test]
fn authorization_header_with_crlf() {
    let t = jwt();
    let input = format!("Authorization: Bearer {t}\r\n");
    assert_top(
        input.as_bytes(),
        Kind::Jwt,
        &[trim("", "\r\n"), auth("Authorization: "), bearer("Bearer ")],
        22..22 + t.len(),
    );
}

#[test]
fn authorization_bearer_sd_jwt_kb() {
    let t = sd_jwt_kb();
    let input = format!("Authorization: Bearer {t}");
    assert_top(
        input.as_bytes(),
        Kind::SdJwt { kb: true },
        &[auth("Authorization: "), bearer("Bearer ")],
        22..input.len(),
    );
}

// ------------------------------------------------------------------ URL encoding

#[test]
fn url_encoded_base64_cwt() {
    let raw = token(CWT_TAG18);
    let input = pct(b64std(&raw).as_bytes());
    assert!(input.contains('%'));
    assert_top(
        input.as_bytes(),
        Kind::Cwt,
        &[Layer::UrlEncoded, B64STD, Layer::CborTag(18)],
        0..input.len(),
    );
}

#[test]
fn url_encoded_sd_jwt_with_escaped_tildes() {
    let t = sd_jwt_kb();
    let input = t.replace('~', "%7E");
    assert_top(
        input.as_bytes(),
        Kind::SdJwt { kb: true },
        &[Layer::UrlEncoded],
        0..input.len(),
    );
}

#[test]
fn fully_percent_encoded_jwt() {
    let t = jwt();
    let input = pct_all(t.as_bytes());
    assert_top(
        input.as_bytes(),
        Kind::Jwt,
        &[Layer::UrlEncoded],
        0..input.len(),
    );
}

#[test]
fn lower_case_percent_escapes_are_decoded() {
    let t = sd_jwt_kb();
    let input = t.replace('~', "%7e");
    let c = top(input.as_bytes());
    assert_eq!(c.kind, Kind::SdJwt { kb: true });
    assert_eq!(c.layers, vec![Layer::UrlEncoded]);
}

#[test]
fn url_encoded_json_container() {
    let t = token_text(SD_JWT);
    let input = pct(format!(r#"{{"credential":"{t}"}}"#).as_bytes());
    assert_top(
        input.as_bytes(),
        Kind::SdJwt { kb: false },
        &[Layer::UrlEncoded, field(&["credential"])],
        0..input.len(),
    );
}

#[test]
fn plus_is_not_a_space() {
    // A base64std CWT with '+' and no %XX is plain base64, not URL-encoded.
    let raw = token(CWT_TAG18);
    let input = b64std(&raw);
    assert!(input.contains('+'));
    assert_top(
        input.as_bytes(),
        Kind::Cwt,
        &[B64STD, Layer::CborTag(18)],
        0..input.len(),
    );
}

#[test]
fn invalid_percent_escape_is_not_url_encoded() {
    let t = jwt();
    let input = format!("{t}%G1");
    let cands = run(input.as_bytes());
    assert!(
        !cands.iter().any(|c| c.layers.contains(&Layer::UrlEncoded)),
        "{}",
        summary(&cands)
    );
}

// ------------------------------------------------------------------ JSON containers

#[test]
fn json_field_holding_sd_jwt() {
    let t = token_text(SD_JWT);
    let input = format!(r#"{{"credential":"{t}"}}"#);
    let r = range_of(input.as_bytes(), t.as_bytes());
    assert_top(
        input.as_bytes(),
        Kind::SdJwt { kb: false },
        &[field(&["credential"])],
        r,
    );
}

#[test]
fn json_field_in_pretty_printed_document() {
    let t = jwt();
    let input = format!("{{\n  \"format\": \"jwt\",\n  \"credential\": \"{t}\"\n}}\n");
    let r = range_of(input.as_bytes(), t.as_bytes());
    assert_top(
        input.as_bytes(),
        Kind::Jwt,
        &[trim("", "\n"), field(&["credential"])],
        r,
    );
}

#[test]
fn nested_json_field() {
    let t = sd_jwt_kb();
    let input = format!(r#"{{"vp_token":{{"pid":"{t}"}}}}"#);
    let r = range_of(input.as_bytes(), t.as_bytes());
    assert_top(
        input.as_bytes(),
        Kind::SdJwt { kb: true },
        &[field(&["vp_token", "pid"])],
        r,
    );
}

#[test]
fn json_array_elements_each_yield_a_candidate() {
    let a = jwt();
    let b = sd_jwt_kb();
    let input = format!(r#"{{"vp_token":["{a}","{b}"]}}"#);
    let cands = run(input.as_bytes());
    let ca = find_with(
        &cands,
        &Kind::Jwt,
        &[path(vec![seg("vp_token"), PathSegment::Index(0)])],
    )
    .unwrap_or_else(|| panic!("{}", summary(&cands)));
    assert_eq!(ca.payload_range, range_of(input.as_bytes(), a.as_bytes()));
    let cb = find_with(
        &cands,
        &Kind::SdJwt { kb: true },
        &[path(vec![seg("vp_token"), PathSegment::Index(1)])],
    )
    .unwrap_or_else(|| panic!("{}", summary(&cands)));
    assert_eq!(cb.payload_range, range_of(input.as_bytes(), b.as_bytes()));
}

#[test]
fn top_level_json_array_of_tokens() {
    let t = jwt();
    let input = format!(r#"["{t}"]"#);
    assert_top(
        input.as_bytes(),
        Kind::Jwt,
        &[path(vec![PathSegment::Index(0)])],
        2..2 + t.len(),
    );
}

#[test]
fn several_token_fields_yield_one_candidate_each() {
    let id = jwt();
    let access = token_text("rfc7515-a3-jws-es256.txt");
    let input = format!(r#"{{"id_token":"{id}","access_token":"{access}","state":"xyz"}}"#);
    let cands = run(input.as_bytes());
    let fields: Vec<_> = cands
        .iter()
        .filter(|c| c.kind == Kind::Jwt)
        .map(|c| c.layers.clone())
        .collect();
    assert!(
        fields.contains(&vec![field(&["id_token"])]),
        "{}",
        summary(&cands)
    );
    assert!(
        fields.contains(&vec![field(&["access_token"])]),
        "{}",
        summary(&cands)
    );
    assert!(
        !cands.iter().any(|c| c.layers.contains(&field(&["state"]))),
        "{}",
        summary(&cands)
    );
}

#[test]
fn json_field_key_needing_pointer_escapes() {
    let t = jwt();
    let input = format!(r#"{{"a/b~c":"{t}"}}"#);
    assert_top(
        input.as_bytes(),
        Kind::Jwt,
        &[field(&["a/b~c"])],
        range_of(input.as_bytes(), t.as_bytes()),
    );
}

#[test]
fn json_field_with_escaped_slashes_still_detected() {
    // Some serializers escape '/' as "\/" (base64std tokens contain '/').
    let raw = token(CWT_TAG18);
    let b = b64std(&raw);
    assert!(b.contains('/'));
    let input = format!(r#"{{"cwt":"{}"}}"#, b.replace('/', "\\/"));
    let c = top(input.as_bytes());
    assert_eq!(c.kind, Kind::Cwt);
    assert_eq!(c.layers, vec![field(&["cwt"]), B64STD, Layer::CborTag(18)]);
}

#[test]
fn json_field_holding_base64url_of_tagged_cwt() {
    let raw = token("derived-rfc8392-a3-tag61.cbor");
    let b = b64url(&raw);
    let input = format!(r#"{{"cwt":"{b}"}}"#);
    assert_top(
        input.as_bytes(),
        Kind::Cwt,
        &[
            field(&["cwt"]),
            B64URL,
            Layer::CborTag(61),
            Layer::CborTag(18),
        ],
        range_of(input.as_bytes(), b.as_bytes()),
    );
}

#[test]
fn json_field_holding_hex_sd_cwt() {
    let raw = token(SD_CWT);
    let x = hex(&raw);
    let input = format!(r#"{{"sd_cwt":"{x}"}}"#);
    assert_top(
        input.as_bytes(),
        Kind::SdCwt,
        &[field(&["sd_cwt"]), HEX, Layer::CborTag(18)],
        range_of(input.as_bytes(), x.as_bytes()),
    );
}

#[test]
fn json_string_fields_that_are_not_tokens_yield_nothing() {
    let input = br#"{"name":"Alice","greeting":"hello world","n":"12"}"#;
    let cands = run(input);
    assert!(
        cands.iter().all(|c| c.layers.is_empty()),
        "only the container itself: {}",
        summary(&cands)
    );
}

// ------------------------------------------------------------------ base64

#[test]
fn base64url_unpadded_cwt() {
    let raw = token(CWT_TAG18);
    let input = b64url(&raw);
    assert!(input.contains(['-', '_']));
    assert_top(
        input.as_bytes(),
        Kind::Cwt,
        &[B64URL, Layer::CborTag(18)],
        0..input.len(),
    );
}

#[test]
fn base64url_padded_cwt() {
    let raw = token(CWT_TAG18);
    let input = b64url_pad(&raw);
    assert!(input.ends_with('='));
    assert_top(
        input.as_bytes(),
        Kind::Cwt,
        &[B64URL_PAD, Layer::CborTag(18)],
        0..input.len(),
    );
}

#[test]
fn base64std_padded_and_unpadded_cwt() {
    let raw = token(CWT_TAG18);
    let padded = b64std(&raw);
    assert!(padded.ends_with('=') && padded.contains(['+', '/']));
    assert_top(
        padded.as_bytes(),
        Kind::Cwt,
        &[B64STD, Layer::CborTag(18)],
        0..padded.len(),
    );
    let unpadded = b64std_nopad(&raw);
    assert_top(
        unpadded.as_bytes(),
        Kind::Cwt,
        &[B64STD_NOPAD, Layer::CborTag(18)],
        0..unpadded.len(),
    );
}

#[test]
fn base64_without_alphabet_specific_characters() {
    // Neither "+/" nor "-_": unpadded is recorded as base64url, padded as
    // classic base64.
    let raw = token("rfc8392-a1-claims.cbor");
    let unpadded = b64url(&raw);
    let padded = b64std(&raw);
    assert!(!unpadded.contains(['-', '_', '+', '/']));
    assert!(padded.ends_with('='));
    assert_top(
        unpadded.as_bytes(),
        Kind::CborClaims,
        &[B64URL],
        0..unpadded.len(),
    );
    assert_top(
        padded.as_bytes(),
        Kind::CborClaims,
        &[B64STD],
        0..padded.len(),
    );
}

#[test]
fn base64std_wrapped_lines() {
    let raw = token(SD_KBT);
    for width in [64, 76] {
        let input = wrap(&b64std(&raw), width);
        assert!(input.contains('\n'));
        assert_top(
            input.as_bytes(),
            Kind::SdKbt,
            &[
                Layer::Base64Std {
                    padded: true,
                    wrap: Some(width),
                },
                Layer::CborTag(18),
            ],
            0..input.len(),
        );
    }
}

#[test]
fn base64_wrapped_with_crlf_is_detected() {
    let raw = token(SD_KBT);
    let input = wrap(&b64std(&raw), 64).replace('\n', "\r\n");
    let c = top(input.as_bytes());
    assert_eq!(c.kind, Kind::SdKbt);
    assert!(
        matches!(c.layers[0], Layer::Base64Std { padded: true, .. }),
        "{c:?}"
    );
}

#[test]
fn base64_of_jwt_text() {
    let t = jwt();
    let input = b64std(t.as_bytes());
    let c = top(input.as_bytes());
    assert_eq!(c.kind, Kind::Jwt);
    assert_eq!(c.layers.len(), 1);
    assert!(matches!(
        c.layers[0],
        Layer::Base64Std { .. } | Layer::Base64Url { .. }
    ));
}

#[test]
fn base64_of_base64() {
    let t = jwt();
    let input = b64url(b64url(t.as_bytes()).as_bytes());
    let cands = run(input.as_bytes());
    let c = expect_kind(&cands, &Kind::Jwt);
    assert_eq!(c.layers.len(), 2, "{c:?}");
    assert!(
        c.layers
            .iter()
            .all(|l| matches!(l, Layer::Base64Std { .. } | Layer::Base64Url { .. }))
    );
}

#[test]
fn base64_with_invalid_characters_is_not_base64() {
    let raw = token(CWT_TAG18);
    let mut input = b64std(&raw);
    input.insert(10, '*');
    let cands = run(input.as_bytes());
    assert!(find(&cands, &Kind::Cwt).is_none(), "{}", summary(&cands));
}

#[test]
fn base64_mixing_both_alphabets_is_rejected() {
    let raw = token(CWT_TAG18);
    let std = b64std_nopad(&raw);
    let url = b64url(&raw);
    // Take the first '+' or '/' from std and splice url's '-'/'_' elsewhere.
    let i = std.find(['+', '/']).unwrap();
    let j = url.rfind(['-', '_']).unwrap();
    if i < j {
        let mixed = format!("{}{}", &std[..j], &url[j..]);
        let cands = run(mixed.as_bytes());
        assert!(find(&cands, &Kind::Cwt).is_none(), "{}", summary(&cands));
    }
}

// ------------------------------------------------------------------ hex

#[test]
fn hex_lower_and_upper() {
    let raw = token(CWT_TAG18);
    let lower = hex(&raw);
    assert_top(
        lower.as_bytes(),
        Kind::Cwt,
        &[HEX, Layer::CborTag(18)],
        0..lower.len(),
    );
    let upper = hex_upper(&raw);
    assert_top(
        upper.as_bytes(),
        Kind::Cwt,
        &[
            Layer::Hex {
                upper: true,
                separator: None,
                wrap: None,
            },
            Layer::CborTag(18),
        ],
        0..upper.len(),
    );
}

#[test]
fn hex_with_separators_and_wrapping() {
    let raw = token(CWT_TAG18);
    for (upper, sep, per_line) in [
        (false, Some(' '), None),
        (true, Some(':'), None),
        (false, Some(':'), None),
        (false, None, Some(32)),
        (false, Some(' '), Some(16)),
        (true, Some(':'), Some(16)),
    ] {
        let input = hex_layout(&raw, upper, sep, per_line);
        assert_top(
            input.as_bytes(),
            Kind::Cwt,
            &[
                Layer::Hex {
                    upper,
                    separator: sep,
                    wrap: per_line,
                },
                Layer::CborTag(18),
            ],
            0..input.len(),
        );
    }
}

#[test]
fn hex_with_mixed_case_and_irregular_whitespace() {
    let raw = token(CWT_TAG18);
    let mut input = String::new();
    for (i, b) in raw.iter().enumerate() {
        input.push_str(&if i % 2 == 0 {
            format!("{b:02x}")
        } else {
            format!("{b:02X}")
        });
        if i % 7 == 3 {
            input.push_str("  \n\t");
        }
    }
    let c = top(input.as_bytes());
    assert_eq!(c.kind, Kind::Cwt);
    assert!(matches!(c.layers[0], Layer::Hex { .. }), "{c:?}");
}

#[test]
fn odd_length_hex_is_not_hex() {
    let raw = token(CWT_TAG18);
    let mut input = hex(&raw);
    input.push('a');
    let cands = run(input.as_bytes());
    assert!(
        !cands
            .iter()
            .any(|c| c.layers.iter().any(|l| matches!(l, Layer::Hex { .. }))),
        "{}",
        summary(&cands)
    );
}

#[test]
fn hex_sd_kbt_and_cose_key_set() {
    let kbt = hex(&token(SD_KBT));
    assert_top(
        kbt.as_bytes(),
        Kind::SdKbt,
        &[HEX, Layer::CborTag(18)],
        0..kbt.len(),
    );
    let ks = hex(&key("rfc8152-c7.1-public.cosekeyset.cbor"));
    assert_top(ks.as_bytes(), Kind::CoseKeySet, &[HEX], 0..ks.len());
}

// ------------------------------------------------------------------ combinations

#[test]
fn authorization_bearer_base64url_of_tagged_cwt() {
    let raw = token("derived-rfc8392-a3-tag61.cbor");
    let b = b64url(&raw);
    let input = format!("Authorization: Bearer {b}");
    assert_top(
        input.as_bytes(),
        Kind::Cwt,
        &[
            auth("Authorization: "),
            bearer("Bearer "),
            B64URL,
            Layer::CborTag(61),
            Layer::CborTag(18),
        ],
        22..input.len(),
    );
}

#[test]
fn bearer_base64url_sd_kbt() {
    let raw = token(SD_KBT);
    let b = b64url(&raw);
    let input = format!("Bearer {b}\n");
    assert_top(
        input.as_bytes(),
        Kind::SdKbt,
        &[
            trim("", "\n"),
            bearer("Bearer "),
            B64URL,
            Layer::CborTag(18),
        ],
        7..7 + b.len(),
    );
}

#[test]
fn quoted_base64_cwt() {
    let raw = token(CWT_TAG18);
    let b = b64std(&raw);
    let input = format!("\"{b}\"");
    assert_top(
        input.as_bytes(),
        Kind::Cwt,
        &[quotes('"'), B64STD, Layer::CborTag(18)],
        1..1 + b.len(),
    );
}

#[test]
fn json_field_url_encoded_jwt_inside() {
    let t = sd_jwt_kb();
    let enc = t.replace('~', "%7E");
    let input = format!(r#"{{"token":"{enc}"}}"#);
    assert_top(
        input.as_bytes(),
        Kind::SdJwt { kb: true },
        &[field(&["token"]), Layer::UrlEncoded],
        range_of(input.as_bytes(), enc.as_bytes()),
    );
}

#[test]
fn hex_of_base64_text_is_not_peeled_forever() {
    // Hex text of base64 text of a CWT: two decoding layers then the tag.
    let raw = token(CWT_TAG18);
    let input = hex(b64url(&raw).as_bytes());
    let cands = run(input.as_bytes());
    let c = expect_kind(&cands, &Kind::Cwt);
    assert_eq!(c.layers, vec![HEX, B64URL, Layer::CborTag(18)]);
}

#[test]
fn raw_binary_input_has_no_text_layers() {
    for name in [CWT_TAG18, SD_CWT, SD_KBT, "rfc8392-a1-claims.cbor"] {
        let input = token(name);
        let c = top(&input);
        assert!(
            c.layers.iter().all(|l| matches!(l, Layer::CborTag(_))),
            "{name}: {c:?}"
        );
    }
}
