//! JOSE classification: JWS compact / JWT, SD-JWT compact, JWS JSON and
//! SD-JWT JSON serializations, from RFC 7515, RFC 7519, and RFC 9901.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use tokenator_detect::Kind;

fn assert_top_exact(text: &str, kind: Kind) {
    let input = text.as_bytes();
    let c = top(input);
    assert_eq!(c.kind, kind, "{}", summary(&run(input)));
    assert!(
        c.layers.is_empty(),
        "exact input should have no layers: {c:?}"
    );
    assert_eq!(c.payload_range, 0..input.len());
}

// ------------------------------------------------------------------ compact JWS / JWT

#[test]
fn rfc7519_jwt_hs256() {
    assert_top_exact(&token_text(JWT), Kind::Jwt);
}

#[test]
fn rfc7515_a1_hs256() {
    assert_top_exact(&token_text("rfc7515-a1-jws-hs256.txt"), Kind::Jwt);
}

#[test]
fn rfc7515_a2_rs256() {
    assert_top_exact(&token_text("rfc7515-a2-jws-rs256.txt"), Kind::Jwt);
}

#[test]
fn rfc7515_a3_es256() {
    assert_top_exact(&token_text("rfc7515-a3-jws-es256.txt"), Kind::Jwt);
}

#[test]
fn rfc7515_a4_non_json_payload_is_jws_not_jwt() {
    let text = token_text("rfc7515-a4-jws-es512-nonjson-payload.txt");
    assert_top_exact(&text, Kind::JwsCompact);
    assert!(find(&run(text.as_bytes()), &Kind::Jwt).is_none());
}

#[test]
fn rfc7515_a5_unsecured_jws_empty_signature() {
    let text = token_text("rfc7515-a5-unsecured-jws.txt");
    assert!(text.ends_with('.'));
    assert_top_exact(&text, Kind::Jwt);
}

#[test]
fn rfc7519_unsecured_jwt_alg_none() {
    assert_top_exact(&token_text("rfc7519-s6.1-unsecured-jwt.txt"), Kind::Jwt);
}

#[test]
fn rfc9901_issuer_signed_jwt_without_tilde_is_jwt() {
    assert_top_exact(&token_text("rfc9901-s5.1-issuer-signed-jwt.txt"), Kind::Jwt);
}

#[test]
fn minimal_jwt_with_empty_claims() {
    // {"alg":"HS256"} . {} . sig
    let t = format!(
        "{}.{}.{}",
        b64url(br#"{"alg":"HS256"}"#),
        b64url(b"{}"),
        b64url(&[1, 2, 3])
    );
    assert_top_exact(&t, Kind::Jwt);
}

#[test]
fn detached_payload_is_jws_compact() {
    // RFC 7515 Appendix F: the payload segment is empty.
    let t = format!("{}..{}", b64url(br#"{"alg":"ES256"}"#), b64url(&[9; 64]));
    assert_top_exact(&t, Kind::JwsCompact);
}

#[test]
fn header_without_ey_prefix_still_detected() {
    // A header with leading whitespace inside the JSON encodes to "ICB7..."
    let t = format!(
        "{}.{}.{}",
        b64url(br#"  {"alg":"ES256"}"#),
        b64url(br#"{"sub":"x"}"#),
        b64url(&[7; 64])
    );
    assert!(!t.starts_with("ey"));
    let cands = run(t.as_bytes());
    expect_kind(&cands, &Kind::Jwt);
}

#[test]
fn header_without_alg_has_lower_confidence() {
    let with_alg = format!(
        "{}.{}.{}",
        b64url(br#"{"alg":"ES256","typ":"JWT"}"#),
        b64url(br#"{"sub":"x"}"#),
        b64url(&[7; 64])
    );
    let without = format!(
        "{}.{}.{}",
        b64url(br#"{"typ":"JWT"}"#),
        b64url(br#"{"sub":"x"}"#),
        b64url(&[7; 64])
    );
    let a = top(with_alg.as_bytes());
    assert_eq!(a.kind, Kind::Jwt);
    let b = run(without.as_bytes());
    if let Some(c) = find(&b, &Kind::Jwt) {
        assert!(c.confidence < a.confidence, "{}", summary(&b));
    }
}

#[test]
fn header_that_is_not_json_is_not_jws() {
    for t in [
        // base64url of "not json"
        format!("{}.{}.{}", b64url(b"not json"), b64url(b"{}"), b64url(b"s")),
        // a JSON array header
        format!("{}.{}.{}", b64url(b"[1,2]"), b64url(b"{}"), b64url(b"s")),
        // truncated header
        "eyJhbGc.eyJzdWIiOiJ4In0.c2ln".to_owned(),
        // header segment is not base64url
        "ey!!.eyJzdWIiOiJ4In0.c2ln".to_owned(),
    ] {
        let cands = run(t.as_bytes());
        assert!(
            find(&cands, &Kind::Jwt).is_none() && find(&cands, &Kind::JwsCompact).is_none(),
            "{t}: {}",
            summary(&cands)
        );
    }
}

#[test]
fn wrong_segment_counts_are_not_jws() {
    let h = b64url(br#"{"alg":"ES256"}"#);
    let p = b64url(br#"{"sub":"x"}"#);
    for t in [
        h.clone(),
        format!("{h}.{p}"),
        format!("{h}.{p}.c2ln.extra"),
        format!("{h}.{p}.c2ln."),
        format!(".{h}.{p}"),
    ] {
        let cands = run(t.as_bytes());
        assert!(
            find(&cands, &Kind::Jwt).is_none() && find(&cands, &Kind::JwsCompact).is_none(),
            "{t}: {}",
            summary(&cands)
        );
    }
}

#[test]
fn jwe_compact_is_not_a_jws() {
    // RFC 7516 shape: five segments, header has "enc".
    let t = format!(
        "{}.{}.{}.{}.{}",
        b64url(br#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#),
        b64url(&[1; 32]),
        b64url(&[2; 12]),
        b64url(&[3; 40]),
        b64url(&[4; 16])
    );
    let cands = run(t.as_bytes());
    for k in [
        Kind::Jwt,
        Kind::JwsCompact,
        Kind::SdJwt { kb: false },
        Kind::SdJwt { kb: true },
    ] {
        assert!(find(&cands, &k).is_none(), "{}", summary(&cands));
    }
}

#[test]
fn signature_segment_with_bad_alphabet_is_not_jws() {
    let t = format!(
        "{}.{}.{}",
        b64url(br#"{"alg":"ES256"}"#),
        b64url(br#"{"sub":"x"}"#),
        "abc+/def"
    );
    let cands = run(t.as_bytes());
    assert!(find(&cands, &Kind::Jwt).is_none(), "{}", summary(&cands));
}

// ------------------------------------------------------------------ SD-JWT compact

#[test]
fn rfc9901_sd_jwt_without_kb() {
    let text = token_text(SD_JWT);
    assert!(text.ends_with('~'));
    assert_top_exact(&text, Kind::SdJwt { kb: false });
}

#[test]
fn rfc9901_sd_jwt_with_kb() {
    let text = token_text(SD_JWT_KB);
    assert!(!text.ends_with('~'));
    assert_top_exact(&text, Kind::SdJwt { kb: true });
}

#[test]
fn sd_jwt_outranks_any_jwt_reading() {
    for name in [SD_JWT, SD_JWT_KB] {
        let text = token_text(name);
        let cands = run(text.as_bytes());
        let sd = &cands[0];
        assert!(matches!(sd.kind, Kind::SdJwt { .. }));
        for c in cands.iter().filter(|c| c.kind == Kind::Jwt) {
            assert!(c.confidence < sd.confidence, "{}", summary(&cands));
        }
    }
}

#[test]
fn sd_jwt_with_no_disclosures() {
    // "<issuer-signed JWT>~" is an SD-JWT with zero disclosures.
    let jwt = token_text("rfc9901-s5.1-issuer-signed-jwt.txt");
    assert_top_exact(&format!("{jwt}~"), Kind::SdJwt { kb: false });
}

#[test]
fn sd_jwt_with_kb_and_no_disclosures() {
    let full = token_text(SD_JWT_KB);
    let jwt = full.split('~').next().unwrap();
    let kb = full.rsplit('~').next().unwrap();
    assert_top_exact(&format!("{jwt}~{kb}"), Kind::SdJwt { kb: true });
}

#[test]
fn sd_jwt_from_minimal_parts() {
    let jwt = format!(
        "{}.{}.{}",
        b64url(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#),
        b64url(br#"{"_sd":["abc"],"_sd_alg":"sha-256"}"#),
        b64url(&[1; 64])
    );
    let disclosure = b64url(br#"["salt","given_name","John"]"#);
    assert_top_exact(&format!("{jwt}~{disclosure}~"), Kind::SdJwt { kb: false });
}

#[test]
fn tilde_after_non_jws_is_not_sd_jwt() {
    for t in ["hello~world~", "~~~", "abc~", "~eyJhbGciOiJub25lIn0.e30."] {
        let cands = run(t.as_bytes());
        assert!(
            !cands.iter().any(|c| matches!(c.kind, Kind::SdJwt { .. })),
            "{t}: {}",
            summary(&cands)
        );
    }
}

#[test]
fn sd_jwt_payload_range_is_whole_token() {
    let text = token_text(SD_JWT_KB);
    let c = top(text.as_bytes());
    assert_eq!(c.payload_range, 0..text.len());
}

// ------------------------------------------------------------------ JWS JSON

#[test]
fn rfc7515_a6_general_json() {
    let input = token("rfc7515-a6-jws-json-general.json");
    let c = top(&input);
    assert_eq!(c.kind, Kind::JwsJson { general: true });
}

#[test]
fn rfc7515_a7_flattened_json() {
    let input = token("rfc7515-a7-jws-json-flattened.json");
    let c = top(&input);
    assert_eq!(c.kind, Kind::JwsJson { general: false });
}

#[test]
fn jws_json_layers_only_trim_the_final_newline() {
    let input = token("rfc7515-a7-jws-json-flattened.json");
    let c = top(&input);
    assert_eq!(c.layers, vec![trim("", "\n")]);
    assert_eq!(c.payload_range, 0..input.len() - 1);
}

#[test]
fn jws_json_minimal_flattened_and_general() {
    let p = b64url(br#"{"sub":"x"}"#);
    let h = b64url(br#"{"alg":"ES256"}"#);
    let flat = format!(r#"{{"payload":"{p}","protected":"{h}","signature":"c2ln"}}"#);
    assert_top_exact(&flat, Kind::JwsJson { general: false });
    let general =
        format!(r#"{{"payload":"{p}","signatures":[{{"protected":"{h}","signature":"c2ln"}}]}}"#);
    assert_top_exact(&general, Kind::JwsJson { general: true });
}

#[test]
fn json_with_payload_but_no_signature_is_not_jws_json() {
    let p = b64url(br#"{"sub":"x"}"#);
    let input = format!(r#"{{"payload":"{p}"}}"#);
    let cands = run(input.as_bytes());
    assert!(
        !cands
            .iter()
            .any(|c| matches!(c.kind, Kind::JwsJson { .. } | Kind::SdJwtJson { .. })),
        "{}",
        summary(&cands)
    );
    expect_kind(&cands, &Kind::JsonClaims);
}

// ------------------------------------------------------------------ SD-JWT JSON

#[test]
fn rfc9901_s8_2_flattened_sd_jwt_json() {
    let c = top(&token("rfc9901-s8.2-sd-jwt-json-flattened.json"));
    assert_eq!(
        c.kind,
        Kind::SdJwtJson {
            general: false,
            kb: false
        }
    );
}

#[test]
fn rfc9901_s8_2_flattened_sd_jwt_kb_json() {
    let c = top(&token("rfc9901-s8.2-sd-jwt-kb-json-flattened.json"));
    assert_eq!(
        c.kind,
        Kind::SdJwtJson {
            general: false,
            kb: true
        }
    );
}

#[test]
fn rfc9901_s8_3_general_sd_jwt_kb_json() {
    let c = top(&token("rfc9901-s8.3-sd-jwt-kb-json-general.json"));
    assert_eq!(
        c.kind,
        Kind::SdJwtJson {
            general: true,
            kb: true
        }
    );
}

#[test]
fn sd_jwt_json_outranks_plain_jws_json() {
    let input = token("rfc9901-s8.3-sd-jwt-kb-json-general.json");
    let cands = run(&input);
    assert_outranks(
        &cands,
        &Kind::SdJwtJson {
            general: true,
            kb: true,
        },
        &Kind::JwsJson { general: true },
    );
}

#[test]
fn sd_jwt_json_with_empty_disclosures() {
    let p = b64url(br#"{"_sd_alg":"sha-256"}"#);
    let h = b64url(br#"{"alg":"ES256"}"#);
    let input = format!(
        r#"{{"header":{{"disclosures":[]}},"payload":"{p}","protected":"{h}","signature":"c2ln"}}"#
    );
    assert_top_exact(
        &input,
        Kind::SdJwtJson {
            general: false,
            kb: false,
        },
    );
}

#[test]
fn jose_payload_range_and_layers_for_trailing_newline_files() {
    // Text fixtures end in "\n": the top candidate peels exactly that.
    for name in [JWT, SD_JWT, SD_JWT_KB, "rfc7515-a3-jws-es256.txt"] {
        let input = token(name);
        let c = top(&input);
        assert_eq!(c.layers, vec![trim("", "\n")], "{name}");
        assert_eq!(c.payload_range, 0..input.len() - 1, "{name}");
    }
}
