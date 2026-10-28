//! Every tamper primitive breaks verification in the expected way and
//! leaves everything it does not target byte-identical.

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{
    b64d, b64e, holder_key, issuer_key, json, public_jwk, raw, rng, same_json, segment_json,
    segments, split_sd,
};
use tokenator_crypto::{Alg, CryptoError};
use tokenator_jose::{
    Cnf, IssueOptions, JoseError, KbExpectations, KbOptions, PartRef, RawParts, SdFinding, Tamper,
    ValueCheck, VerifyError, assemble_compact, check_kb_jwt, issue, parse, present, tamper,
    verify_signature,
};
use tokenator_keys::Key;

const NOW: i64 = 1_800_000_000;

struct Fixture {
    token: String,
    issuer: Key,
}

/// An ES256 SD-JWT+KB with two disclosures, all keys known.
fn fixture() -> Fixture {
    let issuer = issuer_key(Alg::ES256);
    let holder = holder_key(Alg::ES256);
    let claims = json(r#"{"sub":"alice","a":1,"b":2}"#);
    let mut opts = IssueOptions::new(&issuer, Alg::ES256);
    opts.typ = Some("example+sd-jwt".into());
    opts.kid = Some("issuer-1".into());
    opts.cnf = Some(Cnf::Jwk(public_jwk(&holder)));
    opts.sd = vec!["/a".into(), "/b".into()];
    let issued = issue(&claims, &opts, &mut rng(1)).unwrap();
    let parsed = parse(&issued.token).unwrap();
    let kb = KbOptions::new(&holder, Alg::ES256, "aud", "nonce", NOW);
    let presented = present(
        parsed.token.sd_jwt().unwrap(),
        &[0, 1],
        Some(&kb),
        &mut rng(2),
    )
    .unwrap();
    Fixture {
        token: presented.token,
        issuer,
    }
}

fn expect() -> KbExpectations<'static> {
    KbExpectations {
        aud: Some("aud"),
        nonce: Some("nonce"),
        now: NOW,
        skew: 60,
        max_age: Some(300),
    }
}

fn issuer_check(token: &str, key: &Key) -> Result<Alg, VerifyError> {
    let parsed = parse(token).unwrap();
    verify_signature(parsed.token.jws(), 0, key)
}

fn kb_report(token: &str) -> tokenator_jose::KbReport {
    let parsed = parse(token).unwrap();
    check_kb_jwt(parsed.token.sd_jwt().unwrap(), &[], &expect()).unwrap()
}

#[test]
fn the_fixture_is_valid() {
    let f = fixture();
    assert_eq!(issuer_check(&f.token, &f.issuer), Ok(Alg::ES256));
    let r = kb_report(&f.token);
    assert_eq!(r.signature, Ok(Alg::ES256));
    assert_eq!(r.sd_hash, ValueCheck::Match);
}

#[test]
fn flip_signature_bit() {
    let f = fixture();
    let out = tamper(
        &f.token,
        &Tamper::FlipBit {
            part: PartRef::Signature(0),
            bit: 0,
        },
    )
    .unwrap();
    let (jwt, discs, kb) = split_sd(&f.token);
    let (jwt2, discs2, kb2) = split_sd(&out);
    let [h, p, s] = segments(jwt);
    let [h2, p2, s2] = segments(jwt2);
    assert_eq!((h, p, &discs, kb), (h2, p2, &discs2, kb2));
    let (a, b) = (b64d(s), b64d(s2));
    assert_eq!(a[0] ^ 0x80, b[0]);
    assert_eq!(a[1..], b[1..]);
    assert_eq!(
        issuer_check(&out, &f.issuer),
        Err(VerifyError::Crypto(CryptoError::InvalidSignature))
    );
}

#[test]
fn flip_bit_mask_is_msb_first() {
    let f = fixture();
    let out = tamper(
        &f.token,
        &Tamper::FlipBit {
            part: PartRef::Signature(0),
            bit: 13,
        },
    )
    .unwrap();
    let a = b64d(segments(split_sd(&f.token).0)[2]);
    let b = b64d(segments(split_sd(&out).0)[2]);
    assert_eq!(a[1] ^ 0x04, b[1]);
}

#[test]
fn flip_payload_bit() {
    let f = fixture();
    let out = tamper(
        &f.token,
        &Tamper::FlipBit {
            part: PartRef::Payload,
            bit: 7,
        },
    )
    .unwrap();
    assert_eq!(
        issuer_check(&out, &f.issuer),
        Err(VerifyError::Crypto(CryptoError::InvalidSignature))
    );
    // The KB-JWT is bound to the old issuer JWT.
    assert!(matches!(
        kb_report(&out).sd_hash,
        ValueCheck::Mismatch { .. }
    ));
}

#[test]
fn flip_header_bit_breaks_the_header() {
    let f = fixture();
    // '{' (0x7b) with bit 1 flipped is ';' (0x3b).
    let out = tamper(
        &f.token,
        &Tamper::FlipBit {
            part: PartRef::ProtectedHeader(0),
            bit: 1,
        },
    )
    .unwrap();
    assert_eq!(b64d(segments(split_sd(&out).0)[0])[0], b';');
    assert_eq!(
        issuer_check(&out, &f.issuer),
        Err(VerifyError::HeaderUnreadable)
    );
}

#[test]
fn flip_disclosure_bit() {
    let f = fixture();
    let out = tamper(
        &f.token,
        &Tamper::FlipBit {
            part: PartRef::Disclosure(0),
            bit: 30,
        },
    )
    .unwrap();
    assert_eq!(
        issuer_check(&out, &f.issuer),
        Ok(Alg::ES256),
        "the issuer JWT is untouched"
    );
    let parsed = parse(&out).unwrap();
    let report = parsed.token.sd_jwt().unwrap().process().unwrap().report;
    assert!(
        report
            .findings
            .iter()
            .any(|x| matches!(x, SdFinding::UnmatchedDisclosure { disclosure: 0 }))
    );
    assert!(
        report
            .findings
            .iter()
            .any(|x| matches!(x, SdFinding::DigestWithoutDisclosure { .. }))
    );
    assert!(matches!(
        kb_report(&out).sd_hash,
        ValueCheck::Mismatch { .. }
    ));
}

#[test]
fn flip_kb_parts() {
    let f = fixture();
    for part in [PartRef::KbSignature, PartRef::KbPayload] {
        let out = tamper(&f.token, &Tamper::FlipBit { part, bit: 8 }).unwrap();
        assert_eq!(issuer_check(&out, &f.issuer), Ok(Alg::ES256));
        assert_eq!(
            kb_report(&out).signature,
            Err(VerifyError::Crypto(CryptoError::InvalidSignature)),
            "{part:?}"
        );
    }
    let out = tamper(
        &f.token,
        &Tamper::FlipBit {
            part: PartRef::KbProtectedHeader,
            bit: 1,
        },
    )
    .unwrap();
    assert_eq!(
        kb_report(&out).signature,
        Err(VerifyError::HeaderUnreadable)
    );
}

#[test]
fn flip_bit_errors() {
    let f = fixture();
    assert_eq!(
        tamper(
            &f.token,
            &Tamper::FlipBit {
                part: PartRef::Signature(0),
                bit: 64 * 8
            }
        )
        .unwrap_err(),
        JoseError::OutOfRange
    );
    assert_eq!(
        tamper(
            &f.token,
            &Tamper::FlipBit {
                part: PartRef::Disclosure(5),
                bit: 0
            }
        )
        .unwrap_err(),
        JoseError::NoSuchDisclosure(5)
    );
    let (jwt, _, _) = split_sd(&f.token);
    assert_eq!(
        tamper(
            jwt,
            &Tamper::FlipBit {
                part: PartRef::KbSignature,
                bit: 0
            }
        )
        .unwrap_err(),
        JoseError::OutOfRange,
        "a plain JWT has no KB-JWT"
    );
    let undecodable = format!("{}.{}.!!", segments(jwt)[0], segments(jwt)[1]);
    assert!(matches!(
        tamper(
            &undecodable,
            &Tamper::FlipBit {
                part: PartRef::Signature(0),
                bit: 0
            }
        )
        .unwrap_err(),
        JoseError::Part {
            part: PartRef::Signature(0),
            ..
        }
    ));
}

#[test]
fn set_alg() {
    let f = fixture();
    let out = tamper(&f.token, &Tamper::SetAlg("none".into())).unwrap();
    assert_eq!(
        segment_json(segments(split_sd(&out).0)[0]),
        r#"{"alg":"none","typ":"example+sd-jwt","kid":"issuer-1"}"#,
        "only the alg value changes"
    );
    assert_eq!(issuer_check(&out, &f.issuer), Err(VerifyError::AlgNone));
    let out = tamper(&f.token, &Tamper::SetAlg("HS256".into())).unwrap();
    assert_eq!(
        issuer_check(&out, &f.issuer),
        Err(VerifyError::UnsupportedAlg("HS256".into()))
    );
    let out = tamper(&f.token, &Tamper::SetAlg("ES384".into())).unwrap();
    assert!(matches!(
        issuer_check(&out, &f.issuer),
        Err(VerifyError::Crypto(CryptoError::KeyNotSuitable {
            alg: Alg::ES384,
            ..
        }))
    ));
}

#[test]
fn set_alg_adds_a_missing_alg_at_the_end() {
    let payload = b64e(br#"{"a":1}"#);
    let header = b64e(br#"{"typ":"JWT"}"#);
    let token = format!("{header}.{payload}.");
    let out = tamper(&token, &Tamper::SetAlg("ES256".into())).unwrap();
    assert_eq!(
        segment_json(segments(&out)[0]),
        r#"{"typ":"JWT","alg":"ES256"}"#
    );
    assert_eq!(segments(&out)[1], payload);
}

#[test]
fn set_alg_keeps_original_header_layout() {
    // RFC 7515 A.1's header has a CRLF and a space; they survive.
    let t = common::token("rfc7515-a1-jws-hs256.txt");
    let out = tamper(&t, &Tamper::SetAlg("none".into())).unwrap();
    assert_eq!(
        b64d(segments(&out)[0]),
        b"{\"typ\":\"JWT\",\r\n \"alg\":\"none\"}"
    );
}

#[test]
fn strip_signature() {
    let f = fixture();
    let out = tamper(&f.token, &Tamper::StripSignature).unwrap();
    assert_eq!(segments(split_sd(&out).0)[2], "");
    assert_eq!(split_sd(&out).1, split_sd(&f.token).1);
    assert_eq!(
        issuer_check(&out, &f.issuer),
        Err(VerifyError::Crypto(CryptoError::InvalidSignature))
    );
}

#[test]
fn set_and_remove_kid() {
    let f = fixture();
    let out = tamper(&f.token, &Tamper::SetKid(Some("other".into()))).unwrap();
    assert_eq!(
        segment_json(segments(split_sd(&out).0)[0]),
        r#"{"alg":"ES256","typ":"example+sd-jwt","kid":"other"}"#
    );
    assert_eq!(
        issuer_check(&out, &f.issuer),
        Err(VerifyError::Crypto(CryptoError::InvalidSignature))
    );
    let out = tamper(&f.token, &Tamper::SetKid(None)).unwrap();
    assert_eq!(
        segment_json(segments(split_sd(&out).0)[0]),
        r#"{"alg":"ES256","typ":"example+sd-jwt"}"#
    );
    let t = common::token("rfc7515-a3-jws-es256.txt");
    let out = tamper(&t, &Tamper::SetKid(Some("k".into()))).unwrap();
    assert_eq!(
        segment_json(segments(&out)[0]),
        r#"{"alg":"ES256","kid":"k"}"#
    );
}

#[test]
fn truncate() {
    let f = fixture();
    for n in [0usize, 5, 40, f.token.len() / 2, f.token.len() - 1] {
        let out = tamper(&f.token, &Tamper::Truncate(n)).unwrap();
        assert_eq!(out, &f.token[..n]);
        // Truncated tokens never panic the parser.
        let _ = parse(&out);
    }
    assert_eq!(
        tamper(&f.token, &Tamper::Truncate(f.token.len())).unwrap_err(),
        JoseError::OutOfRange
    );
    // Cutting off the KB-JWT signature.
    let out = tamper(&f.token, &Tamper::Truncate(f.token.len() - 10)).unwrap();
    assert!(kb_report(&out).signature.is_err());
}

#[test]
fn duplicate_disclosure() {
    let f = fixture();
    let out = tamper(&f.token, &Tamper::DuplicateDisclosure(0)).unwrap();
    let (_, discs, kb) = split_sd(&out);
    let (_, orig, kb0) = split_sd(&f.token);
    assert_eq!(discs, [orig[0], orig[1], orig[0]]);
    assert_eq!(kb, kb0);
    assert_eq!(issuer_check(&out, &f.issuer), Ok(Alg::ES256));
    let parsed = parse(&out).unwrap();
    let report = parsed.token.sd_jwt().unwrap().process().unwrap().report;
    assert_eq!(
        report.findings,
        [SdFinding::DuplicateDisclosure {
            disclosures: vec![0, 2]
        }]
    );
    assert!(matches!(
        kb_report(&out).sd_hash,
        ValueCheck::Mismatch { .. }
    ));
    assert_eq!(
        tamper(&f.token, &Tamper::DuplicateDisclosure(2)).unwrap_err(),
        JoseError::NoSuchDisclosure(2)
    );
}

#[test]
fn reencode_header() {
    let f = fixture();
    let out = tamper(&f.token, &Tamper::ReencodeHeader).unwrap();
    let before = segment_json(segments(split_sd(&f.token).0)[0]);
    let after = segment_json(segments(split_sd(&out).0)[0]);
    assert_ne!(before, after);
    assert!(same_json(&json(&before), &json(&after)));
    assert_eq!(
        issuer_check(&out, &f.issuer),
        Err(VerifyError::Crypto(CryptoError::InvalidSignature))
    );
}

#[test]
fn tamper_needs_compact() {
    let input = raw("rfc7515-a7-jws-json-flattened.json");
    assert_eq!(
        tamper(&input, &Tamper::StripSignature).unwrap_err(),
        JoseError::NotCompact
    );
}

#[test]
fn tamper_ignores_surrounding_whitespace() {
    let t = common::token("rfc7515-a3-jws-es256.txt");
    let out = tamper(&format!("  {t}\n"), &Tamper::StripSignature).unwrap();
    assert_eq!(out, format!("{}.{}.", segments(&t)[0], segments(&t)[1]));
}

#[test]
fn assemble_raw_parts() {
    let d = ["d1", "d2"];
    let mut raw = RawParts {
        header: "h",
        payload: "p",
        signature: "s",
        disclosures: None,
        kb_jwt: None,
    };
    assert_eq!(assemble_compact(&raw), "h.p.s");
    raw.disclosures = Some(&d);
    assert_eq!(assemble_compact(&raw), "h.p.s~d1~d2~");
    raw.kb_jwt = Some("k.k.k");
    assert_eq!(assemble_compact(&raw), "h.p.s~d1~d2~k.k.k");
    raw.disclosures = Some(&[]);
    assert_eq!(assemble_compact(&raw), "h.p.s~k.k.k");
}

#[test]
fn assembled_forgeries_fail_as_expected() {
    let f = fixture();
    let (jwt, discs, kb) = split_sd(&f.token);
    let [h, p, s] = segments(jwt);
    // alg: none with the original payload.
    let none = b64e(br#"{"alg":"none"}"#);
    let t = assemble_compact(&RawParts {
        header: &none,
        payload: p,
        signature: "",
        disclosures: Some(&discs),
        kb_jwt: None,
    });
    assert_eq!(issuer_check(&t, &f.issuer), Err(VerifyError::AlgNone));
    // Swapped alg (header of an EdDSA token over an ES256 signature).
    let eddsa = b64e(br#"{"alg":"EdDSA"}"#);
    let t = assemble_compact(&RawParts {
        header: &eddsa,
        payload: p,
        signature: s,
        disclosures: None,
        kb_jwt: None,
    });
    assert!(matches!(
        issuer_check(&t, &f.issuer),
        Err(VerifyError::Crypto(CryptoError::KeyNotSuitable {
            alg: Alg::EdDSA,
            ..
        }))
    ));
    // Disclosures reordered: issuer fine, KB-JWT sd_hash broken.
    let swapped = [discs[1], discs[0]];
    let t = assemble_compact(&RawParts {
        header: h,
        payload: p,
        signature: s,
        disclosures: Some(&swapped),
        kb_jwt: Some(kb),
    });
    assert_eq!(issuer_check(&t, &f.issuer), Ok(Alg::ES256));
    assert!(matches!(kb_report(&t).sd_hash, ValueCheck::Mismatch { .. }));
    // The unmodified parts reassemble to the original.
    let t = assemble_compact(&RawParts {
        header: h,
        payload: p,
        signature: s,
        disclosures: Some(&discs),
        kb_jwt: Some(kb),
    });
    assert_eq!(t, f.token);
}
