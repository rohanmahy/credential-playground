//! Self-checks for the test helpers, so a failing detection test points at
//! the crate and not at a broken expectation. These pass without the
//! implementation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;

#[test]
fn base64_rfc4648_vectors() {
    let v = [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];
    for (raw, enc) in v {
        assert_eq!(b64std(raw.as_bytes()), enc);
        assert_eq!(b64url_pad(raw.as_bytes()), enc);
        assert_eq!(b64std_nopad(raw.as_bytes()), enc.trim_end_matches('='));
        assert_eq!(b64url(raw.as_bytes()), enc.trim_end_matches('='));
    }
    assert_eq!(b64std(&[0xfb, 0xff, 0xbf]), "+/+/");
    assert_eq!(b64url(&[0xfb, 0xff, 0xbf]), "-_-_");
}

#[test]
fn base64_matches_rfc7515_header() {
    // RFC 7515 A.1: the protected header, CRLF and all.
    let header = b"{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}";
    assert_eq!(b64url(header), "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");
    assert!(token_text(JWT).starts_with(&b64url(header)));
}

#[test]
fn hex_helpers() {
    assert_eq!(hex(&[0xa1, 0x01, 0x26]), "a10126");
    assert_eq!(hex_upper(&[0xa1, 0x01, 0x26]), "A10126");
    assert_eq!(
        hex_layout(&[0xa1, 0x01, 0x26], true, Some(':'), None),
        "A1:01:26"
    );
    assert_eq!(
        hex_layout(&[0xa1, 0x01, 0x26], false, Some(' '), Some(2)),
        "a1 01\n26"
    );
    assert_eq!(h("a1 01\n26"), [0xa1, 0x01, 0x26]);
}

#[test]
fn percent_helpers() {
    assert_eq!(pct(b"a+b/c=~.-_ "), "a%2Bb%2Fc%3D~.-_%20");
    assert_eq!(pct_all(b"a~"), "%61%7E");
}

#[test]
fn wrap_helper() {
    assert_eq!(wrap("abcdefg", 3), "abc\ndef\ng");
    assert_eq!(wrap("abc", 3), "abc");
}

#[test]
fn fixtures_have_expected_shapes() {
    let cwt = token(CWT_TAG18);
    assert_eq!(cwt[..2], [0xd2, 0x84]);
    assert_eq!(
        token("derived-rfc8392-a3-tag61.cbor")[..3],
        [0xd8, 0x3d, 0xd2]
    );
    assert_eq!(cwt_untagged()[0], 0x84);
    assert_eq!(&cwt_untagged()[..], &cwt[1..]);
    assert_eq!(
        h(&String::from_utf8(token("rfc8392-a3-signed-cwt.hex")).unwrap()),
        cwt
    );
    assert_eq!(token(SD_CWT)[..2], [0xd2, 0x84]);
    assert_eq!(token(SD_KBT)[..2], [0xd2, 0x84]);
    assert_eq!(
        token("rfc8392-a4-maced-cwt-tag61.cbor")[..3],
        [0xd8, 0x3d, 0xd1]
    );
    assert_eq!(token("rfc9052-c2.1-sign1.cbor").len(), 98);
    assert_eq!(key("rfc8152-c7.1-public.cosekeyset.cbor").len(), 481);
    assert_eq!(
        *key("rfc8392-a2.1-symmetric128.cosekey.cbor")
            .last()
            .unwrap(),
        0x0a
    );
    assert_eq!(token_text(SD_JWT).matches('~').count(), 11);
    assert_eq!(token_text(SD_JWT_KB).matches('~').count(), 5);
    for name in [JWT, SD_JWT, SD_JWT_KB, "rfc7515-a5-unsecured-jws.txt"] {
        let t = token(name);
        assert_eq!(t.iter().filter(|&&b| b == b'\n').count(), 1, "{name}");
        assert_eq!(*t.last().unwrap(), b'\n');
    }
}

#[test]
fn fixtures_decode_as_cbor() {
    for name in [
        CWT_TAG18,
        SD_CWT,
        SD_KBT,
        "sd-cwt-08-nested-issuer-sd-cwt.cbor",
        "sd-cwt-08-nested-sd-kbt.cbor",
        "derived-rfc8392-a3-untagged.cbor",
        "derived-rfc8392-a3-tag61.cbor",
        "rfc8392-a1-claims.cbor",
        "rfc8392-a4-maced-cwt-tag61.cbor",
        "rfc9052-c2.1-sign1.cbor",
    ] {
        tokenator_cbor::decode(&token(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    for name in [
        "rfc8392-a2.1-symmetric128.cosekey.cbor",
        "rfc8392-a2.3-ec-p256.cosekey.cbor",
        "rfc8152-c7.1-public.cosekeyset.cbor",
        "sd-cwt-08-c1-holder-private.cosekey.cbor",
    ] {
        tokenator_cbor::decode(&key(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn fixtures_parse_as_json() {
    for name in [
        "rfc7515-a6-jws-json-general.json",
        "rfc7515-a7-jws-json-flattened.json",
        "rfc7519-s3.1-claims.json",
        "rfc9901-s5.1-input-claims.json",
        "rfc9901-s8.2-sd-jwt-json-flattened.json",
        "rfc9901-s8.2-sd-jwt-kb-json-flattened.json",
        "rfc9901-s8.3-sd-jwt-kb-json-general.json",
    ] {
        tokenator_json::parse(&token(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    for name in [
        "rfc7517-a1-public.jwks.json",
        "rfc7517-a2-private.jwks.json",
        "rfc7517-a3-symmetric.jwks.json",
        "rfc9901-a5-ec-p256-public.jwk.json",
        "sd-cwt-08-c1-holder-private.jwk.json",
    ] {
        tokenator_json::parse(&key(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn synthetic_sign1_builders() {
    let item = sign1(vec![(int(1), int(-7))], vec![], wrapped(claims()));
    let bytes = sign1_tagged(item);
    assert_eq!(bytes[..4], [0xd2, 0x84, 0x43, 0xa1]);
    tokenator_cbor::decode(&bytes).unwrap();
}
