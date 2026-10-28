//! Unpadded base64url codec.

// Helpers outside #[test] fns unwrap and panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{b64d, b64e};
use tokenator_jose::{B64Error, b64u_decode, b64u_encode};

#[test]
fn rfc4648_test_vectors_unpadded() {
    // RFC 4648 §10, with padding removed and the URL-safe alphabet.
    for (plain, enc) in [
        ("", ""),
        ("f", "Zg"),
        ("fo", "Zm8"),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg"),
        ("fooba", "Zm9vYmE"),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(b64u_encode(plain.as_bytes()), enc);
        assert_eq!(b64u_decode(enc).unwrap(), plain.as_bytes());
    }
}

#[test]
fn url_safe_alphabet() {
    assert_eq!(b64u_encode(&[0xfb, 0xff, 0xbf]), "-_-_");
    assert_eq!(b64u_decode("-_-_").unwrap(), [0xfb, 0xff, 0xbf]);
}

#[test]
fn rfc7515_header_example() {
    // RFC 7515 §3.3: the encoded JOSE header (with its CRLF bytes).
    let header = b"{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}";
    assert_eq!(
        b64u_encode(header),
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
    );
}

#[test]
fn rejects_padding_and_standard_alphabet() {
    assert_eq!(
        b64u_decode("Zg=="),
        Err(B64Error::InvalidByte { offset: 2 })
    );
    assert_eq!(
        b64u_decode("ab+c"),
        Err(B64Error::InvalidByte { offset: 2 })
    );
    assert_eq!(
        b64u_decode("ab/c"),
        Err(B64Error::InvalidByte { offset: 2 })
    );
    assert_eq!(
        b64u_decode("ab c"),
        Err(B64Error::InvalidByte { offset: 2 })
    );
    assert_eq!(
        b64u_decode("abc\n"),
        Err(B64Error::InvalidByte { offset: 3 })
    );
    assert_eq!(b64u_decode("é"), Err(B64Error::InvalidByte { offset: 0 }));
    assert_eq!(
        b64u_decode("abc."),
        Err(B64Error::InvalidByte { offset: 3 })
    );
}

#[test]
fn rejects_impossible_length() {
    assert_eq!(b64u_decode("a"), Err(B64Error::InvalidLength));
    assert_eq!(b64u_decode("abcde"), Err(B64Error::InvalidLength));
}

#[test]
fn rejects_non_canonical_trailing_bits() {
    // "Zg" is canonical for "f"; "Zh" has a non-zero unused bit.
    assert_eq!(b64u_decode("Zh"), Err(B64Error::NonCanonical));
    assert_eq!(b64u_decode("Zm9"), Err(B64Error::NonCanonical));
}

#[test]
fn agrees_with_independent_codec() {
    for len in 0..70u8 {
        let bytes: Vec<u8> = (0..len)
            .map(|i| i.wrapping_mul(37).wrapping_add(len))
            .collect();
        let enc = b64u_encode(&bytes);
        assert_eq!(enc, b64e(&bytes));
        assert_eq!(b64u_decode(&enc).unwrap(), b64d(&enc));
    }
}
