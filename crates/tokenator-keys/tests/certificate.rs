//! `import_certificate`: the SubjectPublicKeyInfo of an X.509 certificate.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::path::PathBuf;

use base64ct::{Base64, Encoding};
use tokenator_keys::{HashAlg, KeyError, ThumbprintKind, import, import_certificate, thumbprint};

fn fixture(rel: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/keys")
        .join(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// The DER inside a single-block PEM file.
fn pem_der(rel: &str) -> Vec<u8> {
    let text = String::from_utf8(fixture(rel)).unwrap();
    let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    Base64::decode_vec(&body).unwrap()
}

#[test]
fn certificate_keys_equal_their_spki() {
    for (cert, spki) in [
        ("x509/p256-selfsigned.pem", "openssl/p256-spki.pem"),
        ("x509/ed25519-selfsigned.pem", "openssl/ed25519-spki.pem"),
    ] {
        let key = import_certificate(&pem_der(cert)).unwrap();
        assert!(!key.is_private(), "{cert}");
        let expected = import(&fixture(spki), None).unwrap().remove(0);
        assert!(key.same_material(&expected), "{cert}");
        assert_eq!(
            thumbprint(&key, ThumbprintKind::Jwk, HashAlg::Sha256),
            thumbprint(&expected, ThumbprintKind::Jwk, HashAlg::Sha256),
        );
    }
    let der = fixture("x509/p256-selfsigned.der");
    assert_eq!(der, pem_der("x509/p256-selfsigned.pem"));
}

#[test]
fn bad_certificates_are_errors() {
    assert_eq!(
        import_certificate(b""),
        Err(KeyError::Der("malformed X.509 certificate"))
    );
    let mut der = fixture("x509/p256-selfsigned.der");
    der.truncate(der.len() - 10);
    assert!(import_certificate(&der).is_err());
    // An X25519 key (RFC 8410 §10.2) is not supported.
    let err = import_certificate(&pem_der("rfc8410-s10.2-x25519-cert.pem")).unwrap_err();
    assert_eq!(err, KeyError::UnsupportedAlgorithm("1.3.101.110".into()));
}

#[test]
fn import_still_rejects_certificate_pem() {
    let err = import(&fixture("x509/p256-selfsigned.pem"), None).unwrap_err();
    assert_eq!(err, KeyError::UnsupportedPemLabel("CERTIFICATE".into()));
}
