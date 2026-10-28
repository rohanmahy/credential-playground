//! Sig_structure, signing, and verification (RFC 9052 §4.4, RFC 8392 A.3,
//! RFC 9052 C.2.1, RFC 9964 A.2).

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::borrow::Cow;

use common::*;
use tokenator_cose::{
    Alg, CoseError, DeclaredAlg, Part, Sign1Backend, Sign1Parts, SignOptions, VerifyOptions,
};
use tokenator_crypto::CryptoError;

fn parts<'a>(protected: &[u8], payload: Option<&[u8]>) -> Sign1Parts<'a> {
    Sign1Parts {
        tags: vec![18],
        protected: Cow::Owned(protected.to_vec()),
        unprotected: map(vec![]),
        payload: payload.map(|p| Cow::Owned(p.to_vec())),
        signature: Cow::Borrowed(&[]),
    }
}

fn alg_header(alg: Alg) -> Vec<u8> {
    enc(&map(vec![(
        int(1),
        int(tokenator_crypto::alg_to_cose(alg)),
    )]))
}

#[test]
fn sig_structure_matches_rfc9964() {
    for n in [44, 65, 87] {
        let v = rfc9964(n);
        let bytes = hexs(&v["sign1"]);
        let msg = B.parse(&bytes).unwrap();
        let tbs = B.sig_structure(
            &msg.protected.as_ref().unwrap().raw,
            b"",
            msg.payload_bytes().unwrap(),
        );
        assert_eq!(tbs, hexs(&v["raw_to_be_signed"]), "ML-DSA-{n}");
    }
}

#[test]
fn sig_structure_layout() {
    // ["Signature1", h'a10126', h'', <<A.1 claims>>]
    let claims = token(RFC8392_A1);
    let mut want = h("84 6a 5369676e617475726531 43a10126 40 5850");
    want.extend(&claims);
    assert_eq!(B.sig_structure(&h("a10126"), b"", &claims), want);

    // External AAD and an empty protected header.
    assert_eq!(
        B.sig_structure(b"", b"aad", b""),
        h("84 6a 5369676e617475726531 40 43616164 40")
    );
}

#[test]
fn sig_structure_uses_preferred_heads() {
    let payload = vec![0u8; 300];
    let tbs = B.sig_structure(b"", b"", &payload);
    assert_eq!(&tbs[..14], h("84 6a 5369676e617475726531 40 40"));
    assert_eq!(&tbs[14..17], h("59012c"));
    assert_eq!(tbs.len(), 17 + 300);
}

#[test]
fn verify_rfc8392_a3_all_wrappings() {
    let key = rfc8392_key();
    for name in [RFC8392_A3, RFC8392_A3_UNTAGGED, RFC8392_A3_TAG61] {
        let bytes = token(name);
        let msg = B.parse(&bytes).unwrap();
        assert_eq!(
            B.verify(&msg, &key, &VerifyOptions::default()),
            Ok(Alg::ES256),
            "{name}"
        );
        // The public half alone verifies too.
        assert_eq!(
            B.verify(&msg, &public(&key), &VerifyOptions::default()),
            Ok(Alg::ES256)
        );
    }
}

#[test]
fn verify_rfc9052_c21() {
    let bytes = token(RFC9052_C21);
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(
        B.verify(&msg, &rfc9052_key_11(), &VerifyOptions::default()),
        Ok(Alg::ES256)
    );
    // The wrong P-256 key fails.
    assert_eq!(
        B.verify(&msg, &rfc8392_key(), &VerifyOptions::default()),
        Err(CoseError::InvalidSignature)
    );
}

#[test]
fn verify_rfc9964() {
    for (n, alg) in [(44, Alg::MlDsa44), (65, Alg::MlDsa65), (87, Alg::MlDsa87)] {
        let v = rfc9964(n);
        let bytes = hexs(&v["sign1"]);
        let msg = B.parse(&bytes).unwrap();
        assert_eq!(
            B.verify(&msg, &rfc9964_key(n), &VerifyOptions::default()),
            Ok(alg)
        );
    }
}

#[test]
fn deterministic_ml_dsa_reproduces_rfc9964() {
    for (n, alg) in [(44, Alg::MlDsa44), (65, Alg::MlDsa65), (87, Alg::MlDsa87)] {
        let v = rfc9964(n);
        let bytes = hexs(&v["sign1"]);
        let msg = B.parse(&bytes).unwrap();
        let p = Sign1Parts::from_sign1(&msg).unwrap();
        let out = B
            .sign(&p, &rfc9964_key(n), &SignOptions::new(alg), None)
            .unwrap();
        assert_eq!(out, bytes, "ML-DSA-{n}");
    }
}

#[test]
fn parts_from_sign1_borrow_and_reassemble() {
    for name in [
        RFC8392_A3,
        RFC8392_A3_UNTAGGED,
        RFC8392_A3_TAG61,
        RFC9052_C21,
        SD_ISSUER,
        SD_KBT,
    ] {
        let bytes = token(name);
        let msg = B.parse(&bytes).unwrap();
        let p = Sign1Parts::from_sign1(&msg).unwrap();
        assert!(matches!(p.protected, Cow::Borrowed(_)));
        assert_eq!(B.assemble(&p), bytes, "{name}");
    }
}

#[test]
fn parts_from_malformed_sign1() {
    let bytes = h("83 43a10126 a0 40");
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(
        Sign1Parts::from_sign1(&msg).unwrap_err(),
        CoseError::MalformedPart(Part::Signature)
    );
    let bytes = h("84 01 a0 40 40");
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(
        Sign1Parts::from_sign1(&msg).unwrap_err(),
        CoseError::MalformedPart(Part::Protected)
    );
}

#[test]
fn assemble_detached_and_tags() {
    let mut p = parts(&h("a10126"), None);
    p.tags = vec![61, 18];
    p.signature = Cow::Owned(vec![1, 2]);
    assert_eq!(B.assemble(&p), h("d83d d2 84 43a10126 a0 f6 420102"));
    p.tags.clear();
    assert_eq!(B.assemble(&p), h("84 43a10126 a0 f6 420102"));
}

#[test]
fn sign_and_verify_every_alg() {
    for alg in Alg::ALL {
        let key = key_for(alg, 1);
        let p = parts(&alg_header(alg), Some(b"hello"));
        let mut r = rng(7);
        let out = B
            .sign(&p, &key, &SignOptions::new(alg), Some(&mut r))
            .unwrap();
        let msg = B.parse(&out).unwrap();
        assert_eq!(msg.tags, [18]);
        assert_eq!(msg.alg(), Some(DeclaredAlg::Known(alg)));
        assert_eq!(
            B.verify(&msg, &public(&key), &VerifyOptions::default()),
            Ok(alg),
            "{alg:?}"
        );
        if let Some(len) = alg.fixed_signature_len() {
            assert_eq!(msg.signature.as_ref().unwrap().raw.len(), len, "{alg:?}");
        }

        // A different payload under the same signature fails.
        let mut forged = Sign1Parts::from_sign1(&msg).unwrap();
        forged.payload = Some(Cow::Borrowed(b"hellO"));
        let forged = B.assemble(&forged);
        assert_eq!(
            B.verify(&B.parse(&forged).unwrap(), &key, &VerifyOptions::default()),
            Err(CoseError::InvalidSignature),
            "{alg:?}"
        );
    }
}

#[test]
fn deterministic_signing_is_reproducible() {
    for alg in [Alg::ES256, Alg::Ed25519, Alg::RS256, Alg::MlDsa44] {
        let key = key_for(alg, 3);
        let p = parts(&alg_header(alg), Some(b"x"));
        let a = B.sign(&p, &key, &SignOptions::new(alg), None).unwrap();
        let b = B.sign(&p, &key, &SignOptions::new(alg), None).unwrap();
        assert_eq!(a, b, "{alg:?}");
    }
    // Seeded randomized signing is reproducible as well.
    let key = key_for(Alg::PS256, 1);
    let p = parts(&alg_header(Alg::PS256), Some(b"x"));
    let a = B
        .sign(&p, &key, &SignOptions::new(Alg::PS256), Some(&mut rng(9)))
        .unwrap();
    let b = B
        .sign(&p, &key, &SignOptions::new(Alg::PS256), Some(&mut rng(9)))
        .unwrap();
    assert_eq!(a, b);
}

#[test]
fn pss_needs_randomness() {
    let key = key_for(Alg::PS256, 1);
    let p = parts(&alg_header(Alg::PS256), Some(b"x"));
    assert_eq!(
        B.sign(&p, &key, &SignOptions::new(Alg::PS256), None),
        Err(CoseError::Crypto(CryptoError::RandomnessRequired(
            Alg::PS256
        )))
    );
}

#[test]
fn sign_errors() {
    let p = parts(&alg_header(Alg::ES384), Some(b"x"));
    let p256 = key_for(Alg::ES256, 1);
    assert!(matches!(
        B.sign(&p, &p256, &SignOptions::new(Alg::ES384), None),
        Err(CoseError::KeyNotSuitable {
            alg: Alg::ES384,
            ..
        })
    ));
    assert_eq!(
        B.sign(&p, &public(&p256), &SignOptions::new(Alg::ES256), None),
        Err(CoseError::NoPrivateKey)
    );
    // Detached parts need the payload.
    let p = parts(&alg_header(Alg::ES256), None);
    assert_eq!(
        B.sign(&p, &p256, &SignOptions::new(Alg::ES256), None),
        Err(CoseError::DetachedPayload)
    );
}

#[test]
fn sign_ignores_header_alg() {
    // The header says ES384 but the signature is ES256: a mismatch on purpose.
    let key = key_for(Alg::ES256, 1);
    let p = parts(&alg_header(Alg::ES384), Some(b"x"));
    let out = B
        .sign(&p, &key, &SignOptions::new(Alg::ES256), None)
        .unwrap();
    let msg = B.parse(&out).unwrap();
    assert!(matches!(
        B.verify(&msg, &key, &VerifyOptions::default()),
        Err(CoseError::KeyNotSuitable {
            alg: Alg::ES384,
            ..
        })
    ));
    let opts = VerifyOptions {
        alg: Some(Alg::ES256),
        ..VerifyOptions::default()
    };
    assert_eq!(B.verify(&msg, &key, &opts), Ok(Alg::ES256));
}

#[test]
fn verify_errors() {
    let key = key_for(Alg::ES256, 1);
    // No alg.
    let p = parts(b"", Some(b"x"));
    let out = B
        .sign(&p, &key, &SignOptions::new(Alg::ES256), None)
        .unwrap();
    let msg = B.parse(&out).unwrap();
    assert_eq!(
        B.verify(&msg, &key, &VerifyOptions::default()),
        Err(CoseError::MissingAlg)
    );
    // Unsupported alg.
    let prot = enc(&map(vec![(int(1), int(-999))]));
    let out = B
        .sign(
            &parts(&prot, Some(b"x")),
            &key,
            &SignOptions::new(Alg::ES256),
            None,
        )
        .unwrap();
    let msg = B.parse(&out).unwrap();
    assert_eq!(
        B.verify(&msg, &key, &VerifyOptions::default()),
        Err(CoseError::UnsupportedAlg(DeclaredAlg::UnknownCose(-999)))
    );
    // Wrong key type.
    let bytes = token(RFC8392_A3);
    let msg = B.parse(&bytes).unwrap();
    assert!(matches!(
        B.verify(&msg, &key_for(Alg::Ed25519, 1), &VerifyOptions::default()),
        Err(CoseError::KeyNotSuitable {
            alg: Alg::ES256,
            ..
        })
    ));
    // Missing signature element.
    let bytes = h("83 43a10126 a0 40");
    let msg = B.parse(&bytes).unwrap();
    assert_eq!(
        B.verify(&msg, &key, &VerifyOptions::default()),
        Err(CoseError::MalformedPart(Part::Signature))
    );
}

#[test]
fn external_aad() {
    let key = key_for(Alg::Ed25519, 1);
    let p = parts(&alg_header(Alg::Ed25519), Some(b"x"));
    let opts = SignOptions {
        external_aad: b"context",
        ..SignOptions::new(Alg::Ed25519)
    };
    let out = B.sign(&p, &key, &opts, None).unwrap();
    let msg = B.parse(&out).unwrap();
    assert_eq!(
        B.verify(&msg, &key, &VerifyOptions::default()),
        Err(CoseError::InvalidSignature)
    );
    let v = VerifyOptions {
        external_aad: b"context",
        ..VerifyOptions::default()
    };
    assert_eq!(B.verify(&msg, &key, &v), Ok(Alg::Ed25519));
    let v = VerifyOptions {
        external_aad: b"Context",
        ..VerifyOptions::default()
    };
    assert_eq!(B.verify(&msg, &key, &v), Err(CoseError::InvalidSignature));
}

#[test]
fn detached_payload_sign_verify() {
    let key = key_for(Alg::ES256, 2);
    let p = parts(&alg_header(Alg::ES256), None);
    let opts = SignOptions {
        detached_payload: Some(b"detached"),
        ..SignOptions::new(Alg::ES256)
    };
    let out = B.sign(&p, &key, &opts, None).unwrap();
    let msg = B.parse(&out).unwrap();
    assert!(matches!(
        msg.payload,
        tokenator_cose::Payload::Detached { .. }
    ));
    assert_eq!(
        B.verify(&msg, &key, &VerifyOptions::default()),
        Err(CoseError::DetachedPayload)
    );
    let ok = VerifyOptions {
        detached_payload: Some(b"detached"),
        ..VerifyOptions::default()
    };
    assert_eq!(B.verify(&msg, &key, &ok), Ok(Alg::ES256));
    let bad = VerifyOptions {
        detached_payload: Some(b"Detached"),
        ..VerifyOptions::default()
    };
    assert_eq!(B.verify(&msg, &key, &bad), Err(CoseError::InvalidSignature));

    // Same signature as an attached message over the same payload.
    let attached = B.assemble(&Sign1Parts {
        payload: Some(Cow::Borrowed(b"detached")),
        ..Sign1Parts::from_sign1(&msg).unwrap()
    });
    assert_eq!(
        B.verify(
            &B.parse(&attached).unwrap(),
            &key,
            &VerifyOptions::default()
        ),
        Ok(Alg::ES256)
    );
}

#[test]
fn signing_keeps_parts_verbatim() {
    let key = key_for(Alg::Ed25519, 1);
    // A protected header with a non-preferred integer: {1: -8 as 0x38 0x07}
    let prot = h("a1 01 3807");
    let mut p = parts(&prot, Some(&h("a1 01 1801")));
    p.tags = vec![61, 18];
    p.unprotected = map(vec![(int(4), bs(b"kid"))]);
    let out = B
        .sign(&p, &key, &SignOptions::new(Alg::EdDSA), None)
        .unwrap();
    let msg = B.parse(&out).unwrap();
    assert_eq!(msg.tags, [61, 18]);
    assert_eq!(&msg.protected.as_ref().unwrap().raw[..], prot);
    assert_eq!(msg.payload_bytes(), Some(&h("a1 01 1801")[..]));
    assert_eq!(msg.kid(), Some(&b"kid"[..]));
    assert_eq!(
        B.verify(&msg, &key, &VerifyOptions::default()),
        Ok(Alg::EdDSA)
    );
}
