//! JOSE names / COSE labels for algorithms, curves, key types, and hashes.
//! Expected values are from the IANA JOSE and COSE registries (see TEST-PLAN.md).

// Test crate: panicking helpers are intended.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use tokenator_crypto::{
    Alg, Curve, HashAlg, KeyType, MlDsaParams, alg_from_cose, alg_from_jose, alg_to_cose,
    alg_to_jose,
};

/// (alg, JOSE name, COSE label)
const ALG_TABLE: [(Alg, &str, i64); 14] = [
    (Alg::ES256, "ES256", -7),
    (Alg::ES384, "ES384", -35),
    (Alg::ES512, "ES512", -36),
    (Alg::EdDSA, "EdDSA", -8),
    (Alg::Ed25519, "Ed25519", -19),
    (Alg::RS256, "RS256", -257),
    (Alg::RS384, "RS384", -258),
    (Alg::RS512, "RS512", -259),
    (Alg::PS256, "PS256", -37),
    (Alg::PS384, "PS384", -38),
    (Alg::PS512, "PS512", -39),
    (Alg::MlDsa44, "ML-DSA-44", -48),
    (Alg::MlDsa65, "ML-DSA-65", -49),
    (Alg::MlDsa87, "ML-DSA-87", -50),
];

#[test]
fn all_lists_every_alg_once_in_declaration_order() {
    let from_table: Vec<Alg> = ALG_TABLE.iter().map(|(a, _, _)| *a).collect();
    assert_eq!(Alg::ALL.to_vec(), from_table);
}

#[test]
fn jose_names_match_iana() {
    for (alg, name, _) in ALG_TABLE {
        assert_eq!(alg_to_jose(alg), name, "{alg:?}");
        assert_eq!(alg_from_jose(name), Some(alg), "{name}");
    }
}

#[test]
fn cose_labels_match_iana() {
    for (alg, _, label) in ALG_TABLE {
        assert_eq!(alg_to_cose(alg), label, "{alg:?}");
        assert_eq!(alg_from_cose(label), Some(alg), "{label}");
    }
}

#[test]
fn jose_and_cose_round_trip_for_every_alg() {
    for alg in Alg::ALL {
        assert_eq!(alg_from_jose(alg_to_jose(alg)), Some(alg));
        assert_eq!(alg_from_cose(alg_to_cose(alg)), Some(alg));
    }
}

#[test]
fn jose_names_are_case_sensitive() {
    for name in [
        "es256",
        "Es256",
        "eddsa",
        "EDDSA",
        "ed25519",
        "ml-dsa-44",
        "ML-DSA44",
        "MLDSA44",
        "ps256",
    ] {
        assert_eq!(alg_from_jose(name), None, "{name}");
    }
}

#[test]
fn unsupported_jose_names_are_none() {
    // `none`, MACs, Ed448, secp256k1, COSE-only fully-specified ECDSA names, junk.
    for name in [
        "", "none", "HS256", "HS384", "HS512", "Ed448", "ES256K", "ESP256", "ESP384", "ESP512",
        " ES256", "ES256 ",
    ] {
        assert_eq!(alg_from_jose(name), None, "{name:?}");
    }
}

#[test]
fn unsupported_cose_labels_are_none() {
    // 0 reserved; -9/-51/-52 ESP256/384/512 (RFC 9864, not in v1 scope);
    // -47 ES256K; -53 Ed448; -16 SHA-256 is a hash, not a signature alg;
    // 5 is HMAC 256/256; -65537 private use.
    for label in [
        0,
        1,
        -1,
        -9,
        -51,
        -52,
        -47,
        -53,
        -16,
        -43,
        -44,
        5,
        -65537,
        i64::MIN,
        i64::MAX,
    ] {
        assert_eq!(alg_from_cose(label), None, "{label}");
    }
}

#[test]
fn eddsa_and_ed25519_are_distinct_identifiers() {
    assert_ne!(alg_to_jose(Alg::EdDSA), alg_to_jose(Alg::Ed25519));
    assert_ne!(alg_to_cose(Alg::EdDSA), alg_to_cose(Alg::Ed25519));
}

#[test]
fn fixed_signature_lengths() {
    let expected: [(Alg, Option<usize>); 14] = [
        (Alg::ES256, Some(64)),
        (Alg::ES384, Some(96)),
        (Alg::ES512, Some(132)),
        (Alg::EdDSA, Some(64)),
        (Alg::Ed25519, Some(64)),
        (Alg::RS256, None),
        (Alg::RS384, None),
        (Alg::RS512, None),
        (Alg::PS256, None),
        (Alg::PS384, None),
        (Alg::PS512, None),
        (Alg::MlDsa44, Some(2420)),
        (Alg::MlDsa65, Some(3309)),
        (Alg::MlDsa87, Some(4627)),
    ];
    for (alg, len) in expected {
        assert_eq!(alg.fixed_signature_len(), len, "{alg:?}");
    }
}

#[test]
fn curves_match_iana() {
    // (curve, JWK crv, COSE crv, kty, field length)
    let table = [
        (Curve::P256, "P-256", 1, KeyType::Ec, 32),
        (Curve::P384, "P-384", 2, KeyType::Ec, 48),
        (Curve::P521, "P-521", 3, KeyType::Ec, 66),
        (Curve::Ed25519, "Ed25519", 6, KeyType::Okp, 32),
    ];
    for (crv, name, label, kty, len) in table {
        assert_eq!(crv.jwk_name(), name);
        assert_eq!(crv.cose_label(), label);
        assert_eq!(crv.key_type(), kty);
        assert_eq!(crv.field_len(), len);
        assert_eq!(Curve::from_jwk_name(name), Some(crv));
        assert_eq!(Curve::from_cose_label(label), Some(crv));
    }
}

#[test]
fn unsupported_curves_are_none() {
    for name in [
        "",
        "p-256",
        "P256",
        "secp256r1",
        "X25519",
        "Ed448",
        "X448",
        "secp256k1",
        "brainpoolP256r1",
    ] {
        assert_eq!(Curve::from_jwk_name(name), None, "{name}");
    }
    // 4 X25519, 5 X448, 7 Ed448, 8 secp256k1, 256 brainpoolP256r1.
    for label in [0, 4, 5, 7, 8, 256, -1] {
        assert_eq!(Curve::from_cose_label(label), None, "{label}");
    }
}

#[test]
fn key_types_match_iana() {
    let table = [
        (KeyType::Ec, "EC", 2),
        (KeyType::Okp, "OKP", 1),
        (KeyType::Rsa, "RSA", 3),
        (KeyType::Akp, "AKP", 7),
    ];
    for (kty, jwk, cose) in table {
        assert_eq!(kty.jwk_kty(), jwk);
        assert_eq!(kty.cose_kty(), cose);
        assert_eq!(KeyType::from_jwk_kty(jwk), Some(kty));
        assert_eq!(KeyType::from_cose_kty(cose), Some(kty));
    }
}

#[test]
fn unsupported_key_types_are_none() {
    // JOSE "oct"; COSE uses "EC2" only as a display name, the JWK value is "EC".
    for kty in ["", "oct", "EC2", "ec", "rsa", "akp", "okp"] {
        assert_eq!(KeyType::from_jwk_kty(kty), None, "{kty}");
    }
    // 0 reserved, 4 Symmetric, 5 HSS-LMS, 6 WalnutDSA.
    for kty in [0, 4, 5, 6, 8, -1] {
        assert_eq!(KeyType::from_cose_kty(kty), None, "{kty}");
    }
}

#[test]
fn ml_dsa_parameter_sizes_match_fips_204() {
    // FIPS 204 Table 2: public key, private key (expanded), signature sizes.
    let table = [
        (MlDsaParams::MlDsa44, Alg::MlDsa44, 1312, 2560, 2420),
        (MlDsaParams::MlDsa65, Alg::MlDsa65, 1952, 4032, 3309),
        (MlDsaParams::MlDsa87, Alg::MlDsa87, 2592, 4896, 4627),
    ];
    for (p, alg, pk, sk, sig) in table {
        assert_eq!(p.alg(), alg);
        assert_eq!(p.public_key_len(), pk, "{p:?}");
        assert_eq!(p.expanded_private_key_len(), sk, "{p:?}");
        assert_eq!(p.signature_len(), sig, "{p:?}");
        assert_eq!(alg.fixed_signature_len(), Some(sig));
    }
    assert_eq!(MlDsaParams::SEED_LEN, 32);
}

#[test]
fn hash_algs_names_labels_and_lengths() {
    // IANA Named Information names (used by _sd_alg) and COSE algorithm labels.
    let table = [
        (HashAlg::Sha256, "sha-256", -16, 32),
        (HashAlg::Sha384, "sha-384", -43, 48),
        (HashAlg::Sha512, "sha-512", -44, 64),
    ];
    for (h, name, label, len) in table {
        assert_eq!(h.name(), name);
        assert_eq!(h.cose_label(), label);
        assert_eq!(h.output_len(), len);
        assert_eq!(HashAlg::from_name(name), Some(h));
        assert_eq!(HashAlg::from_cose_label(label), Some(h));
    }
    for name in ["", "SHA-256", "sha256", "sha-256-128", "sha-1", "sha3-256"] {
        assert_eq!(HashAlg::from_name(name), None, "{name}");
    }
    for label in [0, -14, -15, -17, -18, -45, -7] {
        assert_eq!(HashAlg::from_cose_label(label), None, "{label}");
    }
}
