//! Algorithm, hash, curve, and key-type identifiers with their JOSE names and
//! COSE labels. Codepoints are listed (with sources) in `TEST-PLAN.md`.

// Skeleton: bodies are filled in by the implementation.
#![allow(unused_variables, clippy::unimplemented)]

/// A signature algorithm supported for both signing and verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Alg {
    /// ECDSA with P-256 and SHA-256.
    ES256,
    /// ECDSA with P-384 and SHA-384.
    ES384,
    /// ECDSA with P-521 and SHA-512.
    ES512,
    /// Polymorphic EdDSA (deprecated by RFC 9864); only Ed25519 keys are supported.
    EdDSA,
    /// Fully-specified Ed25519 (RFC 9864).
    Ed25519,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RS256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RS384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    RS512,
    /// RSASSA-PSS with SHA-256, MGF1-SHA-256, 32-byte salt.
    PS256,
    /// RSASSA-PSS with SHA-384, MGF1-SHA-384, 48-byte salt.
    PS384,
    /// RSASSA-PSS with SHA-512, MGF1-SHA-512, 64-byte salt.
    PS512,
    /// ML-DSA-44 (FIPS 204, pure, empty context; RFC 9964).
    MlDsa44,
    /// ML-DSA-65 (FIPS 204, pure, empty context; RFC 9964).
    MlDsa65,
    /// ML-DSA-87 (FIPS 204, pure, empty context; RFC 9964).
    MlDsa87,
}

impl Alg {
    /// Every supported algorithm, in declaration order.
    pub const ALL: [Alg; 14] = [
        Alg::ES256,
        Alg::ES384,
        Alg::ES512,
        Alg::EdDSA,
        Alg::Ed25519,
        Alg::RS256,
        Alg::RS384,
        Alg::RS512,
        Alg::PS256,
        Alg::PS384,
        Alg::PS512,
        Alg::MlDsa44,
        Alg::MlDsa65,
        Alg::MlDsa87,
    ];

    /// The signature length in bytes when it does not depend on the key
    /// (`None` for RSA, whose signatures are as long as the modulus).
    pub fn fixed_signature_len(self) -> Option<usize> {
        unimplemented!()
    }
}

/// Maps a JOSE `alg` name (case-sensitive) to an [`Alg`].
pub fn alg_from_jose(name: &str) -> Option<Alg> {
    unimplemented!()
}

/// Maps a COSE algorithm label to an [`Alg`].
pub fn alg_from_cose(label: i64) -> Option<Alg> {
    unimplemented!()
}

/// The JOSE `alg` name of `alg`.
pub fn alg_to_jose(alg: Alg) -> &'static str {
    unimplemented!()
}

/// The COSE algorithm label of `alg`.
pub fn alg_to_cose(alg: Alg) -> i64 {
    unimplemented!()
}

/// A hash algorithm, used by [`digest`](crate::digest) and for SD digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlg {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlg {
    /// Digest length in bytes.
    pub fn output_len(self) -> usize {
        unimplemented!()
    }

    /// The IANA Named Information name (`sha-256`, ...), as used by `_sd_alg`.
    pub fn name(self) -> &'static str {
        unimplemented!()
    }

    /// Inverse of [`HashAlg::name`] (case-sensitive).
    pub fn from_name(name: &str) -> Option<HashAlg> {
        unimplemented!()
    }

    /// The COSE algorithm label (`-16`, `-43`, `-44`).
    pub fn cose_label(self) -> i64 {
        unimplemented!()
    }

    /// Inverse of [`HashAlg::cose_label`].
    pub fn from_cose_label(label: i64) -> Option<HashAlg> {
        unimplemented!()
    }
}

/// A curve: the `crv` of an EC2/EC or OKP key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Curve {
    /// NIST P-256.
    P256,
    /// NIST P-384.
    P384,
    /// NIST P-521.
    P521,
    /// Ed25519 (OKP).
    Ed25519,
}

impl Curve {
    /// The JWK `crv` name.
    pub fn jwk_name(self) -> &'static str {
        unimplemented!()
    }

    /// The COSE `crv` label.
    pub fn cose_label(self) -> i64 {
        unimplemented!()
    }

    /// Inverse of [`Curve::jwk_name`] (case-sensitive).
    pub fn from_jwk_name(name: &str) -> Option<Curve> {
        unimplemented!()
    }

    /// Inverse of [`Curve::cose_label`].
    pub fn from_cose_label(label: i64) -> Option<Curve> {
        unimplemented!()
    }

    /// The key type this curve belongs to.
    pub fn key_type(self) -> KeyType {
        unimplemented!()
    }

    /// Fixed length in bytes of a coordinate / private scalar (`x`, `y`, `d`):
    /// 32, 48, 66, and 32 for Ed25519.
    pub fn field_len(self) -> usize {
        unimplemented!()
    }
}

/// An ML-DSA parameter set (the AKP key's algorithm).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlDsaParams {
    /// ML-DSA-44.
    MlDsa44,
    /// ML-DSA-65.
    MlDsa65,
    /// ML-DSA-87.
    MlDsa87,
}

impl MlDsaParams {
    /// Length of the private seed `xi` (always 32).
    pub const SEED_LEN: usize = 32;

    /// The signature algorithm for this parameter set.
    pub fn alg(self) -> Alg {
        unimplemented!()
    }

    /// Encoded public key length (FIPS 204 Table 2).
    pub fn public_key_len(self) -> usize {
        unimplemented!()
    }

    /// Encoded expanded private key length (FIPS 204 Table 2).
    pub fn expanded_private_key_len(self) -> usize {
        unimplemented!()
    }

    /// Signature length (FIPS 204 Table 2).
    pub fn signature_len(self) -> usize {
        unimplemented!()
    }
}

/// A key type: JWK `kty` / COSE `kty`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyType {
    /// JWK `EC` / COSE `EC2`.
    Ec,
    /// Octet key pair (Ed25519).
    Okp,
    /// RSA.
    Rsa,
    /// Algorithm Key Pair (ML-DSA, RFC 9964).
    Akp,
}

impl KeyType {
    /// The JWK `kty` value.
    pub fn jwk_kty(self) -> &'static str {
        unimplemented!()
    }

    /// The COSE `kty` label.
    pub fn cose_kty(self) -> i64 {
        unimplemented!()
    }

    /// Inverse of [`KeyType::jwk_kty`] (case-sensitive).
    pub fn from_jwk_kty(kty: &str) -> Option<KeyType> {
        unimplemented!()
    }

    /// Inverse of [`KeyType::cose_kty`].
    pub fn from_cose_kty(kty: i64) -> Option<KeyType> {
        unimplemented!()
    }
}
