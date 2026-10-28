//! Algorithm, hash, curve, and key-type identifiers with their JOSE names and
//! COSE labels. Codepoints are listed (with sources) in `TEST-PLAN.md`.

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
        match self {
            Alg::ES256 | Alg::EdDSA | Alg::Ed25519 => Some(64),
            Alg::ES384 => Some(96),
            Alg::ES512 => Some(132),
            Alg::RS256 | Alg::RS384 | Alg::RS512 | Alg::PS256 | Alg::PS384 | Alg::PS512 => None,
            Alg::MlDsa44 => Some(MlDsaParams::MlDsa44.signature_len()),
            Alg::MlDsa65 => Some(MlDsaParams::MlDsa65.signature_len()),
            Alg::MlDsa87 => Some(MlDsaParams::MlDsa87.signature_len()),
        }
    }
}

/// Maps a JOSE `alg` name (case-sensitive) to an [`Alg`].
pub fn alg_from_jose(name: &str) -> Option<Alg> {
    Alg::ALL.into_iter().find(|a| alg_to_jose(*a) == name)
}

/// Maps a COSE algorithm label to an [`Alg`].
pub fn alg_from_cose(label: i64) -> Option<Alg> {
    Alg::ALL.into_iter().find(|a| alg_to_cose(*a) == label)
}

/// The JOSE `alg` name of `alg`.
pub fn alg_to_jose(alg: Alg) -> &'static str {
    match alg {
        Alg::ES256 => "ES256",
        Alg::ES384 => "ES384",
        Alg::ES512 => "ES512",
        Alg::EdDSA => "EdDSA",
        Alg::Ed25519 => "Ed25519",
        Alg::RS256 => "RS256",
        Alg::RS384 => "RS384",
        Alg::RS512 => "RS512",
        Alg::PS256 => "PS256",
        Alg::PS384 => "PS384",
        Alg::PS512 => "PS512",
        Alg::MlDsa44 => "ML-DSA-44",
        Alg::MlDsa65 => "ML-DSA-65",
        Alg::MlDsa87 => "ML-DSA-87",
    }
}

/// The COSE algorithm label of `alg`.
pub fn alg_to_cose(alg: Alg) -> i64 {
    match alg {
        Alg::ES256 => -7,
        Alg::ES384 => -35,
        Alg::ES512 => -36,
        Alg::EdDSA => -8,
        Alg::Ed25519 => -19,
        Alg::RS256 => -257,
        Alg::RS384 => -258,
        Alg::RS512 => -259,
        Alg::PS256 => -37,
        Alg::PS384 => -38,
        Alg::PS512 => -39,
        Alg::MlDsa44 => -48,
        Alg::MlDsa65 => -49,
        Alg::MlDsa87 => -50,
    }
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
    const ALL: [HashAlg; 3] = [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512];

    /// Digest length in bytes.
    pub fn output_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }

    /// The IANA Named Information name (`sha-256`, ...), as used by `_sd_alg`.
    pub fn name(self) -> &'static str {
        match self {
            HashAlg::Sha256 => "sha-256",
            HashAlg::Sha384 => "sha-384",
            HashAlg::Sha512 => "sha-512",
        }
    }

    /// Inverse of [`HashAlg::name`] (case-sensitive).
    pub fn from_name(name: &str) -> Option<HashAlg> {
        HashAlg::ALL.into_iter().find(|h| h.name() == name)
    }

    /// The COSE algorithm label (`-16`, `-43`, `-44`).
    pub fn cose_label(self) -> i64 {
        match self {
            HashAlg::Sha256 => -16,
            HashAlg::Sha384 => -43,
            HashAlg::Sha512 => -44,
        }
    }

    /// Inverse of [`HashAlg::cose_label`].
    pub fn from_cose_label(label: i64) -> Option<HashAlg> {
        HashAlg::ALL.into_iter().find(|h| h.cose_label() == label)
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
    const ALL: [Curve; 4] = [Curve::P256, Curve::P384, Curve::P521, Curve::Ed25519];

    /// The JWK `crv` name.
    pub fn jwk_name(self) -> &'static str {
        match self {
            Curve::P256 => "P-256",
            Curve::P384 => "P-384",
            Curve::P521 => "P-521",
            Curve::Ed25519 => "Ed25519",
        }
    }

    /// The COSE `crv` label.
    pub fn cose_label(self) -> i64 {
        match self {
            Curve::P256 => 1,
            Curve::P384 => 2,
            Curve::P521 => 3,
            Curve::Ed25519 => 6,
        }
    }

    /// Inverse of [`Curve::jwk_name`] (case-sensitive).
    pub fn from_jwk_name(name: &str) -> Option<Curve> {
        Curve::ALL.into_iter().find(|c| c.jwk_name() == name)
    }

    /// Inverse of [`Curve::cose_label`].
    pub fn from_cose_label(label: i64) -> Option<Curve> {
        Curve::ALL.into_iter().find(|c| c.cose_label() == label)
    }

    /// The key type this curve belongs to.
    pub fn key_type(self) -> KeyType {
        match self {
            Curve::P256 | Curve::P384 | Curve::P521 => KeyType::Ec,
            Curve::Ed25519 => KeyType::Okp,
        }
    }

    /// Fixed length in bytes of a coordinate / private scalar (`x`, `y`, `d`):
    /// 32, 48, 66, and 32 for Ed25519.
    pub fn field_len(self) -> usize {
        match self {
            Curve::P256 | Curve::Ed25519 => 32,
            Curve::P384 => 48,
            Curve::P521 => 66,
        }
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
        match self {
            MlDsaParams::MlDsa44 => Alg::MlDsa44,
            MlDsaParams::MlDsa65 => Alg::MlDsa65,
            MlDsaParams::MlDsa87 => Alg::MlDsa87,
        }
    }

    /// Encoded public key length (FIPS 204 Table 2).
    pub fn public_key_len(self) -> usize {
        match self {
            MlDsaParams::MlDsa44 => 1312,
            MlDsaParams::MlDsa65 => 1952,
            MlDsaParams::MlDsa87 => 2592,
        }
    }

    /// Encoded expanded private key length (FIPS 204 Table 2).
    pub fn expanded_private_key_len(self) -> usize {
        match self {
            MlDsaParams::MlDsa44 => 2560,
            MlDsaParams::MlDsa65 => 4032,
            MlDsaParams::MlDsa87 => 4896,
        }
    }

    /// Signature length (FIPS 204 Table 2).
    pub fn signature_len(self) -> usize {
        match self {
            MlDsaParams::MlDsa44 => 2420,
            MlDsaParams::MlDsa65 => 3309,
            MlDsaParams::MlDsa87 => 4627,
        }
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
    const ALL: [KeyType; 4] = [KeyType::Ec, KeyType::Okp, KeyType::Rsa, KeyType::Akp];

    /// The JWK `kty` value.
    pub fn jwk_kty(self) -> &'static str {
        match self {
            KeyType::Ec => "EC",
            KeyType::Okp => "OKP",
            KeyType::Rsa => "RSA",
            KeyType::Akp => "AKP",
        }
    }

    /// The COSE `kty` label.
    pub fn cose_kty(self) -> i64 {
        match self {
            KeyType::Okp => 1,
            KeyType::Ec => 2,
            KeyType::Rsa => 3,
            KeyType::Akp => 7,
        }
    }

    /// Inverse of [`KeyType::jwk_kty`] (case-sensitive).
    pub fn from_jwk_kty(kty: &str) -> Option<KeyType> {
        KeyType::ALL.into_iter().find(|k| k.jwk_kty() == kty)
    }

    /// Inverse of [`KeyType::cose_kty`].
    pub fn from_cose_kty(kty: i64) -> Option<KeyType> {
        KeyType::ALL.into_iter().find(|k| k.cose_kty() == kty)
    }
}
