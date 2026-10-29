//! Key panel DTOs. Keys cross the boundary as serialized bytes ([`KeyRef`]);
//! every call re-imports them.

use serde::{Deserialize, Serialize};

use super::common::{Bytes, HashName, KidValue};

/// A key as the UI holds it: serialized bytes plus workspace metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
pub struct KeyRef {
    /// JWK, JWK Set, COSE_Key, COSE_KeySet, or PEM bytes.
    pub bytes: Bytes,
    /// Format hint; detected when absent.
    #[serde(default)]
    pub format: Option<KeyFormat>,
    /// Which key of a set (0 for a single key).
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<u32>", optional))]
    pub index: u32,
    /// Workspace role (never serialized into key formats).
    #[serde(default)]
    pub role: Option<Role>,
    /// The UI's name for the key card, echoed in validation reports.
    #[serde(default)]
    pub label: Option<String>,
}

impl KeyRef {
    /// A key reference with no hint, index 0, no role, no label.
    pub fn new(bytes: impl Into<Bytes>) -> KeyRef {
        KeyRef {
            bytes: bytes.into(),
            format: None,
            index: 0,
            role: None,
            label: None,
        }
    }
}

/// Key serializations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeyFormat {
    /// A JWK.
    Jwk,
    /// A JWK Set.
    JwkSet,
    /// A COSE_Key (binary CBOR).
    CoseKey,
    /// A COSE_KeySet (binary CBOR).
    CoseKeySet,
    /// PEM.
    Pem {
        /// The DER structure (export only; import reads the label).
        encoding: PemEncoding,
    },
}

/// PEM structures (`tokenator_keys::PemEncoding`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum PemEncoding {
    /// SPKI for public, PKCS#8 for private.
    #[default]
    Auto,
    /// SPKI `PUBLIC KEY`.
    Spki,
    /// PKCS#8 `PRIVATE KEY`.
    Pkcs8,
    /// PKCS#8, ML-DSA seed form.
    Pkcs8MlDsaSeed,
    /// PKCS#8, ML-DSA expanded form.
    Pkcs8MlDsaExpanded,
    /// PKCS#8, ML-DSA both form.
    Pkcs8MlDsaBoth,
    /// SEC1 `EC PRIVATE KEY`.
    Sec1,
    /// PKCS#1 `RSA PRIVATE KEY` / `RSA PUBLIC KEY`.
    Pkcs1,
}

/// Workspace role of a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Signs credentials.
    Issuer,
    /// Holds credentials, signs key binding.
    Holder,
    /// Verifies.
    Verifier,
}

/// Public or private export.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    /// Public parameters only.
    Public,
    /// Public and private parameters.
    Private,
}

/// A key card.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct KeyInfo {
    /// A self-contained reference to this one key (private when
    /// available): a JWK, or a COSE_Key when the kid is binary (so it stays
    /// binary), or PKCS#8 PEM for an ML-DSA key known only by its expanded
    /// private key (neither JWK nor COSE_Key can hold that).
    pub key: KeyRef,
    /// JWK `kty`: `EC`, `OKP`, `RSA`, `AKP`.
    pub kty: String,
    /// JWK curve name (`P-256`, `Ed25519`).
    pub crv: Option<String>,
    /// RSA modulus size.
    pub bits: Option<u32>,
    /// ML-DSA parameter set (`ML-DSA-44`).
    pub param_set: Option<String>,
    /// `EC P-256`, `RSA 2048`, `ML-DSA-65`, `Ed25519`.
    pub description: String,
    /// Has private material.
    pub private: bool,
    /// The kid.
    pub kid: Option<KidValue>,
    /// Declared `alg` (JOSE name, or the COSE label as text if unknown).
    pub alg: Option<String>,
    /// JOSE names of the algorithms this key can be used with.
    pub algs: Vec<String>,
    /// The role from the [`KeyRef`].
    pub role: Option<Role>,
    /// RFC 7638 SHA-256 thumbprint, base64url.
    pub jwk_thumbprint: String,
    /// RFC 9278 URI of it.
    pub jwk_thumbprint_uri: String,
    /// RFC 9679 SHA-256 thumbprint, hex.
    pub cose_thumbprint: String,
    /// RFC 9679 §5.7 URI of it.
    pub cose_thumbprint_uri: String,
}

/// Input of [`Engine::key_import`](crate::Engine::key_import).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
pub struct KeyImportRequest {
    /// The bytes.
    pub bytes: Bytes,
    /// Format hint.
    #[serde(default)]
    pub format: Option<KeyFormat>,
}

/// Input of [`Engine::key_export`](crate::Engine::key_export).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct KeyExportRequest {
    /// The key.
    pub key: KeyRef,
    /// Target format.
    pub format: KeyFormat,
    /// Public or private (private needs an explicit choice).
    pub visibility: Visibility,
}

/// An exported key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct KeyExport {
    /// The bytes.
    pub bytes: Bytes,
    /// The same as text, for text formats (JWK, PEM).
    pub text: Option<String>,
    /// Contains private material (label the clipboard copy).
    pub private: bool,
}

/// Input of [`Engine::key_generate`](crate::Engine::key_generate).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
pub struct KeyGenRequest {
    /// Key type.
    pub spec: KeySpec,
    /// Role for the card.
    #[serde(default)]
    pub role: Option<Role>,
    /// Where the randomness comes from.
    pub seed: KeySeed,
    /// Set a kid right away.
    #[serde(default)]
    pub kid: Option<KidSource>,
}

/// Key types the panel can create.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeySpec {
    /// EC P-256.
    P256,
    /// EC P-384.
    P384,
    /// EC P-521.
    P521,
    /// Ed25519.
    Ed25519,
    /// RSA (2048, 3072, 4096).
    Rsa {
        /// Modulus size.
        bits: u32,
    },
    /// ML-DSA-44.
    MlDsa44,
    /// ML-DSA-65.
    MlDsa65,
    /// ML-DSA-87.
    MlDsa87,
}

/// Randomness for key generation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeySeed {
    /// The well-known test seed (32 zero bytes,
    /// `tokenator_keys::WELL_KNOWN_TEST_SEED`).
    WellKnown,
    /// Deterministic from this seed (32 bytes used as is; other lengths are
    /// hashed with SHA-256), as `tokenator_keys::generate` defines.
    Seed {
        /// The seed.
        bytes: Bytes,
    },
    /// Fresh randomness from the platform: exactly 32 bytes seeding a
    /// ChaCha20 RNG.
    Entropy {
        /// The entropy.
        bytes: Bytes,
    },
}

/// Where a kid comes from.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KidSource {
    /// The base64url JWK thumbprint, as a text kid.
    JwkThumbprint {
        /// Hash.
        hash: HashName,
    },
    /// The raw COSE thumbprint, as a binary kid.
    CoseThumbprint {
        /// Hash.
        hash: HashName,
    },
    /// A user string.
    Text {
        /// The kid.
        value: String,
    },
    /// User bytes.
    Bytes {
        /// The kid.
        value: Bytes,
    },
}

/// Input of [`Engine::key_thumbprint`](crate::Engine::key_thumbprint).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
pub struct ThumbprintRequest {
    /// The key.
    pub key: KeyRef,
    /// JWK (RFC 7638) or COSE (RFC 9679).
    pub kind: ThumbprintKind,
    /// Hash.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<HashName>", optional))]
    pub hash: HashName,
}

/// Thumbprint kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum ThumbprintKind {
    /// RFC 7638.
    Jwk,
    /// RFC 9679.
    Cose,
}

/// A thumbprint in every form the panel shows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Thumbprint {
    /// Kind.
    pub kind: ThumbprintKind,
    /// Hash.
    pub hash: HashName,
    /// Lowercase hex.
    pub hex: String,
    /// Unpadded base64url.
    pub base64url: String,
    /// RFC 9278 (JWK) or RFC 9679 §5.7 (COSE) URI.
    pub uri: String,
}

/// Input of [`Engine::key_assign_kid`](crate::Engine::key_assign_kid).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct AssignKidRequest {
    /// The key.
    pub key: KeyRef,
    /// The new kid.
    pub source: KidSource,
}

/// Input of [`Engine::key_to_jwk`](crate::Engine::key_to_jwk) and
/// [`Engine::key_to_cwk`](crate::Engine::key_to_cwk).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct KeyConvertRequest {
    /// The key.
    pub key: KeyRef,
    /// Public or private.
    pub visibility: Visibility,
}
