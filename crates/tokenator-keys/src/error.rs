use core::fmt;

use tokenator_crypto::CryptoError;

use crate::KeyFormat;

/// Errors from parsing, converting, and exporting keys.
///
/// Parsers never panic: every malformed input ends up as one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyError {
    /// The input is not recognizably PEM, JSON (JWK / JWK Set), or CBOR
    /// (COSE_Key / COSE_KeySet), or not the format given as a hint.
    UnrecognizedFormat,
    /// The JSON text is malformed.
    Json(tokenator_json::JsonError),
    /// The CBOR bytes are malformed (including trailing bytes after the item).
    Cbor(tokenator_cbor::DecodeError),
    /// The PEM armor or its base64 body is malformed (RFC 7468).
    Pem(&'static str),
    /// The DER inside a PEM block is malformed or has an unexpected shape.
    Der(&'static str),
    /// A PEM block whose label is not a supported key type (e.g. `CERTIFICATE`).
    UnsupportedPemLabel(String),
    /// An `ENCRYPTED PRIVATE KEY` block. Decryption is not supported.
    EncryptedPrivateKey,
    /// An SPKI / PKCS#8 algorithm OID that is not supported (dotted form,
    /// e.g. `1.3.101.110` for X25519).
    UnsupportedAlgorithm(String),
    /// A curve that is not supported: an unknown JWK `crv` name, COSE `crv`
    /// label, or named-curve OID, or explicit EC domain parameters.
    UnsupportedCurve(String),
    /// A key type that is not supported: the JWK `kty` (e.g. `oct`) or the
    /// COSE `kty` label in decimal (e.g. `4`).
    UnsupportedKeyType(String),
    /// A required parameter is missing. JWK member name, or COSE label in
    /// decimal (e.g. `-2`).
    MissingParameter(String),
    /// A parameter is present but unusable: wrong JSON/CBOR type, bad
    /// base64url, wrong length, or duplicated.
    InvalidParameter {
        /// JWK member name or COSE label in decimal.
        name: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// Parameters that contradict each other: `kty` vs `crv`, an ML-DSA
    /// `alg` vs the length of `pub`, or a private key whose stated public
    /// part (JWK `x`/`y`, COSE -2/-3, AKP `pub`, the SEC1 / PKCS#8 public
    /// key) is not the one derived from the private part.
    InconsistentKey(&'static str),
    /// `tokenator-crypto` rejected the key material.
    Crypto(CryptoError),
    /// A private export was requested for a public key.
    NoPrivateKey,
    /// The format cannot hold this key or visibility (e.g. SEC1 for an RSA
    /// key, SEC1 or PKCS#8 with [`Visibility::Public`](crate::Visibility),
    /// SPKI with [`Visibility::Private`](crate::Visibility)).
    FormatNotApplicable {
        /// The requested format.
        format: KeyFormat,
        /// Why it does not apply.
        reason: &'static str,
    },
    /// An ML-DSA seed-form export was requested but only the expanded
    /// private key is known.
    MlDsaSeedUnknown,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnrecognizedFormat => f.write_str("unrecognized key format"),
            Self::Json(e) => write!(f, "invalid JSON: {e}"),
            Self::Cbor(e) => write!(f, "invalid CBOR: {e}"),
            Self::Pem(why) => write!(f, "invalid PEM: {why}"),
            Self::Der(why) => write!(f, "invalid DER: {why}"),
            Self::UnsupportedPemLabel(label) => write!(f, "unsupported PEM label {label:?}"),
            Self::EncryptedPrivateKey => f.write_str("encrypted private keys are not supported"),
            Self::UnsupportedAlgorithm(oid) => write!(f, "unsupported key algorithm {oid}"),
            Self::UnsupportedCurve(crv) => write!(f, "unsupported curve {crv}"),
            Self::UnsupportedKeyType(kty) => write!(f, "unsupported key type {kty}"),
            Self::MissingParameter(name) => write!(f, "missing key parameter {name}"),
            Self::InvalidParameter { name, reason } => {
                write!(f, "invalid key parameter {name}: {reason}")
            }
            Self::InconsistentKey(why) => write!(f, "inconsistent key: {why}"),
            Self::Crypto(e) => write!(f, "{e}"),
            Self::NoPrivateKey => f.write_str("the key has no private part"),
            Self::FormatNotApplicable { format, reason } => {
                write!(f, "{format:?} cannot be used here: {reason}")
            }
            Self::MlDsaSeedUnknown => f.write_str("the ML-DSA seed is not known"),
        }
    }
}

impl std::error::Error for KeyError {}

impl From<CryptoError> for KeyError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<tokenator_json::JsonError> for KeyError {
    fn from(e: tokenator_json::JsonError) -> Self {
        Self::Json(e)
    }
}

impl From<tokenator_cbor::DecodeError> for KeyError {
    fn from(e: tokenator_cbor::DecodeError) -> Self {
        Self::Cbor(e)
    }
}
