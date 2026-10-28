//! JWK (RFC 7517, RFC 7518 §6, RFC 8037, RFC 9964 §3) conversion.

use tokenator_crypto::{HashAlg, KeyParams};

use crate::{Key, KeyError, Visibility};

/// A JSON Web Key: one JSON object, members in arrival order.
///
/// A `Jwk` is only known to be a JSON object; whether it describes a usable
/// key is checked by [`from_jwk`]. That lets [`params_from_jwk`] and
/// [`jwk_thumbprint`] work on keys with missing or broken material (for
/// example a `cnf` key being linted).
#[derive(Debug, Clone)]
pub struct Jwk {
    node: tokenator_json::Node<'static>,
}

impl Jwk {
    /// Parses JSON text that must be a single object.
    pub fn parse(json: &[u8]) -> Result<Jwk, KeyError> {
        unimplemented!()
    }

    /// Copies an object node, e.g. the `jwk` member of a `cnf` claim.
    pub fn from_node(node: &tokenator_json::Node<'_>) -> Result<Jwk, KeyError> {
        unimplemented!()
    }

    /// The object as a JSON tree.
    pub fn node(&self) -> &tokenator_json::Node<'static> {
        &self.node
    }

    /// Compact JSON text (no whitespace), members in order. Unedited
    /// scalars keep their original lexeme.
    pub fn to_json(&self) -> String {
        unimplemented!()
    }

    /// Member names in order, duplicates included.
    pub fn member_names(&self) -> Vec<&str> {
        unimplemented!()
    }

    /// The value of member `name` if it is a JSON string (the first one, if
    /// duplicated).
    pub fn get_str(&self, name: &str) -> Option<&str> {
        unimplemented!()
    }
}

/// Builds the JWK for `key`.
///
/// Member order: `kty`, `kid`, `alg`, `use`, `key_ops`, then the key
/// parameters (`crv`, `x`, `y`, `d` for EC; `crv`, `x`, `d` for OKP; `n`,
/// `e`, `d`, `p`, `q`, `dp`, `dq`, `qi` for RSA; `pub`, `priv` for AKP),
/// then JOSE [`Extra`](crate::Extra)s in arrival order. Absent metadata is
/// omitted, except that AKP keys always get `alg` (RFC 9964 §3 requires it),
/// taken from the ML-DSA parameter set when the key declares none.
///
/// EC coordinates and scalars are fixed-width ([`Curve::field_len`]); RSA
/// integers have no leading zero bytes; the AKP `priv` is the 32-byte seed
/// (RFC 9964 §4). An ML-DSA private key known only in expanded form has no
/// RFC 9964 private representation, so [`Visibility::Private`] fails with
/// [`KeyError::MlDsaSeedUnknown`].
///
/// [`Curve::field_len`]: tokenator_crypto::Curve::field_len
pub fn to_jwk(key: &Key, visibility: Visibility) -> Result<Jwk, KeyError> {
    unimplemented!()
}

/// Parses a JWK into a key, validating the material with
/// `tokenator-crypto`.
///
/// A private JWK must agree with its own public members (`x`/`y`, RSA `n`/`e`,
/// AKP `pub`), otherwise [`KeyError::InconsistentKey`]. Duplicate members
/// are rejected. Unrecognized members become JOSE extras.
///
/// EC `x`, `y`, and `d` shorter than the field length (an encoder dropped
/// leading zero bytes, which RFC 7518 §6.2.1.2 forbids) are left-padded,
/// as tokenator-crypto expects (#11); longer ones are errors. Ed25519 and
/// AKP values must have exactly the right length.
pub fn from_jwk(jwk: &Jwk) -> Result<Key, KeyError> {
    unimplemented!()
}

/// Describes a JWK without validating its material.
///
/// Needs only a recognized `kty`. Reports `crv` as declared, even when it
/// contradicts `kty` (so the linter can flag it), and `None` for an unknown
/// curve name. RSA size is the bit length of `n` when `n` decodes. The ML-DSA
/// parameter set comes from `alg` when it names one, otherwise from the
/// length of `pub`. `alg` becomes the declared alg.
pub fn params_from_jwk(jwk: &Jwk) -> Result<KeyParams, KeyError> {
    unimplemented!()
}

/// The RFC 7638 JWK thumbprint, computed from the JWK's required members
/// exactly as they appear (no decoding or re-encoding of values).
///
/// Required members: EC `crv`, `kty`, `x`, `y`; OKP `crv`, `kty`, `x`; RSA
/// `e`, `kty`, `n`; AKP `alg`, `kty`, `pub` (RFC 9964 §6). Other members
/// and member order do not matter. A missing required member is
/// [`KeyError::MissingParameter`].
pub fn jwk_thumbprint(jwk: &Jwk, hash: HashAlg) -> Result<Vec<u8>, KeyError> {
    unimplemented!()
}
