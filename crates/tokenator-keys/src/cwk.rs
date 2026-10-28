//! COSE_Key (RFC 9052 §7, RFC 9053 §7, RFC 8230 §4, RFC 9964 §3)
//! conversion.

use tokenator_cbor::Item;
use tokenator_crypto::{HashAlg, KeyParams};

use crate::{Key, KeyError, Label, Visibility};

/// A COSE_Key: one CBOR map, entries in arrival order.
///
/// Like [`Jwk`](crate::Jwk), a `CoseKey` is only known to be a map, so
/// [`params_from_cwk`] and [`cose_thumbprint`] work on keys with missing or
/// broken material.
///
/// Labels used by this crate: common 1 `kty`, 2 `kid`, 3 `alg`,
/// 4 `key_ops`; OKP -1 `crv`, -2 `x`, -4 `d`; EC2 -1 `crv`, -2 `x`, -3 `y`,
/// -4 `d`; RSA -1 `n`, -2 `e`, -3 `d`, -4 `p`, -5 `q`, -6 `dP`, -7 `dQ`,
/// -8 `qInv`; AKP -1 `pub`, -2 `priv`.
#[derive(Debug, Clone, PartialEq)]
pub struct CoseKey {
    item: Item<'static>,
}

impl CoseKey {
    /// Decodes CBOR bytes that must be a single map.
    pub fn decode(cbor: &[u8]) -> Result<CoseKey, KeyError> {
        unimplemented!()
    }

    /// Copies a map item, e.g. the `COSE_Key` of a `cnf` claim.
    pub fn from_item(item: &Item<'_>) -> Result<CoseKey, KeyError> {
        unimplemented!()
    }

    /// The map as a CBOR item.
    pub fn item(&self) -> &Item<'static> {
        &self.item
    }

    /// The CBOR encoding, preserving the recorded encoding details
    /// (`EncodeMode::Preserve`). A decoded key encodes to its input bytes.
    pub fn to_cbor(&self) -> Vec<u8> {
        unimplemented!()
    }

    /// Map labels in order, duplicates included. Labels that are neither
    /// integers nor text are skipped.
    pub fn labels(&self) -> Vec<Label> {
        unimplemented!()
    }

    /// The value of integer label `label` (the first one, if duplicated).
    pub fn get(&self, label: i64) -> Option<&Item<'static>> {
        unimplemented!()
    }
}

/// Builds the COSE_Key for `key`.
///
/// Entry order: 1 `kty`, 2 `kid`, 3 `alg`, 4 `key_ops`, then the key-type
/// parameters in descending label order (-1, -2, ...), then COSE
/// [`Extra`](crate::Extra)s in arrival order. Every item uses preferred
/// (shortest) encoding. The kid is always a bstr (see [`Kid`](crate::Kid)).
/// AKP keys always get `alg`. JWK `use` is dropped. As with [`to_jwk`], an
/// expanded-only ML-DSA key cannot be exported privately.
///
/// [`to_jwk`]: crate::to_jwk
pub fn to_cwk(key: &Key, visibility: Visibility) -> Result<CoseKey, KeyError> {
    unimplemented!()
}

/// Parses a COSE_Key into a key, validating the material with
/// `tokenator-crypto`. The rules match [`from_jwk`](crate::from_jwk):
/// public and private parts must agree, duplicate labels are rejected,
/// unrecognized entries become COSE extras, and short EC values are
/// left-padded.
pub fn from_cwk(cwk: &CoseKey) -> Result<Key, KeyError> {
    unimplemented!()
}

/// Describes a COSE_Key without validating its material; the COSE
/// counterpart of [`params_from_jwk`](crate::params_from_jwk). RSA size is
/// the bit length of `n` (-1).
pub fn params_from_cwk(cwk: &CoseKey) -> Result<KeyParams, KeyError> {
    unimplemented!()
}

/// The RFC 9679 COSE Key thumbprint: the deterministic encoding (RFC 8949
/// §4.2.1) of a map holding only the required parameters, hashed.
///
/// Required parameters: OKP 1, -1, -2; EC2 1, -1, -2, -3; RSA 1, -1, -2;
/// AKP 1, 3, -1 (RFC 9964 §6). Values are copied as they appear.
pub fn cose_thumbprint(cwk: &CoseKey, hash: HashAlg) -> Result<Vec<u8>, KeyError> {
    unimplemented!()
}
