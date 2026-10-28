//! The format-neutral key model: material plus metadata.

use tokenator_crypto::{DeclaredAlg, KeyType, PrivateKey, PublicKey};

/// What a key is used for in the workspace (SPEC §4.2). Not part of any
/// key format: it is never imported and never exported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Signs credentials.
    Issuer,
    /// Holds a credential and signs key-binding tokens.
    Holder,
    /// Verifies credentials.
    Verifier,
}

/// A key identifier.
///
/// JOSE `kid` is a JSON string and imports as [`Kid::Text`]; COSE `kid`
/// (label 2) is a byte string and imports as [`Kid::Bytes`] (a COSE text
/// `kid`, which is non-conformant, imports as [`Kid::Text`]).
///
/// On export:
/// - to a COSE_Key, [`Kid::Text`] becomes the bstr of its UTF-8 bytes and
///   [`Kid::Bytes`] is written as is, so the kid is always a bstr;
/// - to a JWK, [`Kid::Text`] is written as is and [`Kid::Bytes`] becomes its
///   UTF-8 text when valid UTF-8, otherwise its unpadded base64url encoding
///   (see [`Kid::to_jose_string`]).
///
/// A JWK → COSE_Key → JWK round trip therefore keeps the kid string, and
/// [`Kid::as_bytes`] is preserved by every conversion of a UTF-8 kid.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Kid {
    /// A text kid (JOSE).
    Text(String),
    /// A binary kid (COSE).
    Bytes(Vec<u8>),
}

impl Kid {
    /// The kid as bytes: UTF-8 for [`Kid::Text`].
    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!()
    }

    /// The JWK `kid` string for this kid (see the type docs).
    pub fn to_jose_string(&self) -> String {
        unimplemented!()
    }
}

/// A key operation (JWK `key_ops`, RFC 7517 §4.3; COSE `key_ops`, label 4,
/// RFC 9052 Table 5).
///
/// The first eight have both a JOSE name and a COSE value and convert
/// between the two. Anything else, including COSE `MAC create` (9) and
/// `MAC verify` (10), is [`KeyOp::Other`] and is written back unchanged,
/// even into the other format (an integer inside a JWK `key_ops` array is
/// non-conformant, but faithful).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyOp {
    /// `sign` / 1.
    Sign,
    /// `verify` / 2.
    Verify,
    /// `encrypt` / 3.
    Encrypt,
    /// `decrypt` / 4.
    Decrypt,
    /// `wrapKey` / 5.
    WrapKey,
    /// `unwrapKey` / 6.
    UnwrapKey,
    /// `deriveKey` / 7.
    DeriveKey,
    /// `deriveBits` / 8.
    DeriveBits,
    /// Any other value, as it appeared.
    Other(Label),
}

/// A JWK member name or a COSE map label; also an unrecognized `key_ops`
/// entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Label {
    /// A text name or label.
    Text(String),
    /// An integer label.
    Int(i64),
}

/// A key parameter that `tokenator-keys` does not interpret (e.g. `x5c`,
/// `ext`, COSE `Base IV`, private-use labels), kept for display and
/// re-export in arrival order.
///
/// Extras are only written back to the format family they came from: JOSE
/// extras into JWKs, COSE extras into COSE_Keys. Converting a key to the
/// other family drops them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extra {
    /// An unrecognized JWK member.
    Jose {
        /// Member name.
        name: String,
        /// The member value as compact JSON text. Scalars keep their
        /// original lexeme (e.g. `1.0` stays `1.0`).
        json: String,
    },
    /// An unrecognized COSE_Key entry.
    Cose {
        /// Map label.
        label: Label,
        /// The value as CBOR, encoded with `EncodeMode::Preserve`.
        cbor: Vec<u8>,
    },
}

/// Whether an export includes the private part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Visibility {
    /// Public parameters only. Allowed for every key.
    Public,
    /// Public and private parameters. Fails with
    /// [`KeyError::NoPrivateKey`](crate::KeyError::NoPrivateKey) for a
    /// public key.
    Private,
}

/// The key material inside a [`Key`].
#[derive(Debug, Clone)]
pub(crate) enum Material {
    Private(PrivateKey),
    Public(PublicKey),
}

/// A key: private or public material (validated by `tokenator-crypto`)
/// plus metadata. Formats live in [`crate::import`] / [`crate::export`].
///
/// `PartialEq` compares everything: material (via [`Key::same_material`])
/// and every metadata field.
#[derive(Debug, Clone)]
pub struct Key {
    pub(crate) material: Material,
    /// Workspace role. Never imported or exported.
    pub role: Option<Role>,
    /// Key identifier.
    pub kid: Option<Kid>,
    /// The key's own declared algorithm (JWK `alg`, COSE label 3). Kept even
    /// when it is unknown or does not fit the key; the linter reports that.
    ///
    /// Known algorithms convert between JOSE names and COSE labels. An
    /// unknown JOSE name (or a COSE text `alg`) is `UnknownJose` and is
    /// written to a COSE_Key as a tstr; an unknown COSE label is
    /// `UnknownCose` and is written to a JWK as a JSON number (a JWK integer
    /// `alg` parses back as `UnknownCose`).
    pub alg: Option<DeclaredAlg>,
    /// JWK `use` (e.g. `sig`). COSE has no equivalent, so a COSE_Key export
    /// drops it.
    pub key_use: Option<String>,
    /// JWK `key_ops` / COSE label 4, in order.
    pub key_ops: Option<Vec<KeyOp>>,
    /// Unrecognized parameters, in arrival order.
    pub extras: Vec<Extra>,
    /// True when this key was produced by [`crate::to_public`] from a
    /// private key.
    pub derived: bool,
}

impl Key {
    /// A private key with no metadata.
    pub fn from_private(key: PrivateKey) -> Key {
        unimplemented!()
    }

    /// A public key with no metadata.
    pub fn from_public(key: PublicKey) -> Key {
        unimplemented!()
    }

    /// True if the key has a private part.
    pub fn is_private(&self) -> bool {
        unimplemented!()
    }

    /// The private key, if any.
    pub fn private_key(&self) -> Option<&PrivateKey> {
        unimplemented!()
    }

    /// The public key (derived from the private key when private).
    pub fn public_key(&self) -> PublicKey {
        unimplemented!()
    }

    /// The key type.
    pub fn key_type(&self) -> KeyType {
        unimplemented!()
    }

    /// True if both keys have the same public key and the same visibility,
    /// and, when private, the same secret. An ML-DSA key known only by its
    /// expanded private key has the same material as the seed-based key it
    /// was expanded from. Metadata is ignored.
    pub fn same_material(&self, other: &Key) -> bool {
        unimplemented!()
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        unimplemented!()
    }
}
