//! The format-neutral key model: material plus metadata.

use base64ct::{Base64UrlUnpadded, Encoding};
use tokenator_crypto::{
    DeclaredAlg, KeyType, PrivateKey, PrivateKeyMaterial, PublicKey, alg_from_cose, alg_from_jose,
};
use zeroize::Zeroize;

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
        match self {
            Kid::Text(t) => t.as_bytes(),
            Kid::Bytes(b) => b,
        }
    }

    /// The JWK `kid` string for this kid (see the type docs).
    pub fn to_jose_string(&self) -> String {
        match self {
            Kid::Text(t) => t.clone(),
            Kid::Bytes(b) => match core::str::from_utf8(b) {
                Ok(t) => t.to_owned(),
                Err(_) => Base64UrlUnpadded::encode_string(b),
            },
        }
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

/// The eight operations with both a JOSE name and a COSE value.
const NAMED_OPS: [(KeyOp, &str, i64); 8] = [
    (KeyOp::Sign, "sign", 1),
    (KeyOp::Verify, "verify", 2),
    (KeyOp::Encrypt, "encrypt", 3),
    (KeyOp::Decrypt, "decrypt", 4),
    (KeyOp::WrapKey, "wrapKey", 5),
    (KeyOp::UnwrapKey, "unwrapKey", 6),
    (KeyOp::DeriveKey, "deriveKey", 7),
    (KeyOp::DeriveBits, "deriveBits", 8),
];

impl KeyOp {
    /// The JOSE name, for the eight shared operations.
    pub(crate) fn jose_name(&self) -> Option<&'static str> {
        NAMED_OPS
            .iter()
            .find(|(op, ..)| op == self)
            .map(|(_, name, _)| *name)
    }

    /// The COSE value, for the eight shared operations.
    pub(crate) fn cose_value(&self) -> Option<i64> {
        NAMED_OPS
            .iter()
            .find(|(op, ..)| op == self)
            .map(|(.., value)| *value)
    }

    /// A JWK `key_ops` string.
    pub(crate) fn from_jose_name(name: &str) -> KeyOp {
        NAMED_OPS.iter().find(|(_, n, _)| *n == name).map_or_else(
            || KeyOp::Other(Label::Text(name.to_owned())),
            |(op, ..)| op.clone(),
        )
    }

    /// A COSE `key_ops` integer.
    pub(crate) fn from_cose_value(value: i64) -> KeyOp {
        NAMED_OPS
            .iter()
            .find(|(.., v)| *v == value)
            .map_or(KeyOp::Other(Label::Int(value)), |(op, ..)| op.clone())
    }
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

/// The declared alg for a JOSE `alg` name.
pub(crate) fn declared_alg_from_jose(name: &str) -> DeclaredAlg {
    alg_from_jose(name).map_or_else(
        || DeclaredAlg::UnknownJose(name.to_owned()),
        DeclaredAlg::Known,
    )
}

/// The declared alg for a COSE `alg` label.
pub(crate) fn declared_alg_from_cose(label: i64) -> DeclaredAlg {
    alg_from_cose(label).map_or(DeclaredAlg::UnknownCose(label), DeclaredAlg::Known)
}

/// Overwrites the secret parts of raw private material.
pub(crate) fn wipe(material: &mut PrivateKeyMaterial) {
    match material {
        PrivateKeyMaterial::Ec { d, .. } | PrivateKeyMaterial::Ed25519 { d } => d.zeroize(),
        PrivateKeyMaterial::Rsa(m) => {
            m.d.zeroize();
            for v in [&mut m.p, &mut m.q, &mut m.dp, &mut m.dq, &mut m.qi] {
                v.zeroize();
            }
        }
        PrivateKeyMaterial::MlDsa { seed, expanded, .. } => {
            seed.zeroize();
            expanded.zeroize();
        }
    }
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
        Key::with_material(Material::Private(key))
    }

    /// A public key with no metadata.
    pub fn from_public(key: PublicKey) -> Key {
        Key::with_material(Material::Public(key))
    }

    pub(crate) fn with_material(material: Material) -> Key {
        Key {
            material,
            role: None,
            kid: None,
            alg: None,
            key_use: None,
            key_ops: None,
            extras: Vec::new(),
            derived: false,
        }
    }

    /// True if the key has a private part.
    pub fn is_private(&self) -> bool {
        matches!(self.material, Material::Private(_))
    }

    /// The private key, if any.
    pub fn private_key(&self) -> Option<&PrivateKey> {
        match &self.material {
            Material::Private(k) => Some(k),
            Material::Public(_) => None,
        }
    }

    /// The public key (derived from the private key when private).
    pub fn public_key(&self) -> PublicKey {
        match &self.material {
            Material::Private(k) => k.public_key(),
            Material::Public(k) => k.clone(),
        }
    }

    /// The key type.
    pub fn key_type(&self) -> KeyType {
        match &self.material {
            Material::Private(k) => k.params().kty,
            Material::Public(k) => k.params().kty,
        }
    }

    /// True if both keys have the same public key and the same visibility,
    /// and, when private, the same secret. An ML-DSA key known only by its
    /// expanded private key has the same material as the seed-based key it
    /// was expanded from. Metadata is ignored.
    pub fn same_material(&self, other: &Key) -> bool {
        match (&self.material, &other.material) {
            (Material::Public(a), Material::Public(b)) => a == b,
            (Material::Private(a), Material::Private(b)) => {
                a.public_key() == b.public_key() && same_secret(a, b)
            }
            _ => false,
        }
    }
}

/// Compares the secrets of two private keys whose public keys are equal.
fn same_secret(a: &PrivateKey, b: &PrivateKey) -> bool {
    let (mut a, mut b) = (a.to_material(), b.to_material());
    let same = match (&a, &b) {
        (PrivateKeyMaterial::Ec { d: x, .. }, PrivateKeyMaterial::Ec { d: y, .. })
        | (PrivateKeyMaterial::Ed25519 { d: x }, PrivateKeyMaterial::Ed25519 { d: y }) => x == y,
        // n and e are already equal; the primes may come in either order.
        (PrivateKeyMaterial::Rsa(x), PrivateKeyMaterial::Rsa(y)) => x.d == y.d,
        // The expanded key is always known; the seed may not be.
        (
            PrivateKeyMaterial::MlDsa { expanded: x, .. },
            PrivateKeyMaterial::MlDsa { expanded: y, .. },
        ) => x == y,
        _ => false,
    };
    wipe(&mut a);
    wipe(&mut b);
    same
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.same_material(other)
            && self.role == other.role
            && self.kid == other.kid
            && self.alg == other.alg
            && self.key_use == other.key_use
            && self.key_ops == other.key_ops
            && self.extras == other.extras
            && self.derived == other.derived
    }
}
