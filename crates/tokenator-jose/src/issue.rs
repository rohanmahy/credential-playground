//! Issuing JWTs and SD-JWTs.

use tokenator_crypto::rand_core::CryptoRng;
use tokenator_crypto::{Alg, HashAlg};
use tokenator_json::Node;
use tokenator_keys::{Jwk, Key};

use crate::error::JoseError;

/// How generated JSON (headers, payloads, disclosures) is written.
///
/// Values copied from an input tree keep their number lexemes; strings are
/// re-escaped by the style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JsonStyle {
    /// No insignificant whitespace; non-ASCII characters written as UTF-8.
    #[default]
    Compact,
    /// `", "` and `": "` separators, as in the RFC 9901 examples (Python's
    /// `json.dumps` default). With `ascii_only`, every non-ASCII character
    /// is written as a lowercase `\uXXXX` escape (a surrogate pair above
    /// U+FFFF), as the RFC 9901 Appendix A examples do.
    Spaced {
        /// Escape all non-ASCII characters.
        ascii_only: bool,
    },
}

/// Order of the digests in each `_sd` array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DigestOrder {
    /// Sorted by byte value, after adding decoys (the RFC 9901 §4.2.4.1
    /// recommendation, and what its examples do).
    #[default]
    Sorted,
    /// Disclosures in creation order, then decoys. Reveals claim order; for
    /// experiments only.
    Creation,
}

/// Where disclosure salts come from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SaltSource {
    /// Base64url of 16 bytes (128 bits) from the RNG per salt.
    #[default]
    Random,
    /// These salts, in disclosure creation order (to reproduce published
    /// examples). Running out is [`JoseError::SaltsExhausted`].
    Fixed(Vec<String>),
}

/// The decoy digests to add at one place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecoyDigests {
    /// `n` decoys, each the base64url digest (under the `_sd_alg` hash) of
    /// the base64url of 16 random bytes.
    Random(usize),
    /// These digest strings, verbatim.
    Fixed(Vec<String>),
}

/// Decoys for one object (added to its `_sd`) or array (appended as
/// `{"...": digest}` elements).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoySpec {
    /// RFC 6901 pointer into the input claims (`""` for the top level). The
    /// target may be inside a selectively disclosable claim; its decoys then
    /// live in that claim's disclosure.
    pub at: String,
    /// What to add.
    pub digests: DecoyDigests,
}

/// The confirmation (`cnf`, RFC 7800) to put in the payload.
#[derive(Debug, Clone)]
pub enum Cnf {
    /// `{"jwk": ...}`, members in the JWK's order.
    Jwk(Jwk),
    /// `{"kid": ...}`.
    Kid(String),
}

/// Everything [`issue`] needs besides the claims.
#[derive(Debug, Clone)]
pub struct IssueOptions<'k> {
    /// The issuer's private key.
    pub key: &'k Key,
    /// The signature algorithm (header `alg`).
    pub alg: Alg,
    /// Header `typ`.
    pub typ: Option<String>,
    /// Header `kid`.
    pub kid: Option<String>,
    /// Header `x5c` (base64 DER certificates, in order); omitted if empty.
    pub x5c: Vec<String>,
    /// More header members, appended in order.
    pub extra_header: Vec<(String, Node<'static>)>,
    /// `cnf`, appended as the last payload member.
    pub cnf: Option<Cnf>,
    /// RFC 6901 pointers of the claims to make selectively disclosable.
    /// Marking a claim and something inside it gives recursive disclosures.
    pub sd: Vec<String>,
    /// Decoy digests.
    pub decoys: Vec<DecoySpec>,
    /// The `_sd_alg` hash. `None` omits the claim and uses SHA-256 (the
    /// default the RFC prescribes).
    pub sd_alg: Option<HashAlg>,
    /// `_sd` order.
    pub digest_order: DigestOrder,
    /// Salt source.
    pub salts: SaltSource,
    /// Style for the header, payload, and disclosures.
    pub style: JsonStyle,
}

impl<'k> IssueOptions<'k> {
    /// Defaults: no `typ`/`kid`/`x5c`/`cnf`, nothing selectively disclosable,
    /// no decoys, `_sd_alg` SHA-256, sorted digests, random salts, compact
    /// JSON.
    pub fn new(key: &'k Key, alg: Alg) -> IssueOptions<'k> {
        IssueOptions {
            key,
            alg,
            typ: None,
            kid: None,
            x5c: Vec::new(),
            extra_header: Vec::new(),
            cnf: None,
            sd: Vec::new(),
            decoys: Vec::new(),
            sd_alg: Some(HashAlg::Sha256),
            digest_order: DigestOrder::Sorted,
            salts: SaltSource::Random,
            style: JsonStyle::Compact,
        }
    }
}

/// One disclosure created by [`issue`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedDisclosure {
    /// Pointer of the claim in the input claims.
    pub pointer: String,
    /// The base64url disclosure.
    pub text: String,
    /// Its digest.
    pub digest: String,
}

/// The output of [`issue`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    /// A compact JWT, or a compact SD-JWT ending in `~`.
    pub token: String,
    /// Disclosures in creation order (also their order in the token).
    pub disclosures: Vec<IssuedDisclosure>,
}

/// Issues a JWT, or an SD-JWT if `opts.sd` or `opts.decoys` is non-empty.
///
/// Header members: `alg`, then `typ`, `kid`, `x5c` when set, then
/// `extra_header`. Payload: an object's `_sd` (if it gets digests) comes
/// first, then its remaining members in input order; at the top level
/// `_sd_alg` (SD-JWT only) and `cnf` follow. Claims are walked in document
/// order and a claim's disclosure is created after those inside it, which
/// fixes the order of salts, disclosures, and RNG use (salts, then random
/// decoys in `decoys` order, then the signature). With fixed salts and
/// decoys and [`JsonStyle::Spaced`], this reproduces the RFC 9901 example
/// payloads and disclosures byte for byte.
///
/// Errors: pointers and decoy targets are checked first
/// ([`JoseError::NoSuchClaim`], [`JoseError::InvalidSdPath`],
/// [`JoseError::InvalidDecoyTarget`]), then conflicts with generated
/// members ([`JoseError::ClaimConflict`]), then salts and signing.
pub fn issue(
    claims: &Node<'_>,
    opts: &IssueOptions<'_>,
    rng: &mut dyn CryptoRng,
) -> Result<Issued, JoseError> {
    unimplemented!()
}
