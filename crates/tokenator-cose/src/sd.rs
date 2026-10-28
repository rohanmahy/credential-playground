//! SD-CWT (draft-ietf-spice-sd-cwt-08): redaction, issuance, disclosures,
//! digests, and disclosure matching.
//!
//! A disclosure travels as a bstr in `sd_claims`; its digest is the hash of
//! that *encoded bstr* (head and contents) exactly as it appears in the
//! token (sd-cwt-08 Appendix G and every example payload; see
//! `TEST-PLAN.md` for the Figure 8 discrepancy).
#![allow(clippy::unimplemented)]

use std::borrow::Cow;

use tokenator_cbor::{Item, Span};
use tokenator_crypto::{Alg, HashAlg, rand_core::CryptoRng};
use tokenator_keys::{Key, Label};

use crate::{Bstr, ContentType, CoseError, Diagnostic, Sign1, Sign1Backend};

/// Where a [`redact`] salt request comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaltRequest {
    /// 0 for the first salt, then 1, 2, ...: the order of the disclosures
    /// in [`Redacted::disclosures`].
    pub ordinal: usize,
    /// The decoy number for a to-be-decoy tag, `None` otherwise.
    pub decoy: Option<u64>,
}

/// Supplies disclosure salts. Injected so issuance is reproducible.
pub trait SaltSource {
    /// The salt for the next disclosure. The draft requires 16 random bytes
    /// (sd-cwt-08 §6.1); other lengths are allowed and linted.
    fn salt(&mut self, req: &SaltRequest) -> Result<Vec<u8>, CoseError>;
}

/// 16-byte salts drawn from an RNG with `fill_bytes`, one call per salt.
pub struct RngSalts<'r> {
    rng: &'r mut dyn CryptoRng,
}

impl<'r> RngSalts<'r> {
    /// Salts from `rng`.
    pub fn new(rng: &'r mut dyn CryptoRng) -> RngSalts<'r> {
        RngSalts { rng }
    }
}

impl SaltSource for RngSalts<'_> {
    fn salt(&mut self, req: &SaltRequest) -> Result<Vec<u8>, CoseError> {
        let _ = (req, &mut self.rng);
        unimplemented!()
    }
}

/// Salts from a list, in order; [`CoseError::SaltExhausted`] after the last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedSalts {
    salts: Vec<Vec<u8>>,
    next: usize,
}

impl FixedSalts {
    /// Salts taken from `salts` in order.
    pub fn new(salts: Vec<Vec<u8>>) -> FixedSalts {
        FixedSalts { salts, next: 0 }
    }
}

impl SaltSource for FixedSalts {
    fn salt(&mut self, req: &SaltRequest) -> Result<Vec<u8>, CoseError> {
        let _ = (req, &self.salts, self.next);
        unimplemented!()
    }
}

/// Something worth labeling in a redaction that still went ahead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedactWarning {
    /// A top-level claim that SD-CWT never redacts (sd-cwt-08 Table 2) was
    /// marked to be redacted.
    NeverRedactedClaim(i64),
    /// The input contains indefinite-length items, which were kept
    /// (sd-cwt-08 §5.1 forbids sending them).
    IndefiniteLength,
    /// A salt that is not 16 bytes long.
    SaltLength(usize),
}

/// The output of [`redact`].
#[derive(Debug, Clone, PartialEq)]
pub struct Redacted<'a> {
    /// The claims set with redacted claim keys (`simple(59)` arrays) and
    /// redacted elements (`60(digest)`).
    pub payload: Item<'a>,
    /// Encoded salted disclosures (the bstr *contents*), in the order they
    /// were created: post-order, so disclosures nested in a value come
    /// before the disclosure of that value.
    pub disclosures: Vec<Vec<u8>>,
    /// Labels for unusual input.
    pub warnings: Vec<RedactWarning>,
}

/// Converts a pre-issuance claims set into an SD-CWT payload and its
/// disclosures (sd-cwt-08 §4.1, §10, §11).
///
/// - A map key `58(k)` removes the entry `k: v` and adds
///   `[salt, v', k]` (v' = v redacted recursively). A key `62(n)` (value
///   `null`) adds a decoy `[salt]`. Their digests go, in key order, into a
///   `simple(59)` array appended as the map's last entry. Other entries
///   keep their order.
/// - An array element `58(x)` becomes `60(digest)` of `[salt, x']`; `62(n)`
///   becomes `60(digest)` of `[salt]`.
/// - Other tags are recursed into.
///
/// Everything copied from the input is encoded with `EncodeMode::Preserve`;
/// new items use preferred encoding. Each digest is `hash` over the
/// disclosure encoded as a bstr (head included).
pub fn redact<'a>(
    claims: &Item<'a>,
    hash: HashAlg,
    salts: &mut dyn SaltSource,
) -> Result<Redacted<'a>, CoseError> {
    let _ = (claims, hash, salts);
    unimplemented!()
}

/// Encodes a salted disclosure array (bstr contents) with preferred
/// encoding for the array and salt and Preserve for `value` and `key`:
/// `[salt]`, `[salt, value]`, or `[salt, value, key]`. A `key` without a
/// `value` gives `[salt]`.
pub fn encode_disclosure(salt: &[u8], value: Option<&Item<'_>>, key: Option<&Item<'_>>) -> Vec<u8> {
    let _ = (salt, value, key);
    unimplemented!()
}

/// The digest of a disclosure given its bstr *contents*: `hash` over the
/// contents wrapped in a preferred bstr head.
pub fn disclosure_digest(hash: HashAlg, contents: &[u8]) -> Vec<u8> {
    let _ = (hash, contents);
    unimplemented!()
}

/// `typ` choice for [`issue`] and [`present`](crate::kbt::present).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Typ {
    /// 293 for an SD-CWT, 294 for an SD-KBT, none for a plain CWT.
    #[default]
    Auto,
    /// No `typ`.
    Omit,
    /// This value.
    Value(ContentType),
}

/// Header options for [`issue`].
#[derive(Debug, Clone, PartialEq)]
pub struct IssueOptions<'a> {
    /// Signature algorithm (written as `alg` and used to sign).
    pub alg: Alg,
    /// `kid` for the protected header.
    pub kid: Option<Cow<'a, [u8]>>,
    /// `typ`.
    pub typ: Typ,
    /// SD hash algorithm. `Some` also writes `sd_alg` to the protected
    /// header of an SD-CWT; `None` omits it and SHA-256 is used. Default
    /// `Some(Sha256)`.
    pub sd_alg: Option<HashAlg>,
    /// Issue an SD-CWT (typ, sd_alg) even when nothing is redacted.
    pub force_sd: bool,
    /// Tags, outermost first. Default `[18]`.
    pub tags: Vec<u64>,
    /// Extra protected header entries, written after the standard ones.
    pub protected_extra: Vec<(Item<'a>, Item<'a>)>,
    /// Extra unprotected header entries, written after `sd_claims`.
    pub unprotected_extra: Vec<(Item<'a>, Item<'a>)>,
    /// RFC 9052 external AAD for the signature.
    pub external_aad: Cow<'a, [u8]>,
}

impl IssueOptions<'_> {
    /// Defaults for `alg`: no kid, automatic typ, `sd_alg` SHA-256 written,
    /// tag 18, no extras, empty external AAD.
    pub fn new(alg: Alg) -> IssueOptions<'static> {
        IssueOptions {
            alg,
            kid: None,
            typ: Typ::Auto,
            sd_alg: Some(HashAlg::Sha256),
            force_sd: false,
            tags: vec![crate::codepoints::TAG_COSE_SIGN1],
            protected_extra: Vec::new(),
            unprotected_extra: Vec::new(),
            external_aad: Cow::Borrowed(&[]),
        }
    }
}

/// The output of [`issue`].
#[derive(Debug, Clone, PartialEq)]
pub struct Issued {
    /// The signed CWT or SD-CWT.
    pub bytes: Vec<u8>,
    /// The disclosures (bstr contents), also in `sd_claims`.
    pub disclosures: Vec<Vec<u8>>,
    /// From [`redact`].
    pub warnings: Vec<RedactWarning>,
}

/// Issues a CWT, or an SD-CWT when `claims` has to-be-redacted or
/// to-be-decoy tags (or `force_sd`).
///
/// Protected header order: `alg` (1), `kid` (4), `typ` (16), `sd_alg`
/// (170), then extras. Unprotected: `sd_claims` (17) when there are
/// disclosures, then extras. Without `rng`, signing is deterministic.
pub fn issue(
    backend: &dyn Sign1Backend,
    claims: &Item<'_>,
    issuer: &Key,
    opts: &IssueOptions<'_>,
    salts: &mut dyn SaltSource,
    rng: Option<&mut dyn CryptoRng>,
) -> Result<Issued, CoseError> {
    let _ = (backend, claims, issuer, opts, salts, rng);
    unimplemented!()
}

/// The resolved `sd_alg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdAlg {
    /// Absent: SHA-256 (sd-cwt-08 §6).
    Default,
    /// A supported hash: -16 SHA-256, -43 SHA-384, -44 SHA-512.
    Known(HashAlg),
    /// An integer this crate does not support; no digests can be computed.
    Unsupported(i64),
    /// Present but not an integer.
    Invalid,
}

impl SdAlg {
    /// The hash to use, if any.
    pub fn hash(self) -> Option<HashAlg> {
        unimplemented!()
    }
}

/// What a disclosure holds (sd-cwt-08 §4.1 Figure 12).
#[derive(Debug, Clone, PartialEq)]
pub enum DisclosureContent<'a> {
    /// `[salt, value, key]`: a redacted claim key.
    Claim {
        /// Salt.
        salt: Cow<'a, [u8]>,
        /// Claim value.
        value: Item<'a>,
        /// Claim key (int or text).
        key: Item<'a>,
    },
    /// `[salt, value]`: a redacted array element.
    Element {
        /// Salt.
        salt: Cow<'a, [u8]>,
        /// Element value.
        value: Item<'a>,
    },
    /// `[salt]`: a decoy.
    Decoy {
        /// Salt.
        salt: Cow<'a, [u8]>,
    },
    /// Anything else.
    Malformed(MalformedDisclosure),
}

/// Why a disclosure is malformed.
#[derive(Debug, Clone, PartialEq)]
pub enum MalformedDisclosure {
    /// The `sd_claims` element is not a byte string.
    NotBytes,
    /// The contents are not one well-formed CBOR item.
    NotCbor,
    /// Not an array.
    NotArray,
    /// An array of length 0 or more than 3.
    WrongLength(usize),
    /// The salt is not a byte string.
    SaltNotBytes,
    /// The claim key is not an int or text string.
    KeyNotLabel,
}

/// One entry of `sd_claims`.
#[derive(Debug, Clone, PartialEq)]
pub struct Disclosure<'a> {
    /// Position in `sd_claims`.
    pub index: usize,
    /// The bstr with its span in [`Sign1::bytes`].
    pub bytes: Bstr<'a>,
    /// Hash of the encoded bstr exactly as received (head included).
    /// `None` when `sd_alg` is not supported or the element is not a bstr.
    pub digest: Option<Vec<u8>>,
    /// The decoded contents.
    pub content: DisclosureContent<'a>,
}

/// A parsed SD-CWT (or any COSE_Sign1 viewed as one).
#[derive(Debug, Clone, PartialEq)]
pub struct SdCwt<'a> {
    /// The COSE_Sign1.
    pub sign1: Sign1<'a>,
    /// `sd_alg` from the protected header.
    pub sd_alg: SdAlg,
    /// `sd_claims`, in order (empty when absent).
    pub disclosures: Vec<Disclosure<'a>>,
    /// SD-specific structural problems (`sd_claims` not an array, empty,
    /// misplaced, ...).
    pub diagnostics: Vec<Diagnostic>,
}

impl<'a> SdCwt<'a> {
    /// Views a parsed COSE_Sign1 as an SD-CWT.
    pub fn from_sign1(sign1: Sign1<'a>) -> SdCwt<'a> {
        let _ = sign1;
        unimplemented!()
    }
}

/// Parses an SD-CWT with `backend`.
pub fn parse_sd_cwt<'a>(
    backend: &dyn Sign1Backend,
    bytes: &'a [u8],
) -> Result<SdCwt<'a>, CoseError> {
    let _ = (backend, bytes);
    unimplemented!()
}

/// One step in a path to a container in the issued structure.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathSeg {
    /// The payload claims map (always first unless `Disclosure`).
    Payload,
    /// The value of disclosure `i` (always first unless `Payload`).
    Disclosure(usize),
    /// A map entry.
    Key(Label),
    /// An array element (position in the issued array).
    Index(usize),
}

/// The kind of place a digest sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlotKind {
    /// In a `simple(59)` array: a redacted claim key.
    ClaimKey,
    /// A `60(digest)` array element.
    ArrayElement,
}

/// A digest in the payload or inside a disclosed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    /// Path to the map (for `ClaimKey`) or array (for `ArrayElement`).
    pub container: Vec<PathSeg>,
    /// Index in the `simple(59)` array, or in the issued array.
    pub position: usize,
    /// Which kind.
    pub kind: SlotKind,
    /// The digest bytes.
    pub digest: Vec<u8>,
    /// The digest item, in [`Sign1::bytes`] coordinates.
    pub span: Span,
}

/// A disclosure and the digest it matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// Disclosure index.
    pub disclosure: usize,
    /// Where its digest is.
    pub slot: Slot,
}

/// Why a disclosure's contents are not allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForbiddenReason {
    /// A top-level claim that is never redacted (sd-cwt-08 Table 2).
    NeverRedactedClaim(i64),
    /// A to-be-redacted (58) or to-be-decoy (62) tag inside the disclosure
    /// (sd-cwt-08 §5.3 `safe_tag`).
    PreIssuanceTag(u64),
    /// A claim disclosure matched an array element digest, or an element
    /// disclosure matched a claim key digest.
    KindMismatch,
}

/// A forbidden disclosure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forbidden {
    /// Disclosure index.
    pub disclosure: usize,
    /// Why.
    pub reason: ForbiddenReason,
}

/// A disclosed claim key that already exists in the same map (sd-cwt-08
/// §9 step 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCollision {
    /// Disclosure index.
    pub disclosure: usize,
    /// The key.
    pub key: Label,
}

/// Who is checking: a Holder needs a disclosure for every digest; a
/// Verifier does not (sd-cwt-08 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// Holder validation (§6.2).
    Holder,
    /// Verifier validation (§9).
    Verifier,
}

/// The disclosure matching report (SPEC §6 "SD").
#[derive(Debug, Clone, PartialEq)]
pub struct SdReport<'a> {
    /// `sd_alg` validity.
    pub sd_alg: SdAlg,
    /// Disclosures that matched a digest, in disclosure order.
    pub matched: Vec<Match>,
    /// Disclosures whose digest is nowhere (well-formed but unmatched).
    pub unmatched: Vec<usize>,
    /// Disclosures whose bytes repeat an earlier disclosure.
    pub duplicate_disclosures: Vec<usize>,
    /// Digests that occur in more than one slot.
    pub duplicate_digests: Vec<Vec<u8>>,
    /// Digests without a disclosure (decoys or withheld claims), in
    /// document order.
    pub undisclosed: Vec<Slot>,
    /// Disclosures with forbidden contents.
    pub forbidden: Vec<Forbidden>,
    /// Malformed disclosures.
    pub malformed: Vec<usize>,
    /// Disclosed keys that collide with existing keys.
    pub key_collisions: Vec<KeyCollision>,
    /// The Validated Disclosed Claims Set: disclosed claims put back, all
    /// remaining digests and decoys removed. A disclosed claim key replaces
    /// the `simple(59)` entry's position (in digest order); an element is
    /// replaced in place. Untouched items keep their original encoding.
    /// `None` when the payload is not a decodable map.
    pub processed: Option<Item<'a>>,
}

impl SdReport<'_> {
    /// Valid for `mode`: no unmatched, duplicate, forbidden, malformed, or
    /// colliding disclosures, no duplicate digests, a usable `sd_alg`, and
    /// (Holder only) no undisclosed digests.
    pub fn is_valid(&self, mode: MatchMode) -> bool {
        let _ = mode;
        unimplemented!()
    }
}

/// Matches disclosures to digests, recursing into disclosed values
/// (sd-cwt-08 §7, Appendix G), and rebuilds the claims set.
pub fn match_disclosures<'a>(sd: &SdCwt<'a>) -> SdReport<'a> {
    let _ = sd;
    unimplemented!()
}
