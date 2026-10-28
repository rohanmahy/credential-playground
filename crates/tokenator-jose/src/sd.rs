//! SD-JWT semantics: disclosures, digests, matching, and processing
//! (RFC 9901 §4.2, §7.1).

use tokenator_crypto::HashAlg;
use tokenator_json::{JsonError, Node};

use crate::b64::B64Error;
use crate::parse::Disclosure;

/// Why a disclosure is not a valid `[salt, name, value]` / `[salt, value]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisclosureError {
    /// The base64url text did not decode.
    Base64(B64Error),
    /// The decoded bytes are not JSON.
    Json(JsonError),
    /// The JSON is not an array.
    NotAnArray,
    /// An array with other than 2 or 3 elements.
    WrongLength(usize),
    /// The salt is not a string.
    SaltNotString,
    /// The claim name of a 3-element disclosure is not a string.
    NameNotString,
}

/// Whether a disclosure is for an object property or an array element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisclosureKind {
    /// `[salt, name, value]` (RFC 9901 §4.2.1).
    Property,
    /// `[salt, value]` (RFC 9901 §4.2.2).
    ArrayElement,
}

/// A decoded, well-formed disclosure. Forbidden names (`_sd`, `...`) are
/// accepted here and reported by [`process`].
#[derive(Debug, Clone)]
pub struct DisclosureView<'b> {
    tree: Node<'b>,
}

impl<'b> DisclosureView<'b> {
    /// The decoded JSON array; spans are relative to the decoded bytes.
    pub fn tree(&self) -> &Node<'b> {
        unimplemented!()
    }

    /// Property or array element.
    pub fn kind(&self) -> DisclosureKind {
        unimplemented!()
    }

    /// The salt.
    pub fn salt(&self) -> &str {
        unimplemented!()
    }

    /// The claim name, for a property disclosure.
    pub fn name(&self) -> Option<&str> {
        unimplemented!()
    }

    /// The claim value or array element.
    pub fn value(&self) -> &Node<'b> {
        unimplemented!()
    }
}

/// The `_sd_alg` of a payload (RFC 9901 §4.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdAlg {
    /// No top-level `_sd_alg`; SHA-256 applies.
    Default,
    /// A supported hash name (`sha-256`, `sha-384`, `sha-512`).
    Named(HashAlg),
    /// A string naming an unsupported hash (names are case-sensitive, so
    /// `SHA-256` lands here).
    Unsupported(String),
    /// `_sd_alg` is present but not a string.
    NotAString,
}

impl SdAlg {
    /// The hash to use, if supported.
    pub fn hash(&self) -> Option<HashAlg> {
        unimplemented!()
    }
}

/// Reads the top-level `_sd_alg` of `payload`.
pub fn sd_alg(payload: &Node<'_>) -> SdAlg {
    unimplemented!()
}

/// Base64url of `hash` over the ASCII bytes of `text`: a disclosure digest
/// (RFC 9901 §4.2.3) or an `sd_hash` (§4.3.1).
///
/// ```
/// use tokenator_crypto::HashAlg;
/// assert_eq!(
///     tokenator_jose::sd_digest(
///         "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0",
///         HashAlg::Sha256,
///     ),
///     "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"
/// );
/// ```
pub fn sd_digest(text: &str, hash: HashAlg) -> String {
    unimplemented!()
}

/// Where a digest slot lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Container {
    /// In the issuer payload.
    Payload,
    /// Inside disclosure `n` (a recursive disclosure).
    Disclosure(usize),
}

/// How a digest is embedded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlotKind {
    /// An entry of an `_sd` array (object property).
    Object,
    /// A `{"...": digest}` array element.
    ArrayElement,
}

/// One embedded digest found in the payload or in a matched disclosure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestSlot {
    /// The digest string as embedded.
    pub digest: String,
    /// `_sd` entry or array element.
    pub kind: SlotKind,
    /// Payload or disclosure.
    pub container: Container,
    /// RFC 6901 pointer within the container's tree (the payload, or the
    /// disclosure's whole array) to the `_sd` entry (e.g. `/address/_sd/1`,
    /// `/2/_sd/0`) or to the `{"...": digest}` element (e.g.
    /// `/nationalities/0`).
    pub pointer: String,
    /// Index of the matching disclosure (set even if a finding keeps it
    /// from being inserted).
    pub disclosure: Option<usize>,
}

/// How one disclosure matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureMatch {
    /// Its digest under the payload's `_sd_alg`; `None` if that hash is
    /// not supported.
    pub digest: Option<String>,
    /// Index into [`SdReport::digests`] of the slot it fills.
    pub slot: Option<usize>,
}

/// A problem found while matching (each corresponds to a validation report
/// item; none of them stops processing).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SdFinding {
    /// The disclosure matches no digest reachable from the payload (directly
    /// or through other matched disclosures).
    UnmatchedDisclosure {
        /// Disclosure index.
        disclosure: usize,
    },
    /// The same digest is embedded more than once (RFC 9901 §7.1 step 4).
    /// Only the first slot can be filled; the others are not also reported
    /// as [`SdFinding::DigestWithoutDisclosure`].
    DuplicateDigest {
        /// The digest.
        digest: String,
        /// Indexes into [`SdReport::digests`], in walk order.
        slots: Vec<usize>,
    },
    /// Several disclosures have the same digest (the same disclosure sent
    /// more than once). Only the first is used; the others are not also
    /// reported as [`SdFinding::UnmatchedDisclosure`].
    DuplicateDisclosure {
        /// Disclosure indexes, in input order.
        disclosures: Vec<usize>,
    },
    /// A slot no disclosure fills: a decoy, or a withheld claim.
    DigestWithoutDisclosure {
        /// Index into [`SdReport::digests`].
        slot: usize,
    },
    /// A property disclosure named `_sd` or `...`. It is not inserted.
    ForbiddenName {
        /// Disclosure index.
        disclosure: usize,
        /// The name.
        name: String,
    },
    /// A property disclosure matched an array slot, or an array-element
    /// disclosure matched an `_sd` slot. It is not inserted.
    KindMismatch {
        /// Disclosure index.
        disclosure: usize,
        /// Index into [`SdReport::digests`].
        slot: usize,
    },
    /// The disclosed name already exists in the object holding the `_sd`
    /// array. The existing member is kept; the disclosure is not inserted.
    NameCollision {
        /// Disclosure index.
        disclosure: usize,
        /// The name.
        name: String,
    },
    /// The disclosure could not be decoded. It is still hashed, so it may
    /// fill a slot (then it is not also unmatched), but nothing is inserted.
    MalformedDisclosure {
        /// Disclosure index.
        disclosure: usize,
        /// Why.
        error: DisclosureError,
    },
    /// An `_sd` member whose value is not an array.
    SdNotArray {
        /// Where.
        container: Container,
        /// Pointer to the `_sd` member.
        pointer: String,
    },
    /// A non-string entry in an `_sd` array.
    SdEntryNotString {
        /// Where.
        container: Container,
        /// Pointer to the entry.
        pointer: String,
    },
    /// An array element object with a `...` member that is not a slot
    /// (other members besides `...`, or a non-string value). It is kept as
    /// an ordinary element.
    MalformedArrayDigest {
        /// Where.
        container: Container,
        /// Pointer to the element.
        pointer: String,
    },
    /// `_sd_alg` anywhere but the top level of the payload. It is left in
    /// place.
    NestedSdAlg {
        /// Where.
        container: Container,
        /// Pointer to the `_sd_alg` member.
        pointer: String,
    },
    /// `_sd_alg` is unsupported or not a string. Slots are still listed,
    /// but no matching is done, so no unmatched/without-disclosure findings
    /// are reported.
    UnsupportedSdAlg,
}

/// The result of matching disclosures to digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdReport {
    /// The payload's `_sd_alg`.
    pub sd_alg: SdAlg,
    /// Every slot, in walk order: depth-first through the payload in member
    /// and element order, where a matched disclosure's value is walked right
    /// after the slot it fills (so its own slots come next).
    pub digests: Vec<DigestSlot>,
    /// One entry per input disclosure, in input order.
    pub disclosures: Vec<DisclosureMatch>,
    /// Problems: first `UnsupportedSdAlg`, then those met during the walk
    /// (in walk order), then duplicate digests (by first slot), duplicate
    /// disclosures (by first index), digests without disclosures (by slot),
    /// and finally unfilled disclosures by index (`MalformedDisclosure`
    /// before `UnmatchedDisclosure` for the same one).
    pub findings: Vec<SdFinding>,
}

/// Processed claims plus the matching report.
#[derive(Debug, Clone)]
pub struct Processed<'s> {
    /// The Processed SD-JWT Payload (RFC 9901 §7.1): every `_sd` removed,
    /// each disclosed property appended to the end of its object in the
    /// order of its digest in `_sd`, array slots replaced in place, unfilled
    /// array slots removed, top-level `_sd_alg` removed. Nodes copied from
    /// the payload or a disclosure keep their spans (relative to their own
    /// decoded bytes).
    pub claims: Node<'s>,
    /// The matching report.
    pub report: SdReport,
}

/// Matches `disclosures` against the digests in `payload` (recursively
/// through matched disclosures) and reconstructs the processed claims.
///
/// Works on any payload tree, signed or not. Problems never abort: the
/// offending disclosure is left out and reported. A disclosure is inserted
/// at most once, even when its digest appears in several slots.
pub fn process<'s>(payload: &Node<'s>, disclosures: &'s [Disclosure<'_>]) -> Processed<'s> {
    unimplemented!()
}

impl core::fmt::Display for DisclosureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DisclosureError {}
