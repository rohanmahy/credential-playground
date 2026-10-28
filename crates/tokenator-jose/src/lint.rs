//! Facts the core's linter needs. Judgement (severity, wording) is the
//! core's job.

use tokenator_crypto::{Alg, KeyMismatch};
use tokenator_json::{Node, Span};
use tokenator_keys::{Jwk, Key, KeyError};

/// The header `alg`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgFact {
    /// Absent.
    Missing,
    /// Not a string.
    NotAString,
    /// `none`.
    None,
    /// A supported algorithm.
    Known(Alg),
    /// A string naming an unsupported algorithm.
    Unsupported(String),
}

/// A header member expected to be a string (`typ`, `cty`, `kid`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrFact {
    /// Absent.
    Absent,
    /// A string.
    Value(String),
    /// Present but not a string.
    NotAString,
}

/// The header `crit` (RFC 7515 §4.1.11). This crate understands no
/// extension parameters, so every proper entry is not understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CritFact {
    /// Absent.
    Absent,
    /// Not an array of strings.
    Malformed,
    /// An empty array (forbidden).
    Empty,
    /// The entries, sorted into what is wrong with them.
    Entries {
        /// Extension names this crate does not understand (all proper ones).
        not_understood: Vec<String>,
        /// Names defined by RFC 7515/7518 itself (`alg`, `kid`, ...), which
        /// must not be listed.
        registered: Vec<String>,
        /// Listed names that are not present in the header.
        missing: Vec<String>,
    },
}

/// Header facts for the linter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderFacts {
    /// `alg`.
    pub alg: AlgFact,
    /// `typ`.
    pub typ: StrFact,
    /// `cty`.
    pub cty: StrFact,
    /// `kid`.
    pub kid: StrFact,
    /// `crit`.
    pub crit: CritFact,
}

/// Facts about a header object (a non-object gives all-absent facts with
/// `alg: Missing`).
pub fn header_facts(header: &Node<'_>) -> HeaderFacts {
    unimplemented!()
}

/// A member name that occurs more than once in one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateMember {
    /// RFC 6901 pointer to the object.
    pub pointer: String,
    /// The repeated (decoded) name.
    pub name: String,
    /// Key spans of every occurrence, in order (relative to the tree's
    /// source bytes; empty for synthesized keys).
    pub spans: Vec<Span>,
}

/// Every repeated member name in `node`, depth-first in document order.
pub fn duplicate_members(node: &Node<'_>) -> Vec<DuplicateMember> {
    unimplemented!()
}

/// The `cnf` claim of a payload (RFC 7800).
#[derive(Debug, Clone)]
pub enum CnfFact {
    /// No `cnf`.
    Absent,
    /// `cnf` is not an object.
    NotAnObject,
    /// `cnf.jwk` (an object; whether it imports is a separate question).
    Jwk(Jwk),
    /// `cnf.kid` as a string.
    Kid(String),
    /// Neither `jwk` nor `kid`; the member names present.
    Other(Vec<String>),
}

/// Reads `cnf` from a payload. `jwk` wins over `kid` when both are present.
pub fn cnf(payload: &Node<'_>) -> CnfFact {
    unimplemented!()
}

/// `tokenator_crypto::check_key` for a key (including its declared `alg`).
pub fn key_findings(alg: Alg, key: &Key) -> Vec<KeyMismatch> {
    unimplemented!()
}

/// `tokenator_crypto::check_key` for a JWK (e.g. `cnf.jwk`), without
/// needing valid key material.
pub fn jwk_findings(alg: Alg, jwk: &Jwk) -> Result<Vec<KeyMismatch>, KeyError> {
    unimplemented!()
}
