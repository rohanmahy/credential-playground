//! Conformance facts for the core's linter (SPEC §6 "Conformance lint").
#![allow(clippy::unimplemented)]

use tokenator_cbor::Span;
use tokenator_crypto::{DeclaredAlg, KeyMismatch, KeyParams};
use tokenator_keys::Label;

use crate::{ContentType, CoseError, Part, Sign1Backend};

/// How serious a finding is. The linter never blocks anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Informational.
    Info,
    /// A likely problem.
    Warn,
}

/// Whose key an alg/key mismatch concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyRole {
    /// The key the caller says signed the token.
    Signer,
    /// The `cnf` key of an SD-CWT, checked against the KBT `alg`.
    Cnf,
}

/// What a [`Finding`] is about.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum FindingKind {
    /// A non-preferred or non-deterministic encoding from
    /// `tokenator-cbor`, with the bytes that would fix it.
    Encoding {
        /// The `tokenator-cbor` finding kind.
        kind: tokenator_cbor::FindingKind,
        /// Replacement bytes for the span.
        preferred_bytes: Vec<u8>,
    },
    /// A map with two keys that have the same preferred encoding
    /// (RFC 9052 §9, sd-cwt-08 §5.4). The span is the second key.
    DuplicateMapKey,
    /// A label in both header buckets (RFC 9052 §3).
    LabelInBothBuckets(Label),
    /// No `alg`.
    MissingAlg,
    /// An `alg` this crate does not support.
    UnsupportedAlg(DeclaredAlg),
    /// `alg` only in the unprotected header.
    AlgNotProtected,
    /// The key does not fit the header `alg` (`tokenator_crypto::check_key`).
    AlgKeyMismatch {
        /// Which key.
        role: KeyRole,
        /// The mismatches.
        mismatches: Vec<KeyMismatch>,
    },
    /// `crit` in the unprotected header (RFC 9052 §3.1).
    CritNotProtected,
    /// `crit` is an empty array or not an array.
    CritMalformed,
    /// A `crit` label that is not in the protected header.
    CritMissingLabel(Label),
    /// A `crit` label this crate does not process.
    CritNotUnderstood(Label),
    /// An SD-CWT or SD-KBT without `typ`.
    TypMissing,
    /// A `typ` that does not fit the token kind.
    TypUnexpected(ContentType),
    /// An empty protected header encoded as `h'a0'` instead of `h''`
    /// (RFC 9052 §3).
    EmptyProtectedNotZeroLength,
    /// A disclosure salt that is not 16 bytes (sd-cwt-08 §6.1).
    SaltLength(usize),
}

/// One lint finding.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// What.
    pub kind: FindingKind,
    /// How serious.
    pub severity: Severity,
    /// Which part (wrapped in [`Part::Kcwt`] inside an SD-KBT).
    pub part: Part,
    /// Absolute byte range in the linted input, when there is one.
    pub span: Option<Span>,
}

/// Inputs for [`lint`].
#[derive(Debug, Clone, Default)]
pub struct LintOptions {
    /// The signer's key parameters, checked against the header `alg`.
    pub signer: Option<KeyParams>,
}

/// Lints a COSE_Sign1, CWT, SD-CWT, or SD-KBT (recursing into `kcwt`).
///
/// Encoding findings are [`Severity::Warn`] where deterministic encoding is
/// required (protected header contents, payload contents, disclosures with
/// their bstr heads, and indefinite lengths anywhere in an SD-CWT/SD-KBT)
/// and [`Severity::Info`] elsewhere; `MapKeyOrder` is always `Info`. All
/// other kinds are `Warn`. Fails only when the input cannot be parsed.
pub fn lint(
    backend: &dyn Sign1Backend,
    bytes: &[u8],
    opts: &LintOptions,
) -> Result<Vec<Finding>, CoseError> {
    let _ = (backend, bytes, opts);
    unimplemented!()
}
