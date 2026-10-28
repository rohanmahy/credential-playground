//! JWS, JWT, SD-JWT, and KB-JWT.
//!
//! A pure library: no I/O, and time and randomness are always passed in.
//!
//! - [`parse`] reads JWS compact / JSON (flattened, general), SD-JWT, and
//!   SD-JWT+KB in either serialization. Every part keeps its original
//!   encoded text and its byte range in the input; decoded headers,
//!   payloads, and disclosures are `tokenator-json` trees. A part that
//!   fails to decode becomes a [`Diagnostic`] instead of an error.
//! - [`process`] matches disclosures to digests (RFC 9901 §7.1), reporting
//!   every problem as an [`SdFinding`] rather than aborting.
//! - [`issue`], [`select`] and [`present`] build JWTs, SD-JWTs, and
//!   presentations with KB-JWTs.
//! - [`verify_signature`], [`check_kb_jwt`] and [`check_time_claims`]
//!   return structured results for the core's validation report.
//! - [`resign`], [`assemble_compact`], [`tamper`], [`edit_disclosures`],
//!   [`to_compact`] and [`to_json`] make the deliberately broken or
//!   re-encoded artifacts the playground needs.
//! - [`header_facts`], [`duplicate_members`], [`cnf`], [`key_findings`] and
//!   [`jwk_findings`] feed the core's linter.
//!
//! ```no_run
//! use tokenator_jose::{parse, verify_signature};
//! # fn demo(text: &str, issuer: &tokenator_keys::Key) -> Result<(), Box<dyn std::error::Error>> {
//! let parsed = parse(text)?;
//! let alg = verify_signature(parsed.token.jws(), 0, issuer)?;
//! if let Some(sd) = parsed.token.sd_jwt() {
//!     let processed = sd.process()?;
//!     println!("{alg:?}: {} findings", processed.report.findings.len());
//! }
//! # Ok(()) }
//! ```

// Skeleton: the implementation replaces every `unimplemented!()`.
#![allow(unused_variables, dead_code, clippy::unimplemented)]

mod b64;
mod error;
mod issue;
mod lint;
mod manipulate;
mod parse;
mod present;
mod sd;
mod verify;

pub use b64::{B64Error, b64u_decode, b64u_encode};
pub use error::JoseError;
pub use issue::{
    Cnf, DecoyDigests, DecoySpec, DigestOrder, IssueOptions, Issued, IssuedDisclosure, JsonStyle,
    SaltSource, issue,
};
pub use lint::{
    AlgFact, CnfFact, CritFact, DuplicateMember, HeaderFacts, StrFact, cnf, duplicate_members,
    header_facts, jwk_findings, key_findings,
};
pub use manipulate::{
    Converted, DisclosureOp, Edits, JsonSerialization, RawParts, Tamper, assemble_compact,
    edit_disclosures, resign, tamper, to_compact, to_json,
};
pub use parse::{
    B64Part, Diagnostic, DiagnosticKind, Disclosure, Jws, JwsSignature, ParseError, Parsed,
    PartError, PartRef, SdJwt, Serialization, Token, parse,
};
pub use present::{KbOptions, Presented, Selection, SelectionFinding, present, select};
pub use sd::{
    Container, DigestSlot, DisclosureError, DisclosureKind, DisclosureMatch, DisclosureView,
    Processed, SdAlg, SdFinding, SdReport, SlotKind, process, sd_alg, sd_digest,
};
/// Byte ranges, shared with `tokenator-json`.
pub use tokenator_json::Span;
pub use verify::{
    HolderKey, KbExpectations, KbReport, TimeReport, TimeStatus, ValueCheck, VerifyError,
    check_kb_jwt, check_time_claims, verify_signature,
};
