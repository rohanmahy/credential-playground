//! COSE_Sign1, CWT, SD-CWT, and SD-KBT.
//!
//! Everything here works on the original bytes: a parsed [`Sign1`] keeps the
//! exact protected header, payload, and signature bytes with their spans, and
//! signatures and disclosure digests are always computed over those bytes.
//! The crate does no I/O; time and randomness are always passed in.
//!
//! - [`Sign1Backend`] is the seam for COSE_Sign1 parsing, `Sig_structure`
//!   construction, assembly, signing, and verification. [`CborBackend`] is the
//!   span-preserving default built on `tokenator-cbor`.
//! - [`claims`]: CWT claims, time claims, and `cnf` (RFC 8392, RFC 8747).
//! - [`sd`]: SD-CWT redaction, disclosures, digests, and disclosure matching
//!   (draft-ietf-spice-sd-cwt-08).
//! - [`kbt`]: presenting an SD-CWT (or a plain CWT) in an SD-KBT, and
//!   verifying one.
//! - [`edit`]: re-signing and deliberate tampering.
//! - [`lint`]: conformance facts for the core's linter.
//!
//! The codepoints used are in [`codepoints`].

mod backend;
pub mod claims;
pub mod codepoints;
pub mod edit;
mod error;
pub mod kbt;
pub mod lint;
mod model;
pub mod sd;

pub use backend::{CborBackend, Sign1Backend, Sign1Parts, SignOptions, VerifyOptions};
pub use error::{CoseError, RedactionError};
pub use model::{
    Bstr, Bucket, ContentType, Diagnostic, DiagnosticKind, Part, Payload, RawBytes, Sign1,
    TokenKind,
};
/// Re-exported so callers name the same types as this crate's API.
pub use tokenator_cbor::{Item, Span, Value};
/// Re-exported so callers name the same types as this crate's API.
pub use tokenator_crypto::{Alg, DeclaredAlg, HashAlg, rand_core::CryptoRng};
/// Re-exported so callers name the same types as this crate's API.
pub use tokenator_keys::{Key, Label};
