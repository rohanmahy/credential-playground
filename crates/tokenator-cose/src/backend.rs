//! The [`Sign1Backend`] seam and its default implementation.
#![allow(clippy::unimplemented)]

use std::borrow::Cow;

use tokenator_cbor::Item;
use tokenator_crypto::{Alg, rand_core::CryptoRng};
use tokenator_keys::Key;

use crate::{CoseError, Sign1};

/// The four elements of a COSE_Sign1 plus its tags, as raw parts.
///
/// [`Sign1Backend::assemble`] writes them out without checking anything, so
/// this is also how tampered tokens are built.
#[derive(Debug, Clone, PartialEq)]
pub struct Sign1Parts<'a> {
    /// Tags, outermost first (e.g. `[18]`, `[61, 18]`, or none).
    pub tags: Vec<u64>,
    /// Protected header bstr contents, used verbatim.
    pub protected: Cow<'a, [u8]>,
    /// Unprotected header (normally a map), encoded with
    /// `EncodeMode::Preserve`.
    pub unprotected: Item<'a>,
    /// Payload bstr contents, or `None` for a detached payload (`nil`).
    pub payload: Option<Cow<'a, [u8]>>,
    /// Signature bstr contents.
    pub signature: Cow<'a, [u8]>,
}

impl<'a> Sign1Parts<'a> {
    /// The parts of a parsed message, borrowing its bytes. Fails with
    /// [`CoseError::MalformedPart`] if the protected header, unprotected
    /// header, or signature is missing or of the wrong type.
    pub fn from_sign1(msg: &Sign1<'a>) -> Result<Sign1Parts<'a>, CoseError> {
        let _ = msg;
        unimplemented!()
    }
}

/// Options for [`Sign1Backend::sign`].
#[derive(Debug, Clone, Copy)]
pub struct SignOptions<'a> {
    /// The signature algorithm. It is not checked against the `alg` in the
    /// protected header, so a mismatch can be produced on purpose.
    pub alg: Alg,
    /// RFC 9052 §4.3 externally supplied data (default empty).
    pub external_aad: &'a [u8],
    /// The payload to sign when `parts.payload` is `None` (detached).
    pub detached_payload: Option<&'a [u8]>,
}

impl SignOptions<'_> {
    /// Options for `alg` with no external AAD and no detached payload.
    pub fn new(alg: Alg) -> SignOptions<'static> {
        SignOptions {
            alg,
            external_aad: &[],
            detached_payload: None,
        }
    }
}

/// Options for [`Sign1Backend::verify`].
#[derive(Debug, Clone, Copy, Default)]
pub struct VerifyOptions<'a> {
    /// RFC 9052 §4.3 externally supplied data (default empty).
    pub external_aad: &'a [u8],
    /// The payload, required when the message's payload is `nil`.
    pub detached_payload: Option<&'a [u8]>,
    /// Verify with this algorithm instead of the header `alg`.
    pub alg: Option<Alg>,
}

/// COSE_Sign1 parsing, `Sig_structure` construction, assembly, signing, and
/// verification.
///
/// The span-preserving [`CborBackend`] is the default. Another backend (for
/// example one built on `coset`) can be swapped in for signing and
/// validation; display models always come from `tokenator-cbor`. Every
/// high-level operation in this crate takes a `&dyn Sign1Backend` and goes
/// through it.
pub trait Sign1Backend {
    /// Parses a COSE_Sign1, tagged (18), CWT-tagged (61), or untagged.
    ///
    /// Fails only when the input is not well-formed CBOR, is a different
    /// COSE structure, or is not an array under its tags. Malformed parts
    /// give a partial result with [`Diagnostic`](crate::Diagnostic)s.
    fn parse<'a>(&self, bytes: &'a [u8]) -> Result<Sign1<'a>, CoseError>;

    /// The encoded RFC 9052 §4.4 `Sig_structure` for COSE_Sign1:
    /// `["Signature1", protected, external_aad, payload]` with each byte
    /// string used verbatim and every head in preferred (shortest) form.
    fn sig_structure(&self, protected: &[u8], external_aad: &[u8], payload: &[u8]) -> Vec<u8>;

    /// Encodes parts as a COSE_Sign1: the tags, a 4-element array, the
    /// protected bstr, the unprotected item (Preserve), the payload bstr or
    /// `nil`, and the signature bstr. Byte string heads are preferred.
    fn assemble(&self, parts: &Sign1Parts<'_>) -> Vec<u8>;

    /// Signs `parts` (ignoring `parts.signature`) and returns the assembled
    /// COSE_Sign1. Without `rng`, signing is deterministic
    /// (`tokenator_crypto::sign_deterministic`), which fails for PSS.
    fn sign(
        &self,
        parts: &Sign1Parts<'_>,
        key: &Key,
        opts: &SignOptions<'_>,
        rng: Option<&mut dyn CryptoRng>,
    ) -> Result<Vec<u8>, CoseError> {
        let _ = (parts, key, opts, rng);
        unimplemented!()
    }

    /// Verifies `msg` with the public part of `key` and returns the
    /// algorithm used: `opts.alg`, else the header `alg`.
    fn verify(
        &self,
        msg: &Sign1<'_>,
        key: &Key,
        opts: &VerifyOptions<'_>,
    ) -> Result<Alg, CoseError> {
        let _ = (msg, key, opts);
        unimplemented!()
    }
}

/// The default, span-preserving backend over `tokenator-cbor`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CborBackend;

impl Sign1Backend for CborBackend {
    fn parse<'a>(&self, bytes: &'a [u8]) -> Result<Sign1<'a>, CoseError> {
        let _ = bytes;
        unimplemented!()
    }

    fn sig_structure(&self, protected: &[u8], external_aad: &[u8], payload: &[u8]) -> Vec<u8> {
        let _ = (protected, external_aad, payload);
        unimplemented!()
    }

    fn assemble(&self, parts: &Sign1Parts<'_>) -> Vec<u8> {
        let _ = parts;
        unimplemented!()
    }
}
