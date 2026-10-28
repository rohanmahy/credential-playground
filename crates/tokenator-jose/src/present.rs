//! Choosing disclosures and adding a KB-JWT (RFC 9901 §7.2).

use tokenator_crypto::Alg;
use tokenator_crypto::rand_core::CryptoRng;
use tokenator_keys::Key;

use crate::error::JoseError;
use crate::issue::JsonStyle;
use crate::parse::SdJwt;

/// A problem with a chosen set of disclosures. Reported, never fixed: the
/// output contains exactly the disclosures asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionFinding {
    /// The digest of `disclosure` is embedded in disclosure `parent`, which
    /// is not kept (RFC 9901 §7.2 step 2). Only the immediate parent is
    /// reported; a missing grandparent is reported for the parent.
    MissingParent {
        /// The kept disclosure.
        disclosure: usize,
        /// The disclosure holding its digest.
        parent: usize,
    },
    /// The digest of `disclosure` is embedded nowhere: not in the payload,
    /// not in any disclosure of the input.
    Unreachable {
        /// The kept disclosure.
        disclosure: usize,
    },
    /// `disclosure` is kept more than once (RFC 9901 §4 forbids sending a
    /// disclosure twice). Reported once per extra occurrence.
    Duplicate {
        /// The disclosure.
        disclosure: usize,
    },
}

/// The checked selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// Input disclosure indexes in output order (as given, duplicates kept).
    pub kept: Vec<usize>,
    /// Problems, ordered by position in `kept`.
    pub findings: Vec<SelectionFinding>,
}

/// Checks keeping `keep` (indexes into `sd.disclosures`, in the order they
/// will be sent) without building anything.
pub fn select(sd: &SdJwt<'_>, keep: &[usize]) -> Result<Selection, JoseError> {
    unimplemented!()
}

/// Options for the KB-JWT (RFC 9901 §4.3).
#[derive(Debug, Clone)]
pub struct KbOptions<'k> {
    /// The holder's private key.
    pub key: &'k Key,
    /// The signature algorithm.
    pub alg: Alg,
    /// Header `typ`; `None` omits it (non-conformant, for experiments).
    pub typ: Option<String>,
    /// `aud`.
    pub aud: String,
    /// `nonce`.
    pub nonce: String,
    /// `iat`, NumericDate seconds.
    pub iat: i64,
    /// Style of the KB-JWT header and payload.
    pub style: JsonStyle,
}

impl<'k> KbOptions<'k> {
    /// `typ: kb+jwt`, compact style.
    pub fn new(key: &'k Key, alg: Alg, aud: &str, nonce: &str, iat: i64) -> KbOptions<'k> {
        KbOptions {
            key,
            alg,
            typ: Some("kb+jwt".to_owned()),
            aud: aud.to_owned(),
            nonce: nonce.to_owned(),
            iat,
            style: JsonStyle::Compact,
        }
    }
}

/// A presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presented {
    /// The SD-JWT (or SD-JWT+KB), in the input's serialization.
    pub token: String,
    /// The checked selection.
    pub selection: Selection,
}

/// Builds the SD-JWT with exactly the disclosures `keep` (in that order)
/// and, with `kb`, a KB-JWT over it.
///
/// The issuer-signed JWT is copied byte for byte and any KB-JWT of the
/// input is dropped. The KB-JWT header is `alg` then `typ`; its payload is
/// `nonce`, `aud`, `iat`, `sd_hash` (the RFC 9901 order), with `sd_hash`
/// computed with the payload's `_sd_alg` over
/// [`SdJwt::sd_hash_input`] of the result. A JSON serialization stays JSON:
/// `disclosures` and `kb_jwt` are replaced in the first unprotected header
/// and everything else is copied. Selection problems are reported in
/// [`Presented::selection`], never corrected.
pub fn present(
    sd: &SdJwt<'_>,
    keep: &[usize],
    kb: Option<&KbOptions<'_>>,
    rng: &mut dyn CryptoRng,
) -> Result<Presented, JoseError> {
    unimplemented!()
}
