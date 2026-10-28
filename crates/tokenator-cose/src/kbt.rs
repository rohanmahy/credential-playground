//! SD-KBT (key binding token): Disclose, Present, and verification
//! (draft-ietf-spice-sd-cwt-08 §8, §9).
#![allow(clippy::unimplemented)]

use std::borrow::Cow;

use tokenator_cbor::Item;
use tokenator_crypto::{Alg, rand_core::CryptoRng};
use tokenator_keys::Key;

use crate::claims::{Cnf, TimeStatus};
use crate::sd::{SdCwt, SdReport, Typ};
use crate::{ContentType, CoseError, Sign1, Sign1Backend};

/// Which disclosures of an SD-CWT to keep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// All, in their current order.
    All,
    /// None: `sd_claims` is omitted (sd-cwt-08 §3.3).
    None,
    /// These indices, in this order (repeats allowed).
    Indices(Vec<usize>),
}

/// Keeps the selected disclosures of an SD-CWT (or of the SD-CWT inside an
/// SD-KBT, without re-signing the KBT) and returns the new token. Only
/// `sd_claims` changes; every other byte is copied, and the selected
/// disclosure bstrs keep their exact encoding.
pub fn disclose(
    backend: &dyn Sign1Backend,
    credential: &[u8],
    selection: &Selection,
) -> Result<Vec<u8>, CoseError> {
    let _ = (backend, credential, selection);
    unimplemented!()
}

/// Options for [`present`].
#[derive(Debug, Clone, PartialEq)]
pub struct PresentOptions<'a> {
    /// Disclosures to include.
    pub selection: Selection,
    /// KBT signature algorithm.
    pub alg: Alg,
    /// `aud` (3), required by the draft.
    pub aud: Option<Cow<'a, str>>,
    /// `iat` (6).
    pub iat: Option<i64>,
    /// `cti` (7).
    pub cti: Option<Cow<'a, [u8]>>,
    /// `cnonce` (39).
    pub cnonce: Option<Cow<'a, [u8]>>,
    /// More KBT claims, written after the standard ones.
    pub extra_claims: Vec<(Item<'a>, Item<'a>)>,
    /// `typ` ([`Typ::Auto`] writes 294).
    pub typ: Typ,
    /// More protected header entries, written after `typ`.
    pub protected_extra: Vec<(Item<'a>, Item<'a>)>,
    /// Tags of the KBT, outermost first. Default `[18]`.
    pub tags: Vec<u64>,
}

impl PresentOptions<'_> {
    /// All disclosures, `alg`, no claims, automatic typ, tag 18.
    pub fn new(alg: Alg) -> PresentOptions<'static> {
        PresentOptions {
            selection: Selection::All,
            alg,
            aud: None,
            iat: None,
            cti: None,
            cnonce: None,
            extra_claims: Vec::new(),
            typ: Typ::Auto,
            protected_extra: Vec::new(),
            tags: vec![crate::codepoints::TAG_COSE_SIGN1],
        }
    }
}

/// Builds an SD-KBT for `credential` (an SD-CWT or a plain CWT), signed by
/// the holder key.
///
/// The KBT protected header is `alg` (1), `kcwt` (13), `typ` (16), then
/// extras; `kcwt` holds the credential's COSE_Sign1 as `18([...])` (tag 61
/// removed, tag 18 added if missing) with its protected header, payload,
/// and signature bytes copied verbatim and `sd_claims` reduced to the
/// selection. The unprotected header is `{}`. The payload is `aud` (3),
/// `iat` (6), `cti` (7), `cnonce` (39), then extras. Without `rng`,
/// signing is deterministic.
pub fn present(
    backend: &dyn Sign1Backend,
    credential: &[u8],
    holder: &Key,
    opts: &PresentOptions<'_>,
    rng: Option<&mut dyn CryptoRng>,
) -> Result<Vec<u8>, CoseError> {
    let _ = (backend, credential, holder, opts, rng);
    unimplemented!()
}

/// Inputs for [`verify_kbt`].
#[derive(Debug, Clone, Default)]
pub struct KbtOptions<'a> {
    /// Current time, seconds since the epoch.
    pub now: i64,
    /// Allowed skew in seconds.
    pub skew: u64,
    /// The expected `aud`; `None` skips the check.
    pub expected_aud: Option<Cow<'a, str>>,
    /// The expected `cnonce`; `None` skips the check.
    pub expected_cnonce: Option<Cow<'a, [u8]>>,
    /// Maximum age of the KBT `iat` in seconds; `None` skips the check.
    pub max_age: Option<u64>,
    /// Keys that a `cnf` kid or thumbprint may refer to.
    pub holder_keys: Vec<Key>,
}

/// One logical time constraint from sd-cwt-08 §9 steps 3 and 7 that does
/// not hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimeRule {
    /// SD-CWT: nbf <= iat.
    SdNbfAfterIat,
    /// SD-CWT: nbf < exp.
    SdNbfNotBeforeExp,
    /// SD-CWT: iat < exp.
    SdIatNotBeforeExp,
    /// KBT: nbf <= iat.
    KbtNbfAfterIat,
    /// KBT: iat < exp.
    KbtIatNotBeforeExp,
    /// KBT exp <= SD-CWT exp.
    KbtExpAfterSdExp,
    /// KBT nbf >= SD-CWT nbf.
    KbtNbfBeforeSdNbf,
    /// KBT iat >= SD-CWT iat.
    KbtIatBeforeSdIat,
    /// KBT nbf < SD-CWT exp.
    KbtNbfNotBeforeSdExp,
    /// KBT iat < SD-CWT exp.
    KbtIatNotBeforeSdExp,
    /// KBT iat >= SD-CWT nbf.
    KbtIatBeforeSdNbf,
}

/// A rule an SD-KBT breaks (beyond signatures and disclosure matching).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum KbtFinding {
    /// `kcwt` is not a COSE_Sign1.
    KcwtNotSign1,
    /// KBT `typ` missing.
    TypMissing,
    /// KBT `typ` is not 294 / `application/kb+cwt`.
    TypUnexpected(ContentType),
    /// The KBT protected header has a CWT Claims (15) parameter (§5.3).
    CwtClaimsHeader,
    /// KBT has `iss` (§8.1 Table 3).
    IssPresent,
    /// KBT has `sub`.
    SubPresent,
    /// KBT has no `aud`.
    AudMissing,
    /// `aud` (KBT or SD-CWT) is not the expected value.
    AudMismatch,
    /// KBT has neither `iat` nor `cti`.
    NoIatOrCti,
    /// KBT has `exp` or `nbf` without `iat`.
    TimeWithoutIat,
    /// A cnonce was expected but is missing.
    CnonceMissing,
    /// The cnonce differs from the expected one.
    CnonceMismatch,
    /// A time constraint between claims fails.
    Time(TimeRule),
    /// An SD-CWT time claim fails against the clock.
    SdCwtClock(TimeStatus),
    /// A KBT time claim fails against the clock (incl. `iat` in the future).
    KbtClock(TimeStatus),
    /// KBT `iat` is older than `max_age`.
    Stale,
    /// Indefinite-length CBOR somewhere in the KBT or SD-CWT (§5.1).
    IndefiniteLength,
    /// `sd_claims` is an empty array (§9 step 2).
    EmptySdClaims,
}

/// The result of [`verify_kbt`]. Each check is reported; nothing stops at
/// the first failure.
#[derive(Debug, Clone, PartialEq)]
pub struct KbtReport<'a> {
    /// The KBT.
    pub kbt: Sign1<'a>,
    /// The SD-CWT from `kcwt` (spans relative to its own bytes, with
    /// `sign1.base` set).
    pub sd_cwt: Option<SdCwt<'a>>,
    /// Issuer signature over the SD-CWT; `Err(CoseError::NoKey)` without an
    /// issuer key.
    pub issuer_signature: Result<Alg, CoseError>,
    /// KBT signature with the `cnf` key.
    pub kbt_signature: Result<Alg, CoseError>,
    /// The parsed `cnf` claim of the SD-CWT.
    pub cnf: Option<Result<Cnf<'a>, CoseError>>,
    /// Disclosure matching of the SD-CWT (Verifier mode applies).
    pub sd: Option<SdReport<'a>>,
    /// Other rule violations.
    pub findings: Vec<KbtFinding>,
}

impl KbtReport<'_> {
    /// Both signatures valid, the SD report valid in Verifier mode, and no
    /// findings.
    pub fn is_valid(&self) -> bool {
        unimplemented!()
    }
}

/// Verifies an SD-KBT (sd-cwt-08 §9). Fails only when the input is not a
/// COSE_Sign1 at all, or has no `kcwt` ([`CoseError::NotKbt`]).
pub fn verify_kbt<'a>(
    backend: &dyn Sign1Backend,
    bytes: &'a [u8],
    issuer_key: Option<&Key>,
    opts: &KbtOptions<'_>,
) -> Result<KbtReport<'a>, CoseError> {
    let _ = (backend, bytes, issuer_key, opts);
    unimplemented!()
}
