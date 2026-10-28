//! Verification primitives. The core composes them into the user-facing
//! validation report.

use std::borrow::Cow;

use tokenator_crypto::{Alg, CryptoError, alg_from_jose, verify};
use tokenator_json::{Node, Value};
use tokenator_keys::{Jwk, Key, KeyError, from_jwk};

use crate::b64::B64Error;
use crate::parse::{Jws, SdJwt};
use crate::sd::{SdAlg, sd_alg, sd_digest};

/// The `typ` a KB-JWT must have (RFC 9901 §4.3).
const KB_TYP: &str = "kb+jwt";

/// Why a signature did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyError {
    /// No signature with that index.
    NoSuchSignature(usize),
    /// No key to verify with (e.g. a KB-JWT whose `cnf` gave none).
    NoKey,
    /// The protected header (or, without one, the unprotected header) does
    /// not decode or is not a JSON object.
    HeaderUnreadable,
    /// No `alg` in the protected or unprotected header.
    MissingAlg,
    /// `alg` is not a string.
    AlgNotString,
    /// `alg` is `none` (RFC 7518 §3.6). Never accepted.
    AlgNone,
    /// `alg` is a string this crate does not support (e.g. `HS256`).
    UnsupportedAlg(String),
    /// The signature's base64url does not decode.
    SignatureUnreadable(B64Error),
    /// `tokenator-crypto` refused: [`CryptoError::InvalidSignature`] for a
    /// bad signature, [`CryptoError::KeyNotSuitable`] for a key that does
    /// not fit `alg`.
    Crypto(CryptoError),
}

/// Verifies signature `index` of `jws` with `key` (public or private).
///
/// `alg` comes from the protected header, or else from the unprotected
/// header (JSON serialization). The signing input is the original encoded
/// text, so any change to the header or payload bytes fails. Returns the
/// algorithm used.
pub fn verify_signature(jws: &Jws<'_>, index: usize, key: &Key) -> Result<Alg, VerifyError> {
    let sig = jws
        .signatures
        .get(index)
        .ok_or(VerifyError::NoSuchSignature(index))?;
    let protected = match &sig.protected {
        Some(part) => match part.json() {
            Ok(node) if node.members().is_some() => Some(node),
            _ => return Err(VerifyError::HeaderUnreadable),
        },
        None => None,
    };
    let alg_node = protected
        .as_ref()
        .and_then(|h| h.get("alg"))
        .or_else(|| sig.unprotected.as_ref()?.get("alg"))
        .ok_or(VerifyError::MissingAlg)?;
    let alg = match alg_node.value() {
        Value::String(name) if name == "none" => return Err(VerifyError::AlgNone),
        Value::String(name) => {
            alg_from_jose(name).ok_or_else(|| VerifyError::UnsupportedAlg(name.to_string()))?
        }
        _ => return Err(VerifyError::AlgNotString),
    };
    let signature = sig
        .signature
        .decoded()
        .map_err(VerifyError::SignatureUnreadable)?;
    let input = jws
        .signing_input(index)
        .ok_or(VerifyError::NoSuchSignature(index))?;
    verify(alg, &key.public_key(), input.as_bytes(), signature).map_err(VerifyError::Crypto)?;
    Ok(alg)
}

/// The status of one time claim (NumericDate seconds; fractions allowed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeStatus {
    /// The claim is absent.
    Absent,
    /// Present and acceptable.
    Valid,
    /// `exp`: `now >= exp + skew`.
    Expired,
    /// `nbf`: `now + skew < nbf`.
    NotYetValid,
    /// `iat`: `iat > now + skew`.
    InFuture,
    /// `iat` with a maximum age: `now > iat + max_age + skew`.
    TooOld,
    /// Present but not a JSON number.
    NotANumber,
}

/// `exp`, `nbf`, and `iat` of a claim set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeReport {
    /// `exp` (RFC 7519 §4.1.4).
    pub exp: TimeStatus,
    /// `nbf` (RFC 7519 §4.1.5).
    pub nbf: TimeStatus,
    /// `iat` (RFC 7519 §4.1.6): only checked for being in the future.
    pub iat: TimeStatus,
}

/// Checks the time claims of `claims` (a top-level object) against the
/// injected clock `now` with `skew` seconds of tolerance.
pub fn check_time_claims(claims: &Node<'_>, now: i64, skew: u64) -> TimeReport {
    let (now, skew) = (now as f64, skew as f64);
    let exp = match numeric_date(claims, "exp") {
        Err(s) => s,
        Ok(t) if now >= t + skew => TimeStatus::Expired,
        Ok(_) => TimeStatus::Valid,
    };
    let nbf = match numeric_date(claims, "nbf") {
        Err(s) => s,
        Ok(t) if now + skew < t => TimeStatus::NotYetValid,
        Ok(_) => TimeStatus::Valid,
    };
    let iat = match numeric_date(claims, "iat") {
        Err(s) => s,
        Ok(t) if t > now + skew => TimeStatus::InFuture,
        Ok(_) => TimeStatus::Valid,
    };
    TimeReport { exp, nbf, iat }
}

/// What the verifier expects of a KB-JWT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KbExpectations<'e> {
    /// Expected `aud`; `None` reports the value unchecked.
    pub aud: Option<&'e str>,
    /// Expected `nonce`; `None` reports the value unchecked.
    pub nonce: Option<&'e str>,
    /// The clock.
    pub now: i64,
    /// Allowed skew in seconds.
    pub skew: u64,
    /// Maximum age of `iat` in seconds; `None` only checks for the future.
    pub max_age: Option<u64>,
}

/// The outcome of comparing one string-valued item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueCheck {
    /// Equal to the expected value.
    Match,
    /// Different from the expected value.
    Mismatch {
        /// What was expected.
        expected: String,
        /// What was found.
        found: String,
    },
    /// Present, but nothing was expected.
    Unchecked(String),
    /// Absent.
    Missing,
    /// Present but not a string.
    NotAString,
}

/// Where the holder key for the KB-JWT came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HolderKey {
    /// `cnf.jwk` of the issuer payload (an untrusted embedded key).
    CnfJwk,
    /// `cnf.kid`, matched by the candidate at this index (its kid as a
    /// JOSE string equals the `cnf.kid` string).
    CnfKid {
        /// The kid.
        kid: String,
        /// Index into the candidates.
        candidate: usize,
    },
    /// `cnf.kid` that no candidate matches.
    CnfKidUnmatched(String),
    /// `cnf.jwk` that does not import.
    CnfJwkInvalid(KeyError),
    /// No `cnf`, or `cnf` without `jwk` or `kid` (e.g. only `jku` or
    /// `jkt`, reported by member name).
    NoCnf(Vec<String>),
}

/// The checks on a KB-JWT (RFC 9901 §7.3 step 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KbReport {
    /// The key the signature was checked with.
    pub holder_key: HolderKey,
    /// Signature check; [`VerifyError::NoKey`] if there was no key.
    pub signature: Result<Alg, VerifyError>,
    /// Header `typ` against `kb+jwt`.
    pub typ: ValueCheck,
    /// `sd_hash` against the hash (with the issuer payload's `_sd_alg`) of
    /// [`SdJwt::sd_hash_input`]. `Mismatch.expected` is the computed value.
    /// An unreadable issuer payload counts as SHA-256; an unsupported
    /// `_sd_alg` (or no protected header) leaves nothing to compare, so the
    /// value is [`ValueCheck::Unchecked`].
    pub sd_hash: ValueCheck,
    /// `aud`.
    pub aud: ValueCheck,
    /// `nonce`.
    pub nonce: ValueCheck,
    /// `iat` freshness: [`TimeStatus::InFuture`], [`TimeStatus::TooOld`],
    /// [`TimeStatus::Absent`] (it is required), ...
    pub iat: TimeStatus,
}

/// Checks the KB-JWT of `sd`, or returns `None` if it has none.
///
/// The holder key is `cnf.jwk` from the issuer payload, or the candidate
/// whose kid equals `cnf.kid`. Candidates are not consulted when `cnf.jwk`
/// is present.
pub fn check_kb_jwt(
    sd: &SdJwt<'_>,
    candidates: &[Key],
    expect: &KbExpectations<'_>,
) -> Option<KbReport> {
    let kb = sd.kb_jwt.as_ref()?;
    let payload = sd.issuer.claims().ok();
    let (holder_key, key) = holder_key(payload.as_ref(), candidates);
    let signature = match &key {
        Some(key) => verify_signature(kb, 0, key),
        None => Err(VerifyError::NoKey),
    };
    let header = kb.header(0).and_then(Result::ok);
    let typ = check_value(header.as_ref(), "typ", Some(KB_TYP));
    let kb_payload = kb.claims().ok();
    let kb_payload = kb_payload.as_ref();

    let sd_alg = payload.as_ref().map_or(SdAlg::Default, sd_alg);
    let computed = sd_alg
        .hash()
        .zip(sd.sd_hash_input())
        .map(|(h, input)| sd_digest(&input, h));
    let sd_hash = check_value(kb_payload, "sd_hash", computed.as_deref());

    let iat = match kb_payload.map_or(Err(TimeStatus::Absent), |p| numeric_date(p, "iat")) {
        Err(s) => s,
        Ok(t) => kb_iat(t, expect),
    };
    Some(KbReport {
        holder_key,
        signature,
        typ,
        sd_hash,
        aud: check_value(kb_payload, "aud", expect.aud),
        nonce: check_value(kb_payload, "nonce", expect.nonce),
        iat,
    })
}

/// A NumericDate claim as seconds, or the status to report instead.
fn numeric_date(claims: &Node<'_>, name: &str) -> Result<f64, TimeStatus> {
    match claims.get(name).map(Node::value) {
        None => Err(TimeStatus::Absent),
        // Every JSON number lexeme parses (huge ones as infinity).
        Some(Value::Number(n)) => n.parse().map_err(|_| TimeStatus::NotANumber),
        Some(_) => Err(TimeStatus::NotANumber),
    }
}

/// KB-JWT `iat` freshness.
fn kb_iat(iat: f64, expect: &KbExpectations<'_>) -> TimeStatus {
    let (now, skew) = (expect.now as f64, expect.skew as f64);
    if iat > now + skew {
        TimeStatus::InFuture
    } else if expect
        .max_age
        .is_some_and(|max_age| now > iat + max_age as f64 + skew)
    {
        TimeStatus::TooOld
    } else {
        TimeStatus::Valid
    }
}

/// Compares string member `name` of `obj` with `expected` (`None`: report
/// the value unchecked).
fn check_value(obj: Option<&Node<'_>>, name: &str, expected: Option<&str>) -> ValueCheck {
    match obj.and_then(|o| o.get(name)).map(Node::value) {
        None => ValueCheck::Missing,
        Some(Value::String(found)) => match expected {
            None => ValueCheck::Unchecked(found.to_string()),
            Some(e) if e == found => ValueCheck::Match,
            Some(e) => ValueCheck::Mismatch {
                expected: e.to_owned(),
                found: found.to_string(),
            },
        },
        Some(_) => ValueCheck::NotAString,
    }
}

/// Finds the holder key from the issuer payload's `cnf`.
fn holder_key<'k>(
    payload: Option<&Node<'_>>,
    candidates: &'k [Key],
) -> (HolderKey, Option<Cow<'k, Key>>) {
    let Some(cnf) = payload.and_then(|p| p.get("cnf")) else {
        return (HolderKey::NoCnf(Vec::new()), None);
    };
    if let Some(jwk) = cnf.get("jwk") {
        return match Jwk::from_node(jwk).and_then(|j| from_jwk(&j)) {
            Ok(key) => (HolderKey::CnfJwk, Some(Cow::Owned(key))),
            Err(e) => (HolderKey::CnfJwkInvalid(e), None),
        };
    }
    if let Some(Value::String(kid)) = cnf.get("kid").map(Node::value) {
        let found = candidates.iter().position(|c| {
            c.kid
                .as_ref()
                .is_some_and(|k| k.to_jose_string() == kid.as_ref())
        });
        return match found.and_then(|i| Some((i, candidates.get(i)?))) {
            Some((candidate, key)) => (
                HolderKey::CnfKid {
                    kid: kid.to_string(),
                    candidate,
                },
                Some(Cow::Borrowed(key)),
            ),
            None => (HolderKey::CnfKidUnmatched(kid.to_string()), None),
        };
    }
    let names = cnf
        .members()
        .unwrap_or_default()
        .iter()
        .map(|m| m.key().to_string())
        .collect();
    (HolderKey::NoCnf(names), None)
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for VerifyError {}
