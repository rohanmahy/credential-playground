//! SD-KBT (key binding token): Disclose, Present, and verification
//! (draft-ietf-spice-sd-cwt-08 §8, §9).

use std::borrow::Cow;
use std::cmp::Ordering;

use tokenator_cbor::{Item, Value, decode};
use tokenator_crypto::{Alg, alg_to_cose, rand_core::CryptoRng};
use tokenator_keys::{Key, Label};

use crate::claims::{
    Cnf, NumericDate, TimeOptions, TimeReport, TimeStatus, check_times, claim, parse_cnf,
    resolve_cnf,
};
use crate::codepoints::{
    CLAIM_AUD, CLAIM_CNF, CLAIM_CNONCE, CLAIM_CTI, CLAIM_IAT, CLAIM_ISS, CLAIM_SUB, HDR_ALG,
    HDR_CWT_CLAIMS, HDR_KCWT, HDR_TYP, MEDIA_KB_CWT, TAG_COSE_SIGN1, TAG_CWT, TYP_KB_CWT,
};
use crate::edit::rewrite_sd_claims;
use crate::model::content_type_item;
use crate::sd::{MatchMode, SdCwt, SdReport, Typ, match_disclosures};
use crate::util::{enc, has_indefinite, head, map_get, slice};
use crate::{
    Bucket, ContentType, CoseError, DiagnosticKind, Payload, Sign1, Sign1Backend, Sign1Parts,
    SignOptions, VerifyOptions,
};

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
    rewrite_sd_claims(backend, credential, &mut |list| {
        match selection {
            Selection::All => {}
            Selection::None => list.clear(),
            Selection::Indices(indices) => {
                let mut out = Vec::with_capacity(indices.len());
                for &i in indices {
                    out.push(list.get(i).cloned().ok_or(CoseError::DisclosureIndex(i))?);
                }
                *list = out;
            }
        }
        Ok(())
    })
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
    if !holder.is_private() {
        return Err(CoseError::NoPrivateKey);
    }
    let disclosed = disclose(backend, credential, &opts.selection)?;
    let msg = backend.parse(&disclosed)?;

    // kcwt requires #6.18: drop tag 61, add 18 if missing, and copy the
    // array verbatim.
    let mut tags: Vec<u64> = msg.tags.iter().copied().filter(|t| *t != TAG_CWT).collect();
    if !tags.contains(&TAG_COSE_SIGN1) {
        tags.push(TAG_COSE_SIGN1);
    }
    let mut kcwt: Vec<u8> = tags.iter().flat_map(|t| head(6, *t)).collect();
    kcwt.extend(slice(&disclosed, msg.span).unwrap_or_default());
    let kcwt = decode(&kcwt)?;

    let mut prot = vec![
        (Item::int(HDR_ALG), Item::int(alg_to_cose(opts.alg))),
        (Item::int(HDR_KCWT), kcwt),
    ];
    let typ = match &opts.typ {
        Typ::Auto => Some(ContentType::Uint(TYP_KB_CWT)),
        Typ::Omit => None,
        Typ::Value(t) => Some(t.clone()),
    };
    if let Some(t) = &typ {
        prot.push((Item::int(HDR_TYP), content_type_item(t)));
    }
    prot.extend(opts.protected_extra.iter().cloned());

    let mut claims = Vec::new();
    if let Some(aud) = &opts.aud {
        claims.push((Item::int(CLAIM_AUD), Item::text(&aud[..])));
    }
    if let Some(iat) = opts.iat {
        claims.push((Item::int(CLAIM_IAT), Item::int(iat)));
    }
    if let Some(cti) = &opts.cti {
        claims.push((Item::int(CLAIM_CTI), Item::bytes(&cti[..])));
    }
    if let Some(cnonce) = &opts.cnonce {
        claims.push((Item::int(CLAIM_CNONCE), Item::bytes(&cnonce[..])));
    }
    claims.extend(opts.extra_claims.iter().cloned());

    let parts = Sign1Parts {
        tags: opts.tags.clone(),
        protected: Cow::Owned(enc(&Item::map(prot))?),
        unprotected: Item::map(Vec::new()),
        payload: Some(Cow::Owned(enc(&Item::map(claims))?)),
        signature: Cow::Borrowed(&[]),
    };
    backend.sign(&parts, holder, &SignOptions::new(opts.alg), rng)
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
        self.issuer_signature.is_ok()
            && self.kbt_signature.is_ok()
            && self
                .sd
                .as_ref()
                .is_some_and(|r| r.is_valid(MatchMode::Verifier))
            && self.findings.is_empty()
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
    let kbt = backend.parse(bytes)?;
    let mut findings = Vec::new();

    let sd_cwt = match embedded(backend, &kbt) {
        Ok(sd) => Some(sd),
        Err(CoseError::NotKbt) => return Err(CoseError::NotKbt),
        Err(_) => {
            findings.push(KbtFinding::KcwtNotSign1);
            None
        }
    };
    let issuer_signature = match (&sd_cwt, issuer_key) {
        (None, _) => Err(CoseError::NotSign1),
        (Some(_), None) => Err(CoseError::NoKey),
        (Some(sd), Some(key)) => backend.verify(&sd.sign1, key, &VerifyOptions::default()),
    };
    let sd = sd_cwt.as_ref().map(match_disclosures);
    // The SD-CWT claims: the processed claims when there are any.
    let sd_claims: Option<&Item<'a>> = sd
        .as_ref()
        .and_then(|r| r.processed.as_ref())
        .or_else(|| sd_cwt.as_ref().and_then(|s| s.sign1.payload_item()));

    let cnf = sd_claims
        .and_then(|c| claim(c, &Label::Int(CLAIM_CNF)))
        .map(parse_cnf);
    let kbt_signature = match &cnf {
        None if sd_cwt.is_none() => Err(CoseError::NoKey),
        None => Err(CoseError::Cnf("the SD-CWT has no cnf claim")),
        Some(Err(e)) => Err(e.clone()),
        Some(Ok(c)) => match resolve_cnf(c, &opts.holder_keys) {
            Ok(Some(key)) => backend.verify(&kbt, &key, &VerifyOptions::default()),
            Ok(None) => Err(CoseError::NoKey),
            Err(e) => Err(e),
        },
    };

    // Headers (§8.1).
    match kbt.typ() {
        None => findings.push(KbtFinding::TypMissing),
        Some(ContentType::Uint(TYP_KB_CWT)) => {}
        Some(ContentType::Text(t)) if t == MEDIA_KB_CWT || t.ends_with("+kb+cwt") => {}
        Some(t) => findings.push(KbtFinding::TypUnexpected(t)),
    }
    if kbt
        .protected_header()
        .and_then(|m| map_get(m, HDR_CWT_CLAIMS))
        .is_some()
    {
        findings.push(KbtFinding::CwtClaimsHeader);
    }

    // KBT claims (§8.1 Table 3).
    let empty = Item::map(Vec::new());
    let claims = kbt
        .payload_item()
        .filter(|c| matches!(c.value, Value::Map(_)))
        .unwrap_or(&empty);
    let get = |key: i64| claim(claims, &Label::Int(key));
    if get(CLAIM_ISS).is_some() {
        findings.push(KbtFinding::IssPresent);
    }
    if get(CLAIM_SUB).is_some() {
        findings.push(KbtFinding::SubPresent);
    }
    match get(CLAIM_AUD) {
        None => findings.push(KbtFinding::AudMissing),
        Some(aud) => {
            let sd_aud = sd_claims.and_then(|c| claim(c, &Label::Int(CLAIM_AUD)));
            if let Some(expected) = &opts.expected_aud
                && [Some(aud), sd_aud]
                    .into_iter()
                    .flatten()
                    .any(|a| !matches!(&a.value, Value::Text(t) if t == expected))
            {
                findings.push(KbtFinding::AudMismatch);
            }
        }
    }
    let times = check_times(claims, &clock(opts));
    if get(CLAIM_IAT).is_none() {
        if get(CLAIM_CTI).is_none() {
            findings.push(KbtFinding::NoIatOrCti);
        }
        if times.exp.is_some() || times.nbf.is_some() {
            findings.push(KbtFinding::TimeWithoutIat);
        }
    }
    if let Some(expected) = &opts.expected_cnonce {
        match get(CLAIM_CNONCE) {
            None => findings.push(KbtFinding::CnonceMissing),
            Some(c) if !matches!(&c.value, Value::Bytes(b) if b[..] == expected[..]) => {
                findings.push(KbtFinding::CnonceMismatch);
            }
            Some(_) => {}
        }
    }

    // Clock and time relations (§9 steps 3 and 7).
    let sd_times = sd_claims.map(|c| check_times(c, &clock(opts)));
    if let Some(t) = &sd_times {
        findings.extend(not_ok(t).map(KbtFinding::SdCwtClock));
    }
    findings.extend(not_ok(&times).map(KbtFinding::KbtClock));
    findings.extend(time_rules(sd_times.as_ref(), &times).map(KbtFinding::Time));
    if let (Some(max_age), Some(TimeStatus::Ok(iat))) = (opts.max_age, times.iat)
        && iat.cmp_secs(i128::from(opts.now) - i128::from(max_age)) == Ordering::Less
    {
        findings.push(KbtFinding::Stale);
    }

    // Encoding and structure.
    if indefinite_anywhere(&kbt, sd_cwt.as_ref()) {
        findings.push(KbtFinding::IndefiniteLength);
    }
    if sd_cwt.as_ref().is_some_and(|s| {
        s.diagnostics
            .iter()
            .any(|d| d.kind == DiagnosticKind::EmptySdClaims)
    }) {
        findings.push(KbtFinding::EmptySdClaims);
    }

    Ok(KbtReport {
        kbt,
        sd_cwt,
        issuer_signature,
        kbt_signature,
        cnf,
        sd,
        findings,
    })
}

fn clock(opts: &KbtOptions<'_>) -> TimeOptions {
    TimeOptions {
        now: opts.now,
        skew: opts.skew,
    }
}

/// The SD-CWT in the `kcwt` header parameter, parsed from its own bytes
/// with `sign1.base` set. [`CoseError::NotKbt`] without `kcwt`.
pub(crate) fn embedded<'a>(
    backend: &dyn Sign1Backend,
    kbt: &Sign1<'a>,
) -> Result<SdCwt<'a>, CoseError> {
    let (bucket, kcwt) = kbt.header(HDR_KCWT).ok_or(CoseError::NotKbt)?;
    let (outer, offset): (&'a [u8], usize) = match bucket {
        Bucket::Protected => match kbt.protected.as_ref().map(|p| (&p.raw, p.content_offset())) {
            Some((Cow::Borrowed(raw), offset)) => (raw, offset),
            _ => return Err(CoseError::NotSign1),
        },
        Bucket::Unprotected => (kbt.bytes, 0),
    };
    // A bstr-wrapped COSE_Sign1 is accepted too.
    let (span, inner) = match &kcwt.value {
        Value::Bytes(Cow::Borrowed(b)) => (kcwt.span.start + kcwt.span.head_len, *b),
        _ => (
            kcwt.span.start,
            slice(outer, kcwt.span).ok_or(CoseError::NotSign1)?,
        ),
    };
    let mut sign1 = backend.parse(inner)?;
    sign1.base = kbt.base + offset + span;
    Ok(SdCwt::from_sign1(sign1))
}

/// The time claims that are not [`TimeStatus::Ok`].
fn not_ok(t: &TimeReport) -> impl Iterator<Item = TimeStatus> {
    [t.exp, t.nbf, t.iat]
        .into_iter()
        .flatten()
        .filter(|s| !matches!(s, TimeStatus::Ok(_)))
}

/// A time rule, two dates, and the orderings of the first against the
/// second that break it.
type Relation = (
    TimeRule,
    Option<NumericDate>,
    Option<NumericDate>,
    &'static [Ordering],
);

/// The time relations of sd-cwt-08 §9 steps 3 and 7 that fail.
fn time_rules(sd: Option<&TimeReport>, kbt: &TimeReport) -> impl Iterator<Item = TimeRule> {
    fn date(s: Option<TimeStatus>) -> Option<NumericDate> {
        match s? {
            TimeStatus::Ok(d)
            | TimeStatus::Expired(d)
            | TimeStatus::NotYetValid(d)
            | TimeStatus::IssuedInFuture(d) => Some(d),
            TimeStatus::Invalid(_) => None,
        }
    }
    let (s_exp, s_nbf, s_iat) = sd.map_or((None, None, None), |s| {
        (date(s.exp), date(s.nbf), date(s.iat))
    });
    let (k_exp, k_nbf, k_iat) = (date(kbt.exp), date(kbt.nbf), date(kbt.iat));
    use Ordering::{Equal, Greater, Less};
    let rules: [Relation; 11] = [
        (TimeRule::SdNbfAfterIat, s_nbf, s_iat, &[Greater]),
        (TimeRule::SdNbfNotBeforeExp, s_nbf, s_exp, &[Greater, Equal]),
        (TimeRule::SdIatNotBeforeExp, s_iat, s_exp, &[Greater, Equal]),
        (TimeRule::KbtNbfAfterIat, k_nbf, k_iat, &[Greater]),
        (
            TimeRule::KbtIatNotBeforeExp,
            k_iat,
            k_exp,
            &[Greater, Equal],
        ),
        (TimeRule::KbtExpAfterSdExp, k_exp, s_exp, &[Greater]),
        (TimeRule::KbtNbfBeforeSdNbf, k_nbf, s_nbf, &[Less]),
        (TimeRule::KbtIatBeforeSdIat, k_iat, s_iat, &[Less]),
        (
            TimeRule::KbtNbfNotBeforeSdExp,
            k_nbf,
            s_exp,
            &[Greater, Equal],
        ),
        (
            TimeRule::KbtIatNotBeforeSdExp,
            k_iat,
            s_exp,
            &[Greater, Equal],
        ),
        (TimeRule::KbtIatBeforeSdNbf, k_iat, s_nbf, &[Less]),
    ];
    rules
        .into_iter()
        .filter_map(|(rule, a, b, bad)| match (a, b) {
            (Some(a), Some(b)) if bad.contains(&a.cmp_date(b)) => Some(rule),
            _ => None,
        })
}

/// Indefinite-length items anywhere in the KBT or its SD-CWT, including
/// inside byte strings that hold CBOR (§5.1).
fn indefinite_anywhere(kbt: &Sign1<'_>, sd: Option<&SdCwt<'_>>) -> bool {
    let decoded = |s: &Sign1<'_>| {
        let mut items = vec![&s.item];
        items.extend(
            s.protected
                .as_ref()
                .and_then(|p| p.decoded.as_ref()?.as_ref().ok()),
        );
        if let Payload::Attached(b) = &s.payload {
            items.extend(b.decoded.as_ref().and_then(|d| d.as_ref().ok()));
        }
        items.into_iter().any(has_indefinite)
    };
    decoded(kbt)
        || sd.is_some_and(|sd| {
            decoded(&sd.sign1)
                || sd.disclosures.iter().any(|d| {
                    d.bytes
                        .decoded
                        .as_ref()
                        .and_then(|r| r.as_ref().ok())
                        .is_some_and(has_indefinite)
                })
        })
}
