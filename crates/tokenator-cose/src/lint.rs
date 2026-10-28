//! Conformance facts for the core's linter (SPEC §6 "Conformance lint").

use std::borrow::Cow;

use tokenator_cbor::{FindingKind as CborKind, Item, Span, Value, deterministic_findings};
use tokenator_crypto::{DeclaredAlg, KeyMismatch, KeyParams, check_key};
use tokenator_keys::{Label, params_from_cwk};

use crate::claims::{Cnf, claim, parse_cnf};
use crate::codepoints::{
    CLAIM_CNF, HDR_ALG, HDR_CONTENT_TYPE, HDR_CRIT, HDR_CWT_CLAIMS, HDR_KCWT, HDR_KID, HDR_SD_ALG,
    HDR_SD_CLAIMS, HDR_TYP, MEDIA_KB_CWT, MEDIA_SD_CWT, TYP_KB_CWT, TYP_SD_CWT,
};
use crate::kbt::embedded;
use crate::model::content_type_of;
use crate::sd::{DisclosureContent, SdCwt};
use crate::util::{declared_alg, entries, label_of, map_get, shift};
use crate::{
    Bucket, ContentType, CoseError, DiagnosticKind, Part, Payload, Sign1, Sign1Backend, TokenKind,
};

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
    let sd = SdCwt::from_sign1(backend.parse(bytes)?);
    let kind = sd.sign1.kind();
    let mut linter = Linter { out: Vec::new() };
    let level = Level {
        base: 0,
        in_kcwt: false,
        sd: matches!(kind, TokenKind::SdCwt | TokenKind::SdKbt),
    };
    linter.token(&sd, &level, opts.signer.as_ref());

    if kind == TokenKind::SdKbt
        && let Ok(inner) = embedded(backend, &sd.sign1)
    {
        let level = Level {
            base: inner.sign1.base,
            in_kcwt: true,
            sd: true,
        };
        linter.token(&inner, &level, None);
        linter.cnf(&sd.sign1, &inner);
    }
    Ok(linter.out)
}

/// Labels whose meaning this crate processes, for `crit`.
const UNDERSTOOD: [i64; 9] = [
    HDR_ALG,
    HDR_CRIT,
    HDR_CONTENT_TYPE,
    HDR_KID,
    HDR_KCWT,
    HDR_CWT_CLAIMS,
    HDR_TYP,
    HDR_SD_CLAIMS,
    HDR_SD_ALG,
];

/// Where a token sits in the linted input.
struct Level {
    /// Offset of the token's bytes in the input.
    base: usize,
    /// Inside an SD-KBT's `kcwt`.
    in_kcwt: bool,
    /// An SD-CWT or SD-KBT (indefinite lengths are Warn everywhere).
    sd: bool,
}

struct Linter {
    out: Vec<Finding>,
}

impl Linter {
    /// Records a finding; `span` is relative to the token's bytes.
    fn push(&mut self, level: &Level, part: Part, kind: FindingKind, span: Option<Span>) {
        let severity = match &kind {
            FindingKind::Encoding {
                kind: CborKind::MapKeyOrder,
                ..
            } => Severity::Info,
            FindingKind::Encoding {
                kind: CborKind::IndefiniteLength,
                ..
            } if level.sd => Severity::Warn,
            FindingKind::Encoding { .. } => match part {
                // Byte string contents that need deterministic encoding.
                Part::Disclosure(_) => Severity::Warn,
                _ => Severity::Info,
            },
            _ => Severity::Warn,
        };
        self.push_with(level, part, kind, severity, span);
    }

    fn push_with(
        &mut self,
        level: &Level,
        part: Part,
        kind: FindingKind,
        severity: Severity,
        span: Option<Span>,
    ) {
        let part = if level.in_kcwt {
            Part::Kcwt(Box::new(part))
        } else {
            part
        };
        self.out.push(Finding {
            kind,
            severity,
            part,
            span: span.map(|s| shift(s, level.base)),
        });
    }

    /// Encoding and duplicate-key findings inside decoded contents at
    /// `offset` (`None` when the contents are not contiguous input bytes),
    /// skipping the range `skip` (relative to the contents).
    fn contents(
        &mut self,
        level: &Level,
        part: &Part,
        item: &Item<'_>,
        offset: Option<usize>,
        skip: Option<Span>,
    ) {
        let outside = |s: Span| skip.is_none_or(|k| s.start < k.start || s.end > k.end);
        for f in deterministic_findings(item) {
            if !outside(f.span) {
                continue;
            }
            let severity = if f.kind == CborKind::MapKeyOrder {
                Severity::Info
            } else {
                Severity::Warn
            };
            let kind = FindingKind::Encoding {
                kind: f.kind,
                preferred_bytes: f.preferred_bytes,
            };
            let span = offset.map(|o| shift(f.span, o));
            self.push_with(level, part.clone(), kind, severity, span);
        }
        for s in duplicate_keys(item) {
            if outside(s) {
                let span = offset.map(|o| shift(s, o));
                self.push(level, part.clone(), FindingKind::DuplicateMapKey, span);
            }
        }
    }

    fn token(&mut self, sd: &SdCwt<'_>, level: &Level, signer: Option<&KeyParams>) {
        let msg = &sd.sign1;
        let kind = msg.kind();

        // The envelope, heads, and unprotected header.
        for f in deterministic_findings(&msg.item) {
            let part = locate(sd, f.span.start);
            let kind = FindingKind::Encoding {
                kind: f.kind,
                preferred_bytes: f.preferred_bytes,
            };
            self.push(level, part, kind, Some(f.span));
        }
        for s in duplicate_keys(&msg.item) {
            self.push(
                level,
                locate(sd, s.start),
                FindingKind::DuplicateMapKey,
                Some(s),
            );
        }

        // Byte string contents.
        if let Some(p) = &msg.protected
            && let Some(Ok(item)) = &p.decoded
        {
            let kcwt = match msg.header(HDR_KCWT) {
                Some((Bucket::Protected, k)) => Some(k.span),
                _ => None,
            };
            let offset = matches!(p.raw, Cow::Borrowed(_)).then(|| p.content_offset());
            self.contents(level, &Part::Protected, item, offset, kcwt);
        }
        if let Payload::Attached(b) = &msg.payload
            && let Some(Ok(item)) = &b.decoded
        {
            let offset = matches!(b.raw, Cow::Borrowed(_)).then(|| b.content_offset());
            self.contents(level, &Part::Payload, item, offset, None);
        }
        for d in &sd.disclosures {
            let part = Part::Disclosure(d.index);
            if let Some(Ok(item)) = &d.bytes.decoded {
                let offset =
                    matches!(d.bytes.raw, Cow::Borrowed(_)).then(|| d.bytes.content_offset());
                self.contents(level, &part, item, offset, None);
            }
            let salt = match &d.content {
                DisclosureContent::Claim { salt, .. }
                | DisclosureContent::Element { salt, .. }
                | DisclosureContent::Decoy { salt } => salt,
                DisclosureContent::Malformed(_) => continue,
            };
            if salt.len() != 16 {
                self.push(
                    level,
                    part,
                    FindingKind::SaltLength(salt.len()),
                    Some(d.bytes.span),
                );
            }
        }

        self.headers(msg, kind, level, signer);
    }

    fn headers(
        &mut self,
        msg: &Sign1<'_>,
        kind: TokenKind,
        level: &Level,
        signer: Option<&KeyParams>,
    ) {
        let prot_offset = msg
            .protected
            .as_ref()
            .filter(|p| matches!(p.raw, Cow::Borrowed(_)))
            .map(|p| p.content_offset());
        let at = |bucket: Bucket, s: Span| match bucket {
            Bucket::Protected => prot_offset.map(|o| shift(s, o)),
            Bucket::Unprotected => Some(s),
        };
        let part_of = |bucket: Bucket| match bucket {
            Bucket::Protected => Part::Protected,
            Bucket::Unprotected => Part::Unprotected,
        };

        for d in &msg.diagnostics {
            if let DiagnosticKind::LabelInBothBuckets(l) = &d.kind {
                self.push(
                    level,
                    Part::Unprotected,
                    FindingKind::LabelInBothBuckets(l.clone()),
                    d.span,
                );
            }
        }

        // alg
        match msg.header(HDR_ALG) {
            None => self.push(level, Part::Protected, FindingKind::MissingAlg, None),
            Some((bucket, v)) => {
                if bucket == Bucket::Unprotected {
                    self.push(
                        level,
                        Part::Unprotected,
                        FindingKind::AlgNotProtected,
                        Some(v.span),
                    );
                }
                match declared_alg(v) {
                    None => self.push(
                        level,
                        part_of(bucket),
                        FindingKind::MissingAlg,
                        at(bucket, v.span),
                    ),
                    Some(DeclaredAlg::Known(alg)) => {
                        if let Some(params) = signer {
                            let mismatches = check_key(alg, params);
                            if !mismatches.is_empty() {
                                let kind = FindingKind::AlgKeyMismatch {
                                    role: KeyRole::Signer,
                                    mismatches,
                                };
                                self.push(level, part_of(bucket), kind, at(bucket, v.span));
                            }
                        }
                    }
                    Some(other) => {
                        let kind = FindingKind::UnsupportedAlg(other);
                        self.push(level, part_of(bucket), kind, at(bucket, v.span));
                    }
                }
            }
        }

        // crit (RFC 9052 §3.1)
        let prot = msg.protected_header();
        if let Some(v) = msg.unprotected.as_ref().and_then(|u| map_get(u, HDR_CRIT)) {
            self.push(
                level,
                Part::Unprotected,
                FindingKind::CritNotProtected,
                Some(v.span),
            );
        }
        if let Some(v) = prot.and_then(|m| map_get(m, HDR_CRIT)) {
            let span = at(Bucket::Protected, v.span);
            match &v.value {
                Value::Array(labels) if !labels.is_empty() => {
                    for l in labels {
                        let Some(label) = label_of(l) else {
                            self.push(level, Part::Protected, FindingKind::CritMalformed, span);
                            continue;
                        };
                        let present = prot.and_then(entries).is_some_and(|e| {
                            e.iter().any(|(k, _)| label_of(k).as_ref() == Some(&label))
                        });
                        let kind = if !present {
                            FindingKind::CritMissingLabel(label)
                        } else if matches!(label, Label::Int(n) if UNDERSTOOD.contains(&n)) {
                            continue;
                        } else {
                            FindingKind::CritNotUnderstood(label)
                        };
                        self.push(level, Part::Protected, kind, span);
                    }
                }
                _ => self.push(level, Part::Protected, FindingKind::CritMalformed, span),
            }
        }

        // typ (RFC 9596; sd-cwt-08 §4, §8.1)
        let expected: Option<(u64, &str, &str)> = match kind {
            TokenKind::SdKbt => Some((TYP_KB_CWT, MEDIA_KB_CWT, "+kb+cwt")),
            TokenKind::SdCwt => Some((TYP_SD_CWT, MEDIA_SD_CWT, "+sd-cwt")),
            TokenKind::Cwt | TokenKind::Sign1 => None,
        };
        if let Some((number, media, suffix)) = expected {
            match msg.header(HDR_TYP) {
                None => self.push(level, Part::Protected, FindingKind::TypMissing, None),
                Some((bucket, v)) => {
                    let ok = match content_type_of(v) {
                        Some(ContentType::Uint(n)) => n == number,
                        Some(ContentType::Text(t)) => t == media || t.ends_with(suffix),
                        None => false,
                    };
                    if !ok {
                        let kind = match content_type_of(v) {
                            Some(t) => FindingKind::TypUnexpected(t),
                            None => FindingKind::TypMissing,
                        };
                        self.push(level, part_of(bucket), kind, at(bucket, v.span));
                    }
                }
            }
        }

        // An empty protected header must be zero-length (RFC 9052 §3).
        if let Some(p) = &msg.protected
            && !p.raw.is_empty()
            && matches!(&p.decoded, Some(Ok(m)) if entries(m).is_some_and(<[_]>::is_empty))
        {
            self.push(
                level,
                Part::Protected,
                FindingKind::EmptyProtectedNotZeroLength,
                Some(p.span),
            );
        }
    }

    /// The SD-CWT's `cnf` COSE_Key against the KBT `alg`.
    fn cnf(&mut self, kbt: &Sign1<'_>, inner: &SdCwt<'_>) {
        let Some(DeclaredAlg::Known(alg)) = kbt.alg() else {
            return;
        };
        let Some(cnf) = inner
            .sign1
            .payload_item()
            .and_then(|c| claim(c, &Label::Int(CLAIM_CNF)))
        else {
            return;
        };
        let Ok(Cnf::CoseKey(cwk)) = parse_cnf(cnf) else {
            return;
        };
        let Ok(params) = params_from_cwk(&cwk) else {
            return;
        };
        let mismatches = check_key(alg, &params);
        if mismatches.is_empty() {
            return;
        }
        let span = match &inner.sign1.payload {
            Payload::Attached(b) if matches!(b.raw, Cow::Borrowed(_)) => {
                Some(shift(cnf.span, inner.sign1.base + b.content_offset()))
            }
            _ => None,
        };
        let level = Level {
            base: 0,
            in_kcwt: true,
            sd: true,
        };
        let kind = FindingKind::AlgKeyMismatch {
            role: KeyRole::Cnf,
            mismatches,
        };
        self.push(&level, Part::Payload, kind, span);
    }
}

/// The part of a token that byte `at` (relative to its bytes) is in.
fn locate(sd: &SdCwt<'_>, at: usize) -> Part {
    let msg = &sd.sign1;
    let within = |s: Span| at >= s.start && at < s.end;
    if msg.protected.as_ref().is_some_and(|p| within(p.span)) {
        return Part::Protected;
    }
    if msg.unprotected.as_ref().is_some_and(|u| within(u.span)) {
        return sd
            .disclosures
            .iter()
            .find(|d| within(d.bytes.span))
            .map_or(Part::Unprotected, |d| Part::Disclosure(d.index));
    }
    let payload = match &msg.payload {
        Payload::Attached(b) => Some(b.span),
        Payload::Detached { span } => Some(*span),
        Payload::Malformed => None,
    };
    if payload.is_some_and(within) {
        return Part::Payload;
    }
    if msg.signature.as_ref().is_some_and(|s| within(s.span)) {
        return Part::Signature;
    }
    Part::Envelope
}

/// The spans of map keys whose deterministic encoding repeats an earlier
/// key in the same map.
fn duplicate_keys(item: &Item<'_>) -> Vec<Span> {
    tokenator_cbor::duplicate_keys(item)
        .into_iter()
        .map(|d| d.duplicate_key)
        .collect()
}
