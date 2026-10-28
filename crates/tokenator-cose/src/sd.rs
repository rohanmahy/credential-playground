//! SD-CWT (draft-ietf-spice-sd-cwt-08): redaction, issuance, disclosures,
//! digests, and disclosure matching.
//!
//! A disclosure travels as a bstr in `sd_claims`; its digest is the hash of
//! that *encoded bstr* (head and contents) exactly as it appears in the
//! token (sd-cwt-08 Appendix G and every example payload; see
//! `TEST-PLAN.md` for the Figure 8 discrepancy).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use tokenator_cbor::{Item, Span, Value};
use tokenator_crypto::{Alg, HashAlg, alg_to_cose, digest, rand_core::CryptoRng};
use tokenator_keys::{Key, Label};

use crate::backend::bstr_of;
use crate::codepoints::{
    HDR_ALG, HDR_KID, HDR_SD_ALG, HDR_SD_CLAIMS, HDR_TYP, NEVER_REDACTED, SIMPLE_REDACTED_KEYS,
    TAG_REDACTED_ELEMENT, TAG_TO_BE_DECOY, TAG_TO_BE_REDACTED, TYP_SD_CWT,
};
use crate::model::content_type_item;
use crate::util::{
    enc, has_indefinite, head, int_of, label_of, len_u64, map_get, shift, slice, walk, with_value,
};
use crate::{
    Bstr, ContentType, CoseError, Diagnostic, DiagnosticKind, Part, Payload, RedactionError, Sign1,
    Sign1Backend, Sign1Parts, SignOptions,
};

/// Where a [`redact`] salt request comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaltRequest {
    /// 0 for the first salt, then 1, 2, ...: the order of the disclosures
    /// in [`Redacted::disclosures`].
    pub ordinal: usize,
    /// The decoy number for a to-be-decoy tag, `None` otherwise.
    pub decoy: Option<u64>,
}

/// Supplies disclosure salts. Injected so issuance is reproducible.
pub trait SaltSource {
    /// The salt for the next disclosure. The draft requires 16 random bytes
    /// (sd-cwt-08 §6.1); other lengths are allowed and linted.
    fn salt(&mut self, req: &SaltRequest) -> Result<Vec<u8>, CoseError>;
}

/// 16-byte salts drawn from an RNG with `fill_bytes`, one call per salt.
pub struct RngSalts<'r> {
    rng: &'r mut dyn CryptoRng,
}

impl<'r> RngSalts<'r> {
    /// Salts from `rng`.
    pub fn new(rng: &'r mut dyn CryptoRng) -> RngSalts<'r> {
        RngSalts { rng }
    }
}

impl SaltSource for RngSalts<'_> {
    fn salt(&mut self, _req: &SaltRequest) -> Result<Vec<u8>, CoseError> {
        let mut salt = vec![0; 16];
        self.rng.fill_bytes(&mut salt);
        Ok(salt)
    }
}

/// Salts from a list, in order; [`CoseError::SaltExhausted`] after the last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedSalts {
    salts: Vec<Vec<u8>>,
    next: usize,
}

impl FixedSalts {
    /// Salts taken from `salts` in order.
    pub fn new(salts: Vec<Vec<u8>>) -> FixedSalts {
        FixedSalts { salts, next: 0 }
    }
}

impl SaltSource for FixedSalts {
    fn salt(&mut self, _req: &SaltRequest) -> Result<Vec<u8>, CoseError> {
        let salt = self
            .salts
            .get(self.next)
            .cloned()
            .ok_or(CoseError::SaltExhausted)?;
        self.next += 1;
        Ok(salt)
    }
}

/// Something worth labeling in a redaction that still went ahead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedactWarning {
    /// A top-level claim that SD-CWT never redacts (sd-cwt-08 Table 2) was
    /// marked to be redacted.
    NeverRedactedClaim(i64),
    /// The input contains indefinite-length items, which were kept
    /// (sd-cwt-08 §5.1 forbids sending them).
    IndefiniteLength,
    /// A salt that is not 16 bytes long.
    SaltLength(usize),
}

/// The output of [`redact`].
#[derive(Debug, Clone, PartialEq)]
pub struct Redacted<'a> {
    /// The claims set with redacted claim keys (`simple(59)` arrays) and
    /// redacted elements (`60(digest)`).
    pub payload: Item<'a>,
    /// Encoded salted disclosures (the bstr *contents*), in the order they
    /// were created: post-order, so disclosures nested in a value come
    /// before the disclosure of that value.
    pub disclosures: Vec<Vec<u8>>,
    /// Labels for unusual input.
    pub warnings: Vec<RedactWarning>,
}

/// Converts a pre-issuance claims set into an SD-CWT payload and its
/// disclosures (sd-cwt-08 §4.1, §10, §11).
///
/// - A map key `58(k)` removes the entry `k: v` and adds
///   `[salt, v', k]` (v' = v redacted recursively). A key `62(n)` (value
///   `null`) adds a decoy `[salt]`. Their digests go, in key order, into a
///   `simple(59)` array appended as the map's last entry. Other entries
///   keep their order.
/// - An array element `58(x)` becomes `60(digest)` of `[salt, x']`; `62(n)`
///   becomes `60(digest)` of `[salt]`.
/// - Other tags are recursed into.
///
/// Everything copied from the input is encoded with `EncodeMode::Preserve`;
/// new items use preferred encoding. Each digest is `hash` over the
/// disclosure encoded as a bstr (head included).
pub fn redact<'a>(
    claims: &Item<'a>,
    hash: HashAlg,
    salts: &mut dyn SaltSource,
) -> Result<Redacted<'a>, CoseError> {
    if !matches!(claims.value, Value::Map(_)) {
        return Err(RedactionError::NotAMap.into());
    }
    let mut r = Redactor {
        hash,
        salts,
        disclosures: Vec::new(),
        warnings: Vec::new(),
        decoys: Vec::new(),
    };
    if has_indefinite(claims) {
        r.warnings.push(RedactWarning::IndefiniteLength);
    }
    let payload = r.map(claims, true)?;
    Ok(Redacted {
        payload,
        disclosures: r.disclosures,
        warnings: r.warnings,
    })
}

/// The state of one [`redact`] run.
struct Redactor<'s> {
    hash: HashAlg,
    salts: &'s mut dyn SaltSource,
    disclosures: Vec<Vec<u8>>,
    warnings: Vec<RedactWarning>,
    decoys: Vec<u64>,
}

/// What a pre-issuance map key asks for.
enum MapKey<'i, 'a> {
    /// Keep the entry.
    Plain,
    /// `58(key)`: redact the entry.
    Redact(&'i Item<'a>),
    /// `62(n)`: add a decoy.
    Decoy(u64),
}

impl Redactor<'_> {
    /// Redacts a claims map: entries keep their order, redacted and decoy
    /// entries become digests in a `simple(59)` entry appended last.
    fn map<'a>(&mut self, item: &Item<'a>, top: bool) -> Result<Item<'a>, CoseError> {
        let Value::Map(entries) = &item.value else {
            return Err(RedactionError::NotAMap.into());
        };
        let mut kinds = Vec::with_capacity(entries.len());
        let mut labels: Vec<Label> = Vec::with_capacity(entries.len());
        for (k, _) in entries {
            let (kind, label) = classify_key(k)?;
            if let Some(label) = label {
                if labels.contains(&label) {
                    return Err(RedactionError::DuplicateKey(label).into());
                }
                labels.push(label);
            }
            kinds.push(kind);
        }

        let mut out = Vec::with_capacity(entries.len() + 1);
        let mut digests = Vec::new();
        for ((k, v), kind) in entries.iter().zip(kinds) {
            match kind {
                MapKey::Plain => out.push((k.clone(), self.map_value(v)?)),
                MapKey::Redact(key) => {
                    let value = self.map_value(v)?;
                    if top
                        && let Some(n) = int_of(key)
                        && NEVER_REDACTED.contains(&n)
                    {
                        self.warnings.push(RedactWarning::NeverRedactedClaim(n));
                    }
                    digests.push(self.disclose(Some(&value), Some(key), None)?);
                }
                MapKey::Decoy(n) => {
                    if v.value != Value::Null {
                        return Err(RedactionError::InvalidDecoy.into());
                    }
                    digests.push(self.disclose(None, None, Some(n))?);
                }
            }
        }
        if !digests.is_empty() {
            out.push((
                Item::simple(SIMPLE_REDACTED_KEYS),
                Item::array(digests.into_iter().map(Item::bytes).collect()),
            ));
        }
        Ok(with_value(item, Value::Map(out)))
    }

    fn map_value<'a>(&mut self, v: &Item<'a>) -> Result<Item<'a>, CoseError> {
        match v.value {
            Value::Tag(t @ (TAG_TO_BE_REDACTED | TAG_TO_BE_DECOY), _) => {
                Err(RedactionError::TagOnMapValue(t).into())
            }
            _ => self.value(v),
        }
    }

    /// Redacts inside any value. Arrays turn `58(x)` and `62(n)` elements
    /// into `60(digest)`.
    fn value<'a>(&mut self, v: &Item<'a>) -> Result<Item<'a>, CoseError> {
        match &v.value {
            Value::Map(_) => self.map(v, false),
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for e in items {
                    let digest = match &e.value {
                        Value::Tag(TAG_TO_BE_REDACTED, inner) => {
                            if let Value::Tag(TAG_TO_BE_REDACTED | TAG_TO_BE_DECOY, _) = inner.value
                            {
                                return Err(RedactionError::NestedTag.into());
                            }
                            let value = self.value(inner)?;
                            self.disclose(Some(&value), None, None)?
                        }
                        Value::Tag(TAG_TO_BE_DECOY, inner) => {
                            let n = decoy_number(inner)?;
                            self.disclose(None, None, Some(n))?
                        }
                        _ => {
                            out.push(self.value(e)?);
                            continue;
                        }
                    };
                    out.push(Item::tag(TAG_REDACTED_ELEMENT, Item::bytes(digest)));
                }
                Ok(with_value(v, Value::Array(out)))
            }
            Value::Tag(TAG_TO_BE_REDACTED | TAG_TO_BE_DECOY, _) => {
                Err(RedactionError::NestedTag.into())
            }
            Value::Tag(t, inner) => Ok(with_value(v, Value::Tag(*t, Box::new(self.value(inner)?)))),
            _ => Ok(v.clone()),
        }
    }

    /// Creates the next disclosure and returns its digest.
    fn disclose(
        &mut self,
        value: Option<&Item<'_>>,
        key: Option<&Item<'_>>,
        decoy: Option<u64>,
    ) -> Result<Vec<u8>, CoseError> {
        if let Some(n) = decoy {
            if self.decoys.contains(&n) {
                return Err(RedactionError::DuplicateDecoy(n).into());
            }
            self.decoys.push(n);
        }
        let req = SaltRequest {
            ordinal: self.disclosures.len(),
            decoy,
        };
        let salt = self.salts.salt(&req)?;
        let warning = RedactWarning::SaltLength(salt.len());
        if salt.len() != 16 && !self.warnings.contains(&warning) {
            self.warnings.push(warning);
        }
        let d = encode_disclosure(&salt, value, key)?;
        let digest = disclosure_digest(self.hash, &d);
        self.disclosures.push(d);
        Ok(digest)
    }
}

/// Classifies a pre-issuance map key; the label is used for duplicate
/// detection (`k` and `58(k)` collide).
fn classify_key<'i, 'a>(k: &'i Item<'a>) -> Result<(MapKey<'i, 'a>, Option<Label>), CoseError> {
    match &k.value {
        Value::Uint(_) | Value::Nint(_) | Value::Text(_) => match label_of(k) {
            Some(l) => Ok((MapKey::Plain, Some(l))),
            None => Err(RedactionError::InvalidMapKey.into()),
        },
        Value::Tag(TAG_TO_BE_REDACTED, inner) => match &inner.value {
            Value::Tag(TAG_TO_BE_REDACTED | TAG_TO_BE_DECOY, _) => {
                Err(RedactionError::NestedTag.into())
            }
            Value::Text(t) if !(1..=255).contains(&t.len()) => {
                Err(RedactionError::InvalidRedactedKey.into())
            }
            Value::Uint(_) | Value::Nint(_) | Value::Text(_) => match label_of(inner) {
                Some(l) => Ok((MapKey::Redact(inner), Some(l))),
                None => Err(RedactionError::InvalidRedactedKey.into()),
            },
            _ => Err(RedactionError::InvalidRedactedKey.into()),
        },
        Value::Tag(TAG_TO_BE_DECOY, inner) => Ok((MapKey::Decoy(decoy_number(inner)?), None)),
        _ => Err(RedactionError::InvalidMapKey.into()),
    }
}

/// The content of a to-be-decoy tag: an unsigned integer > 0.
fn decoy_number(inner: &Item<'_>) -> Result<u64, CoseError> {
    match inner.value {
        Value::Uint(n) if n > 0 => Ok(n),
        _ => Err(RedactionError::InvalidDecoy.into()),
    }
}

/// Encodes a salted disclosure array (bstr contents) with preferred
/// encoding for the array and salt and Preserve for `value` and `key`:
/// `[salt]`, `[salt, value]`, or `[salt, value, key]`. A `key` without a
/// `value` gives `[salt]`. Fails if `value` or `key` cannot be encoded
/// (it holds a `simple(24..=31)`).
pub fn encode_disclosure(
    salt: &[u8],
    value: Option<&Item<'_>>,
    key: Option<&Item<'_>>,
) -> Result<Vec<u8>, CoseError> {
    let n = match (value, key) {
        (Some(_), Some(_)) => 3,
        (Some(_), None) => 2,
        (None, _) => 1,
    };
    let mut out = head(4, n);
    out.extend(head(2, len_u64(salt.len())));
    out.extend(salt);
    if let Some(v) = value {
        out.extend(enc(v)?);
        if let Some(k) = key {
            out.extend(enc(k)?);
        }
    }
    Ok(out)
}

/// The digest of a disclosure given its bstr *contents*: `hash` over the
/// contents wrapped in a preferred bstr head.
pub fn disclosure_digest(hash: HashAlg, contents: &[u8]) -> Vec<u8> {
    // Issue #23: draft -08 Figures 8 and 9 hash the disclosure contents
    // only, but every signed example payload (Figures 5, 26, 28),
    // Appendix G, and the draft's reference generator hash the encoded
    // bstr, head included. The examples are the interoperable behavior.
    let mut encoded = head(2, len_u64(contents.len()));
    encoded.extend(contents);
    digest(hash, &encoded)
}

/// `typ` choice for [`issue`] and [`present`](crate::kbt::present).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Typ {
    /// 293 for an SD-CWT, 294 for an SD-KBT, none for a plain CWT.
    #[default]
    Auto,
    /// No `typ`.
    Omit,
    /// This value.
    Value(ContentType),
}

/// Header options for [`issue`].
#[derive(Debug, Clone, PartialEq)]
pub struct IssueOptions<'a> {
    /// Signature algorithm (written as `alg` and used to sign).
    pub alg: Alg,
    /// `kid` for the protected header.
    pub kid: Option<Cow<'a, [u8]>>,
    /// `typ`.
    pub typ: Typ,
    /// SD hash algorithm. `Some` also writes `sd_alg` to the protected
    /// header of an SD-CWT; `None` omits it and SHA-256 is used. Default
    /// `Some(Sha256)`.
    pub sd_alg: Option<HashAlg>,
    /// Issue an SD-CWT (typ, sd_alg) even when nothing is redacted.
    pub force_sd: bool,
    /// Tags, outermost first. Default `[18]`.
    pub tags: Vec<u64>,
    /// Extra protected header entries, written after the standard ones.
    pub protected_extra: Vec<(Item<'a>, Item<'a>)>,
    /// Extra unprotected header entries, written after `sd_claims`.
    pub unprotected_extra: Vec<(Item<'a>, Item<'a>)>,
    /// RFC 9052 external AAD for the signature.
    pub external_aad: Cow<'a, [u8]>,
}

impl IssueOptions<'_> {
    /// Defaults for `alg`: no kid, automatic typ, `sd_alg` SHA-256 written,
    /// tag 18, no extras, empty external AAD.
    pub fn new(alg: Alg) -> IssueOptions<'static> {
        IssueOptions {
            alg,
            kid: None,
            typ: Typ::Auto,
            sd_alg: Some(HashAlg::Sha256),
            force_sd: false,
            tags: vec![crate::codepoints::TAG_COSE_SIGN1],
            protected_extra: Vec::new(),
            unprotected_extra: Vec::new(),
            external_aad: Cow::Borrowed(&[]),
        }
    }
}

/// The output of [`issue`].
#[derive(Debug, Clone, PartialEq)]
pub struct Issued {
    /// The signed CWT or SD-CWT.
    pub bytes: Vec<u8>,
    /// The disclosures (bstr contents), also in `sd_claims`.
    pub disclosures: Vec<Vec<u8>>,
    /// From [`redact`].
    pub warnings: Vec<RedactWarning>,
}

/// Issues a CWT, or an SD-CWT when `claims` has to-be-redacted or
/// to-be-decoy tags (or `force_sd`).
///
/// Protected header order: `alg` (1), `kid` (4), `typ` (16), `sd_alg`
/// (170), then extras. Unprotected: `sd_claims` (17) when there are
/// disclosures, then extras. Without `rng`, signing is deterministic.
pub fn issue(
    backend: &dyn Sign1Backend,
    claims: &Item<'_>,
    issuer: &Key,
    opts: &IssueOptions<'_>,
    salts: &mut dyn SaltSource,
    rng: Option<&mut dyn CryptoRng>,
) -> Result<Issued, CoseError> {
    if !issuer.is_private() {
        return Err(CoseError::NoPrivateKey);
    }
    let red = redact(claims, opts.sd_alg.unwrap_or(HashAlg::Sha256), salts)?;
    let sd = opts.force_sd || !red.disclosures.is_empty();

    let mut prot = vec![(Item::int(HDR_ALG), Item::int(alg_to_cose(opts.alg)))];
    if let Some(kid) = &opts.kid {
        prot.push((Item::int(HDR_KID), Item::bytes(&kid[..])));
    }
    let typ = match &opts.typ {
        Typ::Auto => sd.then_some(ContentType::Uint(TYP_SD_CWT)),
        Typ::Omit => None,
        Typ::Value(t) => Some(t.clone()),
    };
    if let Some(t) = &typ {
        prot.push((Item::int(HDR_TYP), content_type_item(t)));
    }
    if sd && let Some(h) = opts.sd_alg {
        prot.push((Item::int(HDR_SD_ALG), Item::int(h.cose_label())));
    }
    prot.extend(opts.protected_extra.iter().cloned());

    let mut unprot = Vec::new();
    if !red.disclosures.is_empty() {
        let items = red
            .disclosures
            .iter()
            .map(|d| Item::bytes(&d[..]))
            .collect();
        unprot.push((Item::int(HDR_SD_CLAIMS), Item::array(items)));
    }
    unprot.extend(opts.unprotected_extra.iter().cloned());

    let parts = Sign1Parts {
        tags: opts.tags.clone(),
        protected: Cow::Owned(enc(&Item::map(prot))?),
        unprotected: Item::map(unprot),
        payload: Some(Cow::Owned(enc(&red.payload)?)),
        signature: Cow::Borrowed(&[]),
    };
    let sign = SignOptions {
        alg: opts.alg,
        external_aad: &opts.external_aad,
        detached_payload: None,
    };
    let bytes = backend.sign(&parts, issuer, &sign, rng)?;
    Ok(Issued {
        bytes,
        disclosures: red.disclosures,
        warnings: red.warnings,
    })
}

/// The resolved `sd_alg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdAlg {
    /// Absent: SHA-256 (sd-cwt-08 §6).
    Default,
    /// A supported hash: -16 SHA-256, -43 SHA-384, -44 SHA-512.
    Known(HashAlg),
    /// An integer this crate does not support; no digests can be computed.
    Unsupported(i64),
    /// Present but not an integer.
    Invalid,
}

impl SdAlg {
    /// The hash to use, if any.
    pub fn hash(self) -> Option<HashAlg> {
        match self {
            SdAlg::Default => Some(HashAlg::Sha256),
            SdAlg::Known(h) => Some(h),
            SdAlg::Unsupported(_) | SdAlg::Invalid => None,
        }
    }
}

/// What a disclosure holds (sd-cwt-08 §4.1 Figure 12).
#[derive(Debug, Clone, PartialEq)]
pub enum DisclosureContent<'a> {
    /// `[salt, value, key]`: a redacted claim key.
    Claim {
        /// Salt.
        salt: Cow<'a, [u8]>,
        /// Claim value.
        value: Item<'a>,
        /// Claim key (int or text).
        key: Item<'a>,
    },
    /// `[salt, value]`: a redacted array element.
    Element {
        /// Salt.
        salt: Cow<'a, [u8]>,
        /// Element value.
        value: Item<'a>,
    },
    /// `[salt]`: a decoy.
    Decoy {
        /// Salt.
        salt: Cow<'a, [u8]>,
    },
    /// Anything else.
    Malformed(MalformedDisclosure),
}

/// Why a disclosure is malformed.
#[derive(Debug, Clone, PartialEq)]
pub enum MalformedDisclosure {
    /// The `sd_claims` element is not a byte string.
    NotBytes,
    /// The contents are not one well-formed CBOR item.
    NotCbor,
    /// Not an array.
    NotArray,
    /// An array of length 0 or more than 3.
    WrongLength(usize),
    /// The salt is not a byte string.
    SaltNotBytes,
    /// The claim key is not an int or text string.
    KeyNotLabel,
}

/// One entry of `sd_claims`.
#[derive(Debug, Clone, PartialEq)]
pub struct Disclosure<'a> {
    /// Position in `sd_claims`.
    pub index: usize,
    /// The bstr with its span in [`Sign1::bytes`].
    pub bytes: Bstr<'a>,
    /// Hash of the encoded bstr exactly as received (head included).
    /// `None` when `sd_alg` is not supported or the element is not a bstr.
    pub digest: Option<Vec<u8>>,
    /// The decoded contents.
    pub content: DisclosureContent<'a>,
}

/// A parsed SD-CWT (or any COSE_Sign1 viewed as one).
#[derive(Debug, Clone, PartialEq)]
pub struct SdCwt<'a> {
    /// The COSE_Sign1.
    pub sign1: Sign1<'a>,
    /// `sd_alg` from the protected header.
    pub sd_alg: SdAlg,
    /// `sd_claims`, in order (empty when absent).
    pub disclosures: Vec<Disclosure<'a>>,
    /// SD-specific structural problems (`sd_claims` not an array, empty,
    /// misplaced, ...).
    pub diagnostics: Vec<Diagnostic>,
}

impl<'a> SdCwt<'a> {
    /// Views a parsed COSE_Sign1 as an SD-CWT.
    pub fn from_sign1(sign1: Sign1<'a>) -> SdCwt<'a> {
        let mut diagnostics = Vec::new();
        let prot = sign1.protected_header();
        let unprot = sign1.unprotected.as_ref();

        let sd_alg = match prot.and_then(|m| map_get(m, HDR_SD_ALG)) {
            None => SdAlg::Default,
            Some(v) => match int_of(v) {
                Some(l) => HashAlg::from_cose_label(l).map_or(SdAlg::Unsupported(l), SdAlg::Known),
                None => SdAlg::Invalid,
            },
        };
        if let Some(v) = prot.and_then(|m| map_get(m, HDR_SD_CLAIMS)) {
            let offset = sign1.protected.as_ref().map_or(0, Bstr::content_offset);
            diagnostics.push(Diagnostic {
                part: Part::Protected,
                span: Some(shift(v.span, offset)),
                kind: DiagnosticKind::MisplacedSdHeader(HDR_SD_CLAIMS),
            });
        }
        if let Some(v) = unprot.and_then(|u| map_get(u, HDR_SD_ALG)) {
            diagnostics.push(Diagnostic {
                part: Part::Unprotected,
                span: Some(v.span),
                kind: DiagnosticKind::MisplacedSdHeader(HDR_SD_ALG),
            });
        }

        let hash = sd_alg.hash();
        let mut disclosures = Vec::new();
        if let Some(v) = unprot.and_then(|u| map_get(u, HDR_SD_CLAIMS)) {
            match &v.value {
                Value::Array(items) => {
                    if items.is_empty() {
                        diagnostics.push(Diagnostic {
                            part: Part::Unprotected,
                            span: Some(v.span),
                            kind: DiagnosticKind::EmptySdClaims,
                        });
                    }
                    for (index, e) in items.iter().enumerate() {
                        disclosures.push(match bstr_of(e) {
                            Some(bytes) => Disclosure {
                                index,
                                digest: hash
                                    .and_then(|h| slice(sign1.bytes, e.span).map(|b| digest(h, b))),
                                content: content_of(&bytes),
                                bytes,
                            },
                            None => Disclosure {
                                index,
                                bytes: Bstr {
                                    span: e.span,
                                    raw: Cow::Borrowed(&[]),
                                    decoded: None,
                                },
                                digest: None,
                                content: DisclosureContent::Malformed(
                                    MalformedDisclosure::NotBytes,
                                ),
                            },
                        });
                    }
                }
                _ => diagnostics.push(Diagnostic {
                    part: Part::Unprotected,
                    span: Some(v.span),
                    kind: DiagnosticKind::NotArray,
                }),
            }
        }
        SdCwt {
            sign1,
            sd_alg,
            disclosures,
            diagnostics,
        }
    }
}

/// Classifies decoded disclosure contents (sd-cwt-08 §4.1 Figure 12).
fn content_of<'a>(b: &Bstr<'a>) -> DisclosureContent<'a> {
    use MalformedDisclosure as M;
    let Some(Ok(item)) = &b.decoded else {
        return DisclosureContent::Malformed(M::NotCbor);
    };
    let Value::Array(a) = &item.value else {
        return DisclosureContent::Malformed(M::NotArray);
    };
    if a.is_empty() || a.len() > 3 {
        return DisclosureContent::Malformed(M::WrongLength(a.len()));
    }
    let salt = match a.first().map(|s| &s.value) {
        Some(Value::Bytes(s)) => s.clone(),
        _ => return DisclosureContent::Malformed(M::SaltNotBytes),
    };
    match (a.get(1), a.get(2)) {
        (None, _) => DisclosureContent::Decoy { salt },
        (Some(value), None) => DisclosureContent::Element {
            salt,
            value: value.clone(),
        },
        (Some(value), Some(key)) => match key.value {
            Value::Uint(_) | Value::Nint(_) | Value::Text(_) => DisclosureContent::Claim {
                salt,
                value: value.clone(),
                key: key.clone(),
            },
            _ => DisclosureContent::Malformed(M::KeyNotLabel),
        },
    }
}

/// Parses an SD-CWT with `backend`.
pub fn parse_sd_cwt<'a>(
    backend: &dyn Sign1Backend,
    bytes: &'a [u8],
) -> Result<SdCwt<'a>, CoseError> {
    backend.parse(bytes).map(SdCwt::from_sign1)
}

/// One step in a path to a container in the issued structure.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathSeg {
    /// The payload claims map (always first unless `Disclosure`).
    Payload,
    /// The value of disclosure `i` (always first unless `Payload`).
    Disclosure(usize),
    /// A map entry.
    Key(Label),
    /// An array element (position in the issued array).
    Index(usize),
}

/// The kind of place a digest sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlotKind {
    /// In a `simple(59)` array: a redacted claim key.
    ClaimKey,
    /// A `60(digest)` array element.
    ArrayElement,
}

/// A digest in the payload or inside a disclosed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    /// Path to the map (for `ClaimKey`) or array (for `ArrayElement`).
    pub container: Vec<PathSeg>,
    /// Index in the `simple(59)` array, or in the issued array.
    pub position: usize,
    /// Which kind.
    pub kind: SlotKind,
    /// The digest bytes.
    pub digest: Vec<u8>,
    /// The digest bstr item (inside tag 60 for an element), in
    /// [`Sign1::bytes`] coordinates.
    pub span: Span,
}

/// A disclosure and the digest it matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// Disclosure index.
    pub disclosure: usize,
    /// Where its digest is.
    pub slot: Slot,
}

/// Why a disclosure's contents are not allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForbiddenReason {
    /// A top-level claim that is never redacted (sd-cwt-08 Table 2).
    NeverRedactedClaim(i64),
    /// A to-be-redacted (58) or to-be-decoy (62) tag inside the disclosure
    /// (sd-cwt-08 §5.3 `safe_tag`).
    PreIssuanceTag(u64),
    /// A claim disclosure matched an array element digest, or an element
    /// disclosure matched a claim key digest.
    KindMismatch,
}

/// A forbidden disclosure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forbidden {
    /// Disclosure index.
    pub disclosure: usize,
    /// Why.
    pub reason: ForbiddenReason,
}

/// A disclosed claim key that already exists in the same map (sd-cwt-08
/// §9 step 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCollision {
    /// Disclosure index.
    pub disclosure: usize,
    /// The key.
    pub key: Label,
}

/// Who is checking: a Holder needs a disclosure for every digest; a
/// Verifier does not (sd-cwt-08 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// Holder validation (§6.2).
    Holder,
    /// Verifier validation (§9).
    Verifier,
}

/// The disclosure matching report (SPEC §6 "SD").
#[derive(Debug, Clone, PartialEq)]
pub struct SdReport<'a> {
    /// `sd_alg` validity.
    pub sd_alg: SdAlg,
    /// Disclosures that matched a digest, in disclosure order.
    pub matched: Vec<Match>,
    /// Disclosures whose digest is nowhere (well-formed but unmatched).
    pub unmatched: Vec<usize>,
    /// Disclosures whose bytes repeat an earlier disclosure.
    pub duplicate_disclosures: Vec<usize>,
    /// Digests that occur in more than one slot.
    pub duplicate_digests: Vec<Vec<u8>>,
    /// Digests without a disclosure (decoys or withheld claims), in
    /// document order.
    pub undisclosed: Vec<Slot>,
    /// Disclosures with forbidden contents.
    pub forbidden: Vec<Forbidden>,
    /// Malformed disclosures.
    pub malformed: Vec<usize>,
    /// Disclosed keys that collide with existing keys.
    pub key_collisions: Vec<KeyCollision>,
    /// The Validated Disclosed Claims Set: disclosed claims put back, all
    /// remaining digests and decoys removed. A disclosed claim key replaces
    /// the `simple(59)` entry's position (in digest order); an element is
    /// replaced in place. Untouched items keep their original encoding.
    /// `None` when the payload is not a decodable map.
    pub processed: Option<Item<'a>>,
    /// The SD structural problems of [`SdCwt::diagnostics`] (an empty or
    /// misplaced `sd_claims`, ...); any of them makes the report invalid.
    pub diagnostics: Vec<Diagnostic>,
}

impl SdReport<'_> {
    /// Valid for `mode`: no unmatched, duplicate, forbidden, malformed, or
    /// colliding disclosures, no duplicate digests, a usable `sd_alg`, and
    /// (Holder only) no undisclosed digests. SD structural diagnostics
    /// also make it invalid.
    pub fn is_valid(&self, mode: MatchMode) -> bool {
        self.unmatched.is_empty()
            && self.duplicate_disclosures.is_empty()
            && self.duplicate_digests.is_empty()
            && self.forbidden.is_empty()
            && self.malformed.is_empty()
            && self.key_collisions.is_empty()
            && self.diagnostics.is_empty()
            && self.sd_alg.hash().is_some()
            && (mode == MatchMode::Verifier || self.undisclosed.is_empty())
    }
}

/// Matches disclosures to digests, recursing into disclosed values
/// (sd-cwt-08 §7, Appendix G), and rebuilds the claims set.
pub fn match_disclosures<'a>(sd: &SdCwt<'a>) -> SdReport<'a> {
    let mut by_digest: HashMap<&[u8], usize> = HashMap::new();
    let mut encodings: HashSet<&[u8]> = HashSet::new();
    let mut duplicate_disclosures = Vec::new();
    let mut malformed = Vec::new();
    for d in &sd.disclosures {
        if let DisclosureContent::Malformed(why) = &d.content {
            malformed.push(d.index);
            if *why == MalformedDisclosure::NotBytes {
                continue;
            }
        }
        let encoded = slice(sd.sign1.bytes, d.bytes.span).unwrap_or_default();
        if !encodings.insert(encoded) {
            duplicate_disclosures.push(d.index);
            continue;
        }
        if let Some(dg) = &d.digest {
            by_digest.entry(dg.as_slice()).or_insert(d.index);
        }
    }

    let mut m = Matcher {
        sd,
        by_digest,
        seen: HashSet::new(),
        duplicate_digests: Vec::new(),
        matched: Vec::new(),
        undisclosed: Vec::new(),
        forbidden: Vec::new(),
        key_collisions: Vec::new(),
    };
    let processed = match (&sd.sign1.payload, sd.sign1.payload_item()) {
        (Payload::Attached(b), Some(claims)) if matches!(claims.value, Value::Map(_)) => {
            Some(m.process(
                claims,
                &mut vec![PathSeg::Payload],
                b.content_offset(),
                true,
            ))
        }
        _ => None,
    };
    for d in &sd.disclosures {
        if let DisclosureContent::Claim { value, .. } | DisclosureContent::Element { value, .. } =
            &d.content
            && let Some(t) = pre_issuance_tag(value)
        {
            m.forbidden.push(Forbidden {
                disclosure: d.index,
                reason: ForbiddenReason::PreIssuanceTag(t),
            });
        }
    }
    m.matched.sort_by_key(|x| x.disclosure);
    m.forbidden.sort_by_key(|f| f.disclosure);

    let matched: HashSet<usize> = m.matched.iter().map(|x| x.disclosure).collect();
    let unmatched = sd
        .disclosures
        .iter()
        .map(|d| d.index)
        .filter(|i| {
            !matched.contains(i) && !malformed.contains(i) && !duplicate_disclosures.contains(i)
        })
        .collect();
    SdReport {
        sd_alg: sd.sd_alg,
        matched: m.matched,
        unmatched,
        duplicate_disclosures,
        duplicate_digests: m.duplicate_digests,
        undisclosed: m.undisclosed,
        forbidden: m.forbidden,
        malformed,
        key_collisions: m.key_collisions,
        processed,
        diagnostics: sd.diagnostics.clone(),
    }
}

/// The first to-be-redacted or to-be-decoy tag inside a disclosed value.
fn pre_issuance_tag(value: &Item<'_>) -> Option<u64> {
    let mut found = None;
    walk(value, |i| {
        if let Value::Tag(t @ (TAG_TO_BE_REDACTED | TAG_TO_BE_DECOY), _) = i.value {
            found = found.or(Some(t));
        }
    });
    found
}

/// The state of one [`match_disclosures`] run.
struct Matcher<'s, 'a> {
    sd: &'s SdCwt<'a>,
    /// Digest to the first disclosure with it.
    by_digest: HashMap<&'s [u8], usize>,
    /// Digests already found in a slot.
    seen: HashSet<Vec<u8>>,
    duplicate_digests: Vec<Vec<u8>>,
    matched: Vec<Match>,
    undisclosed: Vec<Slot>,
    forbidden: Vec<Forbidden>,
    key_collisions: Vec<KeyCollision>,
}

impl<'a> Matcher<'_, 'a> {
    /// Records a slot; returns the disclosure that fills it, if any. A
    /// repeated digest is recorded as a duplicate and never filled again.
    fn take(&mut self, slot: Slot) -> Option<usize> {
        if !self.seen.insert(slot.digest.clone()) {
            if !self.duplicate_digests.contains(&slot.digest) {
                self.duplicate_digests.push(slot.digest);
            }
            return None;
        }
        match self.by_digest.get(slot.digest.as_slice()) {
            Some(&disclosure) => {
                self.matched.push(Match { disclosure, slot });
                Some(disclosure)
            }
            None => {
                self.undisclosed.push(slot);
                None
            }
        }
    }

    /// Processes the value of disclosure `i`.
    fn disclosed(&mut self, i: usize, value: &Item<'a>) -> Item<'a> {
        let offset = self
            .sd
            .disclosures
            .get(i)
            .map_or(0, |d| d.bytes.content_offset());
        self.process(value, &mut vec![PathSeg::Disclosure(i)], offset, false)
    }

    /// Finds the slots in `item` (spans inside it are `offset` bytes into
    /// [`Sign1::bytes`]) and returns it with disclosures put back and the
    /// remaining digests removed.
    fn process(
        &mut self,
        item: &Item<'a>,
        path: &mut Vec<PathSeg>,
        offset: usize,
        top: bool,
    ) -> Item<'a> {
        let sd = self.sd;
        match &item.value {
            Value::Map(entries) => {
                let existing: Vec<Label> =
                    entries.iter().filter_map(|(k, _)| label_of(k)).collect();
                let mut disclosed_keys: Vec<Label> = Vec::new();
                let mut out = Vec::with_capacity(entries.len());
                for (k, v) in entries {
                    if k.value != Value::Simple(SIMPLE_REDACTED_KEYS) {
                        match label_of(k) {
                            Some(label) => {
                                path.push(PathSeg::Key(label));
                                let v = self.process(v, path, offset, false);
                                path.pop();
                                out.push((k.clone(), v));
                            }
                            None => out.push((k.clone(), v.clone())),
                        }
                        continue;
                    }
                    let Value::Array(digests) = &v.value else {
                        continue;
                    };
                    for (position, dg) in digests.iter().enumerate() {
                        let Value::Bytes(digest) = &dg.value else {
                            continue;
                        };
                        let slot = Slot {
                            container: path.clone(),
                            position,
                            kind: SlotKind::ClaimKey,
                            digest: digest.to_vec(),
                            span: shift(dg.span, offset),
                        };
                        let Some(i) = self.take(slot) else {
                            continue;
                        };
                        match sd.disclosures.get(i).map(|d| &d.content) {
                            Some(DisclosureContent::Claim { value, key, .. }) => {
                                let Some(label) = label_of(key) else {
                                    continue;
                                };
                                if let Label::Int(n) = &label
                                    && top
                                    && NEVER_REDACTED.contains(n)
                                {
                                    self.forbidden.push(Forbidden {
                                        disclosure: i,
                                        reason: ForbiddenReason::NeverRedactedClaim(*n),
                                    });
                                }
                                if existing.contains(&label) || disclosed_keys.contains(&label) {
                                    self.key_collisions.push(KeyCollision {
                                        disclosure: i,
                                        key: label,
                                    });
                                    continue;
                                }
                                let v = self.disclosed(i, value);
                                disclosed_keys.push(label);
                                out.push((key.clone(), v));
                            }
                            Some(DisclosureContent::Element { .. }) => {
                                self.forbidden.push(Forbidden {
                                    disclosure: i,
                                    reason: ForbiddenReason::KindMismatch,
                                });
                            }
                            _ => {}
                        }
                    }
                }
                with_value(item, Value::Map(out))
            }
            Value::Array(elements) => {
                let mut out = Vec::with_capacity(elements.len());
                for (position, e) in elements.iter().enumerate() {
                    let Value::Tag(TAG_REDACTED_ELEMENT, inner) = &e.value else {
                        path.push(PathSeg::Index(position));
                        out.push(self.process(e, path, offset, false));
                        path.pop();
                        continue;
                    };
                    let Value::Bytes(digest) = &inner.value else {
                        out.push(e.clone());
                        continue;
                    };
                    let slot = Slot {
                        container: path.clone(),
                        position,
                        kind: SlotKind::ArrayElement,
                        digest: digest.to_vec(),
                        span: shift(inner.span, offset),
                    };
                    let Some(i) = self.take(slot) else {
                        continue;
                    };
                    match sd.disclosures.get(i).map(|d| &d.content) {
                        Some(DisclosureContent::Element { value, .. }) => {
                            out.push(self.disclosed(i, value));
                        }
                        Some(DisclosureContent::Claim { .. }) => {
                            self.forbidden.push(Forbidden {
                                disclosure: i,
                                reason: ForbiddenReason::KindMismatch,
                            });
                        }
                        _ => {}
                    }
                }
                with_value(item, Value::Array(out))
            }
            Value::Tag(t, inner) => with_value(
                item,
                Value::Tag(*t, Box::new(self.process(inner, path, offset, false))),
            ),
            _ => item.clone(),
        }
    }
}
