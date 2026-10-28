//! The [`Sign1Backend`] seam and its default implementation.
use std::borrow::Cow;

use tokenator_cbor::{DecodeError, Item, Value, decode};
use tokenator_crypto::{Alg, DeclaredAlg, rand_core::CryptoRng};
use tokenator_keys::Key;

use crate::codepoints::{TAG_COSE_SIGN1, TAG_CWT};
use crate::util::{enc, head, label_eq, label_of, len_u64};
use crate::{Bstr, CoseError, Diagnostic, DiagnosticKind, Part, Payload, RawBytes, Sign1};

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
        let protected = msg
            .protected
            .as_ref()
            .ok_or(CoseError::MalformedPart(Part::Protected))?;
        let unprotected = msg
            .unprotected
            .as_ref()
            .ok_or(CoseError::MalformedPart(Part::Unprotected))?;
        let payload = match &msg.payload {
            Payload::Attached(b) => Some(b.raw.clone()),
            Payload::Detached { .. } => None,
            Payload::Malformed => return Err(CoseError::MalformedPart(Part::Payload)),
        };
        let signature = msg
            .signature
            .as_ref()
            .ok_or(CoseError::MalformedPart(Part::Signature))?;
        Ok(Sign1Parts {
            tags: msg.tags.clone(),
            protected: protected.raw.clone(),
            unprotected: unprotected.clone(),
            payload,
            signature: signature.raw.clone(),
        })
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
    /// Fails if the unprotected item cannot be encoded (it holds a
    /// `simple(24..=31)`).
    fn assemble(&self, parts: &Sign1Parts<'_>) -> Result<Vec<u8>, CoseError>;

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
        let private = key.private_key().ok_or(CoseError::NoPrivateKey)?;
        let payload: &[u8] = match &parts.payload {
            Some(p) => p,
            None => opts.detached_payload.ok_or(CoseError::DetachedPayload)?,
        };
        let tbs = self.sig_structure(&parts.protected, opts.external_aad, payload);
        let signature = match rng {
            Some(rng) => tokenator_crypto::sign(opts.alg, private, &tbs, rng)?,
            None => tokenator_crypto::sign_deterministic(opts.alg, private, &tbs)?,
        };
        self.assemble(&Sign1Parts {
            tags: parts.tags.clone(),
            protected: Cow::Borrowed(&parts.protected),
            unprotected: parts.unprotected.clone(),
            payload: parts.payload.as_deref().map(Cow::Borrowed),
            signature: Cow::Owned(signature),
        })
    }

    /// Verifies `msg` with the public part of `key` and returns the
    /// algorithm used: `opts.alg`, else the header `alg`.
    fn verify(
        &self,
        msg: &Sign1<'_>,
        key: &Key,
        opts: &VerifyOptions<'_>,
    ) -> Result<Alg, CoseError> {
        let alg = match opts.alg {
            Some(alg) => alg,
            None => match msg.alg() {
                None => return Err(CoseError::MissingAlg),
                Some(DeclaredAlg::Known(alg)) => alg,
                Some(other) => return Err(CoseError::UnsupportedAlg(other)),
            },
        };
        let protected = msg
            .protected
            .as_ref()
            .ok_or(CoseError::MalformedPart(Part::Protected))?;
        let signature = msg
            .signature
            .as_ref()
            .ok_or(CoseError::MalformedPart(Part::Signature))?;
        let payload: &[u8] = match &msg.payload {
            Payload::Attached(b) => &b.raw,
            Payload::Detached { .. } => opts.detached_payload.ok_or(CoseError::DetachedPayload)?,
            Payload::Malformed => return Err(CoseError::MalformedPart(Part::Payload)),
        };
        let tbs = self.sig_structure(&protected.raw, opts.external_aad, payload);
        tokenator_crypto::verify(alg, &key.public_key(), &tbs, &signature.raw)?;
        Ok(alg)
    }
}

/// The default, span-preserving backend over `tokenator-cbor`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CborBackend;

impl Sign1Backend for CborBackend {
    fn parse<'a>(&self, bytes: &'a [u8]) -> Result<Sign1<'a>, CoseError> {
        parse_sign1(bytes)
    }

    fn sig_structure(&self, protected: &[u8], external_aad: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(protected.len() + external_aad.len() + payload.len() + 32);
        out.extend(head(4, 4));
        out.extend(head(3, 10));
        out.extend(b"Signature1");
        for b in [protected, external_aad, payload] {
            out.extend(head(2, len_u64(b.len())));
            out.extend(b);
        }
        out
    }

    fn assemble(&self, parts: &Sign1Parts<'_>) -> Result<Vec<u8>, CoseError> {
        let mut out = Vec::new();
        for t in &parts.tags {
            out.extend(head(6, *t));
        }
        out.extend(head(4, 4));
        push_bstr(&mut out, &parts.protected);
        out.extend(enc(&parts.unprotected)?);
        match &parts.payload {
            Some(p) => push_bstr(&mut out, p),
            None => out.push(0xf6),
        }
        push_bstr(&mut out, &parts.signature);
        Ok(out)
    }
}

fn push_bstr(out: &mut Vec<u8>, b: &[u8]) {
    out.extend(head(2, len_u64(b.len())));
    out.extend(b);
}

/// COSE structures other than COSE_Sign1 (RFC 9052 §2).
const UNSUPPORTED_TAGS: [u64; 5] = [16, 17, 96, 97, 98];

/// Decodes byte string contents as one CBOR item; `None` when empty.
pub(crate) fn decode_contents<'a>(raw: &Cow<'a, [u8]>) -> Option<Result<Item<'a>, DecodeError>> {
    if raw.is_empty() {
        return None;
    }
    Some(match raw {
        Cow::Borrowed(b) => decode(b),
        Cow::Owned(b) => decode(b).map(Item::into_owned),
    })
}

/// A byte string item as a [`Bstr`], decoding its contents.
pub(crate) fn bstr_of<'a>(item: &Item<'a>) -> Option<Bstr<'a>> {
    match &item.value {
        Value::Bytes(raw) => Some(Bstr {
            span: item.span,
            raw: raw.clone(),
            decoded: decode_contents(raw),
        }),
        _ => None,
    }
}

fn parse_sign1(bytes: &[u8]) -> Result<Sign1<'_>, CoseError> {
    let item = decode(bytes)?;
    let mut diagnostics = Vec::new();

    let mut tags = Vec::new();
    let mut tag_spans = Vec::new();
    let mut inner = &item;
    while let Value::Tag(t, content) = &inner.value {
        tags.push(*t);
        tag_spans.push(inner.span);
        inner = content;
    }
    if let Some(tag) = tags.iter().find(|t| UNSUPPORTED_TAGS.contains(t)) {
        return Err(CoseError::UnsupportedStructure { tag: *tag });
    }
    let Value::Array(els) = &inner.value else {
        return Err(CoseError::NotSign1);
    };
    let last = tags.len().saturating_sub(1);
    let first_is_cwt = tags.first() == Some(&TAG_CWT);
    for (i, (t, span)) in tags.iter().zip(&tag_spans).enumerate() {
        let ok = (*t == TAG_CWT && i == 0)
            || (*t == TAG_COSE_SIGN1 && i == last && (i == 0 || (i == 1 && first_is_cwt)));
        if !ok {
            diagnostics.push(Diagnostic {
                part: Part::Envelope,
                span: Some(*span),
                kind: DiagnosticKind::UnexpectedTag(*t),
            });
        }
    }
    if els.len() != 4 {
        diagnostics.push(Diagnostic {
            part: Part::Envelope,
            span: Some(inner.span),
            kind: DiagnosticKind::WrongArity(els.len()),
        });
    }
    let mut diag = |part: Part, it: &Item<'_>, kind: DiagnosticKind| {
        diagnostics.push(Diagnostic {
            part,
            span: Some(it.span),
            kind,
        });
    };

    let protected = els.first().and_then(|p| {
        let b = bstr_of(p);
        match &b {
            None => diag(Part::Protected, p, DiagnosticKind::NotBytes),
            Some(Bstr {
                decoded: Some(Err(e)),
                ..
            }) => diag(Part::Protected, p, DiagnosticKind::Undecodable(e.clone())),
            Some(Bstr {
                decoded: Some(Ok(m)),
                ..
            }) if !matches!(m.value, Value::Map(_)) => {
                diag(Part::Protected, p, DiagnosticKind::NotMap);
            }
            Some(_) => {}
        }
        b
    });

    let unprotected = els.get(1).and_then(|u| match &u.value {
        Value::Map(_) => Some(u.clone()),
        _ => {
            diag(Part::Unprotected, u, DiagnosticKind::NotMap);
            None
        }
    });
    if let (Some(Value::Map(prot)), Some(Value::Map(unprot))) = (
        protected
            .as_ref()
            .and_then(|p| p.decoded.as_ref())
            .and_then(|d| d.as_ref().ok())
            .map(|m| &m.value),
        unprotected.as_ref().map(|u| &u.value),
    ) {
        for (k, _) in unprot {
            if let Some(label) = label_of(k)
                && prot.iter().any(|(pk, _)| label_eq(pk, &label))
            {
                diag(
                    Part::Unprotected,
                    k,
                    DiagnosticKind::LabelInBothBuckets(label),
                );
            }
        }
    }

    let payload = match els.get(2) {
        None => Payload::Malformed,
        Some(p) => match &p.value {
            Value::Null => Payload::Detached { span: p.span },
            _ => match bstr_of(p) {
                Some(b) => Payload::Attached(b),
                None => {
                    diag(Part::Payload, p, DiagnosticKind::NotBytes);
                    Payload::Malformed
                }
            },
        },
    };

    let signature = els.get(3).and_then(|s| match &s.value {
        Value::Bytes(raw) => Some(RawBytes {
            span: s.span,
            raw: raw.clone(),
        }),
        _ => {
            diag(Part::Signature, s, DiagnosticKind::NotBytes);
            None
        }
    });

    let span = inner.span;
    Ok(Sign1 {
        bytes,
        base: 0,
        item,
        tags,
        span,
        protected,
        unprotected,
        payload,
        signature,
        diagnostics,
    })
}
