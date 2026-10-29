//! Resign, tamper, re-encode, edit disclosures, and manual decoding.

use std::borrow::Cow;

use tokenator_cbor::{EncodeMode, Item, Value, decode, encode};
use tokenator_cose::edit::{self as cedit, EquivalentEncoding as CoseEquivalent, ResignOptions, TamperOp as CoseTamper};
use tokenator_cose::sd::encode_disclosure;
use tokenator_cose::{CborBackend, Sign1Backend};
use tokenator_crypto::{alg_from_cose, alg_from_jose, alg_to_cose, alg_to_jose};
use tokenator_jose as tj;
use tokenator_json::Value as JValue;
use tokenator_registry::Registry;

use crate::actions::{cose_error, edn_value, jose_error, json_value, need_randomness, result_doc, sign, to_json_text};
use crate::cbor::{bstr_contents, int_of};
use crate::detect::layer_td;
use crate::dto::actions::{
    AlgValue, CborSerialization, DecodeEmbeddedRequest, DisclosureOp, EditDisclosuresRequest,
    EquivalentEncoding, ManualDecode, PartRef, ReencodeRequest, Reencoded, ResignRequest,
    TamperOp, TamperRequest,
};
use crate::dto::common::{ByteRange, KidValue, NodeId};
use crate::dto::detect::{Family, Kind, Layer};
use crate::dto::document::{Diagnostic, Document, NodeKind, Severity};
use crate::dto::error::{EngineError, ErrorCode};
use crate::keyring::{fits, resolve_private};
use crate::util::{err, rng, seed32, u32_of, unhex, unused_rng};
use crate::view::jose::{b64u, with_parsed};
use crate::view::{self, cbor::MainText, cbor::Role};

fn utf8(bytes: &[u8]) -> Result<&str, EngineError> {
    std::str::from_utf8(bytes).map_err(|_| EngineError::new(ErrorCode::Parse, "not UTF-8"))
}

fn splice(text: &str, start: usize, end: usize, new: &str) -> String {
    let (a, b) = (text.get(..start).unwrap_or(text), text.get(end..).unwrap_or(""));
    format!("{a}{new}{b}")
}

// ---------------------------------------------------------------- signed content

/// The signed parts of a token: (protected, payload) per signature, plus
/// the KB-JWT's. `None` when it does not parse.
fn signed_parts(kind: &Kind, bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    if kind.family() == Some(Family::Jose) {
        let text = std::str::from_utf8(bytes).ok()?;
        return with_parsed(text, |p, _| {
            let jws = p.token.jws();
            let mut out = Vec::new();
            for s in &jws.signatures {
                out.push(s.protected.as_ref().map(|p| p.text().as_bytes().to_vec()).unwrap_or_default());
            }
            out.push(jws.payload.text().as_bytes().to_vec());
            if let Some(kb) = p.token.sd_jwt().and_then(|sd| sd.kb_jwt.as_ref()) {
                out.push(kb.signatures.first().and_then(|s| s.protected.as_ref()).map(|p| p.text().as_bytes().to_vec()).unwrap_or_default());
                out.push(kb.payload.text().as_bytes().to_vec());
            }
            out
        })
        .ok();
    }
    let msg = CborBackend.parse(bytes).ok()?;
    Some(vec![
        msg.protected.as_ref().map(|p| p.raw.to_vec()).unwrap_or_default(),
        msg.payload_bytes().map(<[u8]>::to_vec).unwrap_or_default(),
    ])
}

/// Whether signed content differs between two encodings of a token.
pub(crate) fn signed_changed(kind: &Kind, old: &[u8], new: &[u8]) -> bool {
    if !kind.is_signed() {
        return false;
    }
    match (signed_parts(kind, old), signed_parts(kind, new)) {
        (Some(a), Some(b)) => a != b,
        _ => old != new,
    }
}

fn family(kind: &Kind) -> Result<Family, EngineError> {
    match kind.family() {
        Some(f) if kind.is_signed() => Ok(f),
        _ => err(ErrorCode::UnsupportedKind, format!("not a signed token: {}", kind.label())),
    }
}

// ---------------------------------------------------------------- resign

pub(crate) fn resign(registry: &Registry, req: &ResignRequest) -> Result<Document, EngineError> {
    let fam = family(&req.doc.kind)?;
    let key = resolve_private(&req.key)?;
    let seed = seed32(req.randomness.as_ref())?;
    let wanted = match &req.alg {
        Some(name) => Some(alg_from_jose(name).ok_or_else(|| EngineError::new(ErrorCode::UnsupportedAlg, format!("unsupported algorithm {name}")))?),
        None => None,
    };
    let out = match fam {
        Family::Jose => {
            let text = utf8(&req.doc.bytes)?;
            with_parsed(text, |p, padded| -> Result<String, EngineError> {
                let jws = p.token.jws();
                let sig = jws.signatures.first().ok_or_else(|| EngineError::new(ErrorCode::Parse, "no signature"))?;
                let alg = match wanted {
                    Some(a) => a,
                    None => {
                        let header = sig.protected.as_ref().and_then(|h| h.json().ok());
                        match header.map(|h| tj::header_facts(&h).alg) {
                            Some(tj::AlgFact::Known(a)) => a,
                            other => return err(ErrorCode::UnsupportedAlg, format!("cannot sign with the header alg {other:?}")),
                        }
                    }
                };
                if !fits(&key, alg) {
                    return err(ErrorCode::UnsupportedAlg, format!("{} does not fit this key", alg_to_jose(alg)));
                }
                need_randomness(alg, seed.as_ref())?;
                let input = jws.signing_input(0).unwrap_or_default();
                let s = sign(alg, &key, input.as_bytes(), seed.as_ref(), "resign")?;
                let span = sig.signature.span();
                if padded || span.end > text.len() {
                    return err(ErrorCode::InvalidInput, "the token has no signature segment");
                }
                Ok(splice(text, span.start, span.end, &b64u(&s)))
            })
            .map_err(|e| EngineError::new(ErrorCode::Parse, format!("{e:?}")))??
            .into_bytes()
        }
        Family::Cose => {
            if let Some(a) = wanted
                && !fits(&key, a)
            {
                return err(ErrorCode::UnsupportedAlg, format!("{} does not fit this key", alg_to_jose(a)));
            }
            let opts = ResignOptions {
                alg: wanted,
                ..ResignOptions::default()
            };
            let mut r = seed.as_ref().map(|s| rng(s, "resign"));
            cedit::resign(&CborBackend, &req.doc.bytes, &key, &opts, r.as_mut().map(|r| r as &mut dyn tokenator_cose::CryptoRng))
                .map_err(|e| cose_error(&e))?
        }
    };
    let mut doc = view::document(registry, &req.doc.kind, &out, Vec::new(), &req.view)?;
    doc.signature_stale = false;
    Ok(doc)
}

// ---------------------------------------------------------------- tamper

fn jose_part(p: PartRef) -> tj::PartRef {
    match p {
        PartRef::Protected => tj::PartRef::ProtectedHeader(0),
        PartRef::Unprotected => tj::PartRef::UnprotectedHeader(0),
        PartRef::Payload => tj::PartRef::Payload,
        PartRef::Signature => tj::PartRef::Signature(0),
        PartRef::Disclosure { index } => tj::PartRef::Disclosure(usize::try_from(index).unwrap_or(usize::MAX)),
        PartRef::KbProtected => tj::PartRef::KbProtectedHeader,
        PartRef::KbPayload => tj::PartRef::KbPayload,
        PartRef::KbSignature => tj::PartRef::KbSignature,
    }
}

fn kid_string(kid: &KidValue) -> String {
    match kid {
        KidValue::Text { value } => value.clone(),
        KidValue::Bytes { value } => std::str::from_utf8(value).map_or_else(|_| b64u(value), str::to_owned),
    }
}

fn flip(bytes: &[u8], offset: usize, bit: u8) -> Result<Vec<u8>, EngineError> {
    let mut out = bytes.to_vec();
    match out.get_mut(offset) {
        Some(b) if bit < 8 => {
            *b ^= 0x80 >> bit;
            Ok(out)
        }
        _ => err(ErrorCode::InvalidInput, "offset or bit out of range"),
    }
}

fn truncate(bytes: &[u8], len: u32) -> Vec<u8> {
    bytes.get(..usize::try_from(len).unwrap_or(usize::MAX)).unwrap_or(bytes).to_vec()
}

#[allow(clippy::too_many_lines)]
fn tamper_jose(kind: &Kind, bytes: &[u8], op: &TamperOp) -> Result<Vec<u8>, EngineError> {
    match op {
        TamperOp::FlipByteBit { offset, bit } => return flip(bytes, usize::try_from(*offset).unwrap_or(usize::MAX), *bit),
        TamperOp::Truncate { len } => return Ok(truncate(bytes, *len)),
        TamperOp::SetTags { .. } => return err(ErrorCode::UnsupportedKind, "JOSE tokens have no CBOR tags"),
        TamperOp::RemoveAlg => return err(ErrorCode::Unsupported, "remove_alg applies to COSE; use set_alg"),
        _ => {}
    }
    let text = utf8(bytes)?;
    let jose_op = match op {
        TamperOp::FlipBit { part, bit } => tj::Tamper::FlipBit {
            part: jose_part(*part),
            bit: usize::try_from(*bit).unwrap_or(usize::MAX),
        },
        TamperOp::SetAlg { alg } => tj::Tamper::SetAlg(match alg {
            AlgValue::Name(n) => n.clone(),
            AlgValue::Label(l) => alg_from_cose(*l)
                .map(|a| alg_to_jose(a).to_owned())
                .ok_or_else(|| EngineError::new(ErrorCode::UnsupportedAlg, format!("no JOSE name for COSE alg {l}")))?,
        }),
        TamperOp::StripSignature => tj::Tamper::StripSignature,
        TamperOp::SetKid { kid } => tj::Tamper::SetKid(kid.as_ref().map(kid_string)),
        TamperOp::DuplicateDisclosure { index } => {
            if !matches!(kind, Kind::SdJwt { .. } | Kind::SdJwtJson { .. }) {
                return err(ErrorCode::UnsupportedKind, "only SD-JWTs have disclosures");
            }
            tj::Tamper::DuplicateDisclosure(usize::try_from(*index).unwrap_or(usize::MAX))
        }
        TamperOp::ReencodeProtected { .. } => tj::Tamper::ReencodeHeader,
        _ => return err(ErrorCode::Unsupported, "unsupported tamper op"),
    };
    if let TamperOp::DuplicateDisclosure { index } = op {
        let count = with_parsed(text, |p, _| p.token.sd_jwt().map_or(0, |sd| sd.disclosures.len())).unwrap_or(0);
        if usize::try_from(*index).unwrap_or(usize::MAX) >= count {
            return err(ErrorCode::DisclosureIndex, format!("no disclosure {index}"));
        }
    }
    let json = text.trim_start().starts_with('{');
    if !json {
        return tj::tamper(text, &jose_op).map(String::into_bytes).map_err(|e| jose_error(&e));
    }
    // JSON serializations: tamper the compact form, then splice the parts
    // that changed back into the envelope.
    let compact = to_json_text(text, crate::dto::actions::JoseSerialization::Compact)?;
    let tampered = tj::tamper(&compact, &jose_op).map_err(|e| jose_error(&e))?;
    let parts = |t: &str| -> Vec<String> {
        let mut pieces: Vec<String> = t.split('~').map(str::to_owned).collect();
        let issuer = pieces.remove(0);
        let mut out: Vec<String> = issuer.splitn(3, '.').map(str::to_owned).collect();
        out.resize(3, String::new());
        out.extend(pieces);
        out
    };
    let (before, after) = (parts(&compact), parts(&tampered));
    with_parsed(text, |p, _| -> Result<String, EngineError> {
        let jws = p.token.jws();
        let sig = jws.signatures.first().ok_or_else(|| EngineError::new(ErrorCode::Parse, "no signature"))?;
        let mut spans: Vec<(tj::Span, usize)> = Vec::new();
        if let Some(prot) = &sig.protected {
            spans.push((prot.span(), 0));
        }
        spans.push((jws.payload.span(), 1));
        spans.push((sig.signature.span(), 2));
        let sd = p.token.sd_jwt();
        if let Some(sd) = sd {
            for (i, d) in sd.disclosures.iter().enumerate() {
                spans.push((d.part().span(), 3 + i));
            }
        }
        let mut edits: Vec<(usize, usize, String)> = Vec::new();
        for (span, i) in &spans {
            if before.get(*i) != after.get(*i) {
                edits.push((span.start, span.end, after.get(*i).cloned().unwrap_or_default()));
            }
        }
        // A duplicated disclosure is a new array element.
        if let (Some(sd), true) = (sd, after.len() > before.len())
            && let Some(last) = sd.disclosures.last()
        {
            let at = last.part().span().end + 1;
            let added: Vec<String> = after.iter().skip(before.len()).map(|d| format!(", {}", crate::util::json_string(d))).collect();
            // `after` ends with the KB part (possibly empty): keep it out.
            let n = added.len().saturating_sub(1);
            let text: String = added.into_iter().take(n.max(1)).collect();
            edits.push((at, at, text));
        }
        edits.sort_by_key(|e| std::cmp::Reverse(e.0));
        let mut out = text.to_owned();
        for (s, e, new) in edits {
            out = splice(&out, s, e, &new);
        }
        Ok(out)
    })
    .map_err(|e| EngineError::new(ErrorCode::Parse, format!("{e:?}")))?
    .map(String::into_bytes)
}

/// The decoded-content start and end of a byte string node.
fn bstr_range(doc: &Document, id: &NodeId) -> Option<(usize, usize)> {
    let n = view::find(&doc.tree, id)?;
    let raw = n.raw?;
    let (start, end) = (usize::try_from(raw.start).ok()?, usize::try_from(raw.end).ok()?);
    let item = decode(doc.bytes.get(start..end)?).ok()?;
    bstr_contents(&item, start)
}

fn tamper_cose(registry: &Registry, kind: &Kind, bytes: &[u8], op: &TamperOp) -> Result<Vec<u8>, EngineError> {
    let doc = || view::document(registry, kind, bytes, Vec::new(), &crate::ViewOptions::default());
    let cose_op = match op {
        TamperOp::FlipByteBit { offset, bit } => CoseTamper::FlipBit {
            offset: usize::try_from(*offset).unwrap_or(usize::MAX),
            bit: *bit,
        },
        TamperOp::FlipBit { part: PartRef::Signature, bit } => CoseTamper::FlipSignatureBit(usize::try_from(*bit).unwrap_or(usize::MAX)),
        TamperOp::FlipBit { part, bit } => {
            let d = doc()?;
            let id = match part {
                PartRef::Protected => NodeId::root().child("protected"),
                PartRef::Payload => NodeId::root().child("payload"),
                PartRef::Unprotected => NodeId::root().child("unprotected"),
                PartRef::Disclosure { index } => d
                    .disclosures
                    .get(usize::try_from(*index).unwrap_or(usize::MAX))
                    .map(|x| x.node_id.clone())
                    .ok_or_else(|| EngineError::new(ErrorCode::DisclosureIndex, format!("no disclosure {index}")))?,
                _ => return err(ErrorCode::UnsupportedKind, "COSE tokens have no KB-JWT"),
            };
            let (start, end) = match part {
                PartRef::Unprotected => {
                    let n = view::find(&d.tree, &id).and_then(|n| n.raw).ok_or_else(|| EngineError::new(ErrorCode::NodeNotFound, "no unprotected header"))?;
                    (usize::try_from(n.start).unwrap_or(0), usize::try_from(n.end).unwrap_or(0))
                }
                _ => bstr_range(&d, &id).ok_or_else(|| EngineError::new(ErrorCode::NodeNotFound, format!("{id} is not a byte string")))?,
            };
            let bit = usize::try_from(*bit).unwrap_or(usize::MAX);
            let offset = start + bit / 8;
            if offset >= end {
                return err(ErrorCode::InvalidInput, "bit out of range");
            }
            CoseTamper::FlipBit {
                offset,
                bit: u8::try_from(bit % 8).unwrap_or(0),
            }
        }
        TamperOp::SetAlg { alg } => CoseTamper::SwapAlg(match alg {
            AlgValue::Label(l) => *l,
            AlgValue::Name(n) => alg_from_jose(n)
                .map(alg_to_cose)
                .ok_or_else(|| EngineError::new(ErrorCode::UnsupportedAlg, format!("no COSE label for {n}")))?,
        }),
        TamperOp::RemoveAlg => CoseTamper::RemoveAlg,
        TamperOp::StripSignature => CoseTamper::StripSignature,
        TamperOp::SetKid { kid: Some(kid) } => CoseTamper::SetKid(Cow::Owned(match kid {
            KidValue::Text { value } => value.as_bytes().to_vec(),
            KidValue::Bytes { value } => value.0.clone(),
        })),
        TamperOp::SetKid { kid: None } => CoseTamper::RemoveKid,
        TamperOp::Truncate { len } => return Ok(truncate(bytes, *len)),
        TamperOp::DuplicateDisclosure { index } => {
            if !matches!(kind, Kind::SdCwt | Kind::SdKbt) {
                return err(ErrorCode::UnsupportedKind, "only SD-CWTs have disclosures");
            }
            let op = cedit::DisclosureOp::Duplicate(usize::try_from(*index).unwrap_or(usize::MAX));
            return cedit::edit_disclosures(&CborBackend, bytes, &[op]).map_err(|e| cose_error(&e));
        }
        TamperOp::ReencodeProtected { how } => CoseTamper::ProtectedEquivalent(match how {
            EquivalentEncoding::Auto | EquivalentEncoding::WideIntegers => CoseEquivalent::WideIntegers,
            EquivalentEncoding::WideBstrHead => CoseEquivalent::WideBstrHead,
            EquivalentEncoding::IndefiniteMap => CoseEquivalent::IndefiniteMap,
        }),
        TamperOp::SetTags { tags } => CoseTamper::SetTags(tags.clone()),
    };
    cedit::tamper(&CborBackend, bytes, &cose_op).map_err(|e| cose_error(&e))
}

pub(crate) fn tamper(registry: &Registry, req: &TamperRequest) -> Result<Document, EngineError> {
    let fam = family(&req.doc.kind)?;
    let out = match fam {
        Family::Jose => tamper_jose(&req.doc.kind, &req.doc.bytes, &req.op)?,
        Family::Cose => tamper_cose(registry, &req.doc.kind, &req.doc.bytes, &req.op)?,
    };
    let mut doc = match view::document(registry, &req.doc.kind, &out, Vec::new(), &req.view) {
        Ok(d) => d,
        Err(e) => view::unreadable(&req.doc.kind, &out, &e),
    };
    doc.signature_stale = true;
    Ok(doc)
}

// ---------------------------------------------------------------- reencode

fn mode(c: CborSerialization) -> EncodeMode {
    match c {
        CborSerialization::Preserve => EncodeMode::Preserve,
        CborSerialization::PreferredPlus => EncodeMode::PreferredPlus,
        CborSerialization::Deterministic => EncodeMode::Deterministic,
    }
}

fn enc(item: &Item<'_>, m: EncodeMode) -> Result<Vec<u8>, EngineError> {
    encode(item, m).map_err(|e| EngineError::new(ErrorCode::InvalidInput, format!("cannot encode: {e:?}")))
}

/// Re-encodes byte string contents that hold CBOR (one item).
fn deepen_bytes(item: &mut Item<'_>, m: EncodeMode, sign1: bool) -> Result<(), EngineError> {
    let Value::Bytes(b) = &item.value else { return Ok(()) };
    let Ok(mut inner) = decode(b).map(Item::into_owned) else { return Ok(()) };
    if sign1 {
        // The protected header of an SD-KBT holds the SD-CWT (kcwt).
        if let Value::Map(entries) = &mut inner.value {
            for (k, v) in entries.iter_mut() {
                if int_of(k) == Some(13) {
                    deepen_sign1(v, m)?;
                }
            }
        }
    }
    let new = enc(&inner, m)?;
    item.value = Value::Bytes(Cow::Owned(new));
    Ok(())
}

/// Re-encodes the protected header, payload, and disclosures of a
/// COSE_Sign1 item (under its tags).
fn deepen_sign1(item: &mut Item<'_>, m: EncodeMode) -> Result<(), EngineError> {
    if let Value::Tag(_, inner) = &mut item.value {
        return deepen_sign1(inner, m);
    }
    let Value::Array(parts) = &mut item.value else { return Ok(()) };
    if let Some(p) = parts.get_mut(0) {
        deepen_bytes(p, m, true)?;
    }
    if let Some(Value::Map(entries)) = parts.get_mut(1).map(|u| &mut u.value) {
        for (k, v) in entries.iter_mut() {
            if int_of(k) == Some(17)
                && let Value::Array(ds) = &mut v.value
            {
                for d in ds {
                    deepen_bytes(d, m, false)?;
                }
            }
        }
    }
    if let Some(p) = parts.get_mut(2) {
        deepen_bytes(p, m, false)?;
    }
    Ok(())
}

fn reencode_cose(bytes: &[u8], tags: Option<&Vec<u64>>, m: EncodeMode, deep: bool) -> Result<Vec<u8>, EngineError> {
    let mut item = decode(bytes)
        .map(Item::into_owned)
        .map_err(|e| EngineError::new(ErrorCode::Parse, format!("not CBOR: {e:?}")))?;
    if let Some(tags) = tags {
        let mut inner = item;
        while let Value::Tag(18 | 61, content) = inner.value {
            inner = *content;
        }
        item = tags.iter().rev().fold(inner, |acc, t| Item::tag(*t, acc));
    }
    if deep {
        deepen_sign1(&mut item, m)?;
    }
    if tags.is_none() && !deep && m == EncodeMode::Preserve {
        return Ok(bytes.to_vec());
    }
    enc(&item, m)
}

pub(crate) fn reencode(registry: &Registry, req: &ReencodeRequest) -> Result<Reencoded, EngineError> {
    if req.layers.iter().any(|l| matches!(l, Layer::CborTag { .. })) {
        return err(ErrorCode::InvalidInput, "use cose_tags for CBOR tags");
    }
    let kind = &req.doc.kind;
    let bytes = &req.doc.bytes;
    let jose = kind.family() == Some(Family::Jose);
    if jose && (req.cbor != CborSerialization::Preserve || req.cose_tags.is_some()) {
        return err(ErrorCode::InvalidInput, "CBOR options do not apply to JOSE");
    }
    if !jose && req.jose.is_some() {
        return err(ErrorCode::InvalidInput, "JOSE serializations do not apply to CBOR");
    }
    let (out, out_kind) = match kind {
        Kind::CoseSign1 | Kind::Cwt | Kind::SdCwt | Kind::SdKbt => (reencode_cose(bytes, req.cose_tags.as_ref(), mode(req.cbor), req.deep)?, kind.clone()),
        Kind::CborClaims | Kind::EdnClaims | Kind::CoseKey | Kind::CoseKeySet => {
            if req.cose_tags.is_some() {
                return err(ErrorCode::InvalidInput, "claim sets have no COSE tags");
            }
            let item = match kind {
                Kind::EdnClaims => edn_value(utf8(bytes)?)?,
                _ => decode(bytes).map(Item::into_owned).map_err(|e| EngineError::new(ErrorCode::Parse, format!("not CBOR: {e:?}")))?,
            };
            let out = enc(&item, mode(req.cbor))?;
            let k = if *kind == Kind::EdnClaims { Kind::CborClaims } else { kind.clone() };
            (out, k)
        }
        _ if jose => match req.jose {
            Some(form) if kind.is_signed() => (to_json_text(utf8(bytes)?, form)?.into_bytes(), kind.clone()),
            Some(_) => return err(ErrorCode::InvalidInput, "a claim set has no JOSE serialization"),
            None => (bytes.to_vec(), kind.clone()),
        },
        _ => return err(ErrorCode::UnsupportedKind, format!("cannot re-encode a {}", kind.label())),
    };
    let probe = if jose && kind.is_signed() { Kind::SdJwt { kb: false } } else { out_kind };
    let probe = match (&probe, kind) {
        (Kind::SdJwt { .. }, Kind::Jwt | Kind::JwsCompact) if req.jose.is_none_or(|j| j == crate::dto::actions::JoseSerialization::Compact) => kind.clone(),
        _ => probe,
    };
    let mut document = view::document(registry, &probe, &out, req.layers.clone(), &req.view)?;
    document.signature_stale = signed_changed(kind, bytes, &out);
    let td_layers: Vec<tokenator_detect::Layer> = req.layers.iter().map(layer_td).collect();
    let output = tokenator_detect::rewrap(&out, &td_layers);
    Ok(Reencoded {
        output: crate::Bytes(output),
        document,
    })
}

// ---------------------------------------------------------------- edit disclosures

fn index(i: u32) -> usize {
    usize::try_from(i).unwrap_or(usize::MAX)
}

fn check(i: u32, len: usize) -> Result<usize, EngineError> {
    let i = index(i);
    if i < len { Ok(i) } else { err(ErrorCode::DisclosureIndex, format!("no disclosure {i} ({len} present)")) }
}

/// A JOSE claim name given as plain text or as a JSON string literal.
fn claim_name(text: &str) -> String {
    match tokenator_json::parse(text.as_bytes()).ok().map(|n| n.value().clone()) {
        Some(JValue::String(s)) => s.into_owned(),
        _ => text.to_owned(),
    }
}

#[allow(clippy::too_many_lines)]
fn edit_jose(req: &EditDisclosuresRequest, seed: Option<&[u8; 32]>) -> Result<Vec<u8>, EngineError> {
    let text = utf8(&req.doc.bytes)?;
    with_parsed(text, |p, _| -> Result<String, EngineError> {
        let sd = p.token.sd_jwt().ok_or_else(|| EngineError::new(ErrorCode::UnsupportedKind, "not an SD-JWT"))?;
        let mut len = sd.disclosures.len();
        let mut ops = Vec::with_capacity(req.ops.len());
        for op in &req.ops {
            ops.push(match op {
                DisclosureOp::Remove { index } => {
                    let i = check(*index, len)?;
                    len -= 1;
                    tj::DisclosureOp::Remove(i)
                }
                DisclosureOp::Duplicate { index } => {
                    let i = check(*index, len)?;
                    let mut order: Vec<usize> = (0..len).collect();
                    order.push(i);
                    len += 1;
                    tj::DisclosureOp::Reorder(order)
                }
                DisclosureOp::Move { from, to } => {
                    let (f, t) = (check(*from, len)?, check(*to, len)?);
                    let mut order: Vec<usize> = (0..len).collect();
                    let moved = order.remove(f);
                    order.insert(t, moved);
                    tj::DisclosureOp::Reorder(order)
                }
                DisclosureOp::Select { indices } => {
                    let order = indices.iter().map(|i| check(*i, len)).collect::<Result<Vec<_>, _>>()?;
                    len = order.len();
                    tj::DisclosureOp::Reorder(order)
                }
                DisclosureOp::Append { encoded } => {
                    len += 1;
                    tj::DisclosureOp::Append(encoded.clone())
                }
                DisclosureOp::Forge { salt, claim, value } => {
                    if salt.is_none() && seed.is_none() {
                        return err(ErrorCode::Randomness, "a random salt needs randomness");
                    }
                    len += 1;
                    tj::DisclosureOp::Forge {
                        salt: salt.clone(),
                        name: claim.as_deref().map(claim_name),
                        value: json_value(value.as_deref().unwrap_or("null"))?,
                    }
                }
                DisclosureOp::ReplaceValue { index, value } => tj::DisclosureOp::ReplaceValue {
                    index: check(*index, len)?,
                    value: json_value(value)?,
                },
                DisclosureOp::AddDecoy { at, digest } => {
                    if digest.is_none() && seed.is_none() {
                        return err(ErrorCode::Randomness, "a random digest needs randomness");
                    }
                    let base = NodeId::root().child("payload").decoded(0);
                    let pointer = if at == &base {
                        String::new()
                    } else if base.is_ancestor_of(at) {
                        format!("/{}", at.as_str().get(base.as_str().len() + 1..).unwrap_or(""))
                    } else {
                        return Err(EngineError {
                            code: ErrorCode::NodeNotFound,
                            message: format!("{at} is not in the payload"),
                            node_id: Some(at.clone()),
                        });
                    };
                    tj::DisclosureOp::AddDigest {
                        at: pointer,
                        digest: digest.clone(),
                    }
                }
                DisclosureOp::RemoveDigest { digest } => tj::DisclosureOp::RemoveDigest(digest.clone()),
            });
        }
        let out = match seed {
            Some(s) => tj::edit_disclosures(sd, &ops, tj::JsonStyle::Compact, &mut rng(s, "edit")),
            None => tj::edit_disclosures(sd, &ops, tj::JsonStyle::Compact, &mut unused_rng()),
        };
        out.map_err(|e| jose_error(&e))
    })
    .map_err(|e| EngineError::new(ErrorCode::Parse, format!("{e:?}")))?
    .map(String::into_bytes)
}

/// The current `sd_claims` contents of an SD-CWT (or of the SD-CWT in an
/// SD-KBT).
fn cose_disclosures(registry: &Registry, kind: &Kind, bytes: &[u8]) -> Result<Vec<Vec<u8>>, EngineError> {
    let doc = view::document(registry, kind, bytes, Vec::new(), &crate::ViewOptions::default())?;
    Ok(doc
        .disclosures
        .iter()
        .filter_map(|d| bstr_range(&doc, &d.node_id))
        .filter_map(|(s, e)| bytes.get(s..e).map(<[u8]>::to_vec))
        .collect())
}

#[allow(clippy::too_many_lines)]
fn edit_cose(registry: &Registry, req: &EditDisclosuresRequest, seed: Option<&[u8; 32]>) -> Result<Vec<u8>, EngineError> {
    let mut list = cose_disclosures(registry, &req.doc.kind, &req.doc.bytes)?;
    let mut salt_rng = seed.map(|s| rng(s, "edit"));
    let mut ops: Vec<cedit::DisclosureOp<'static>> = Vec::with_capacity(req.ops.len());
    for op in &req.ops {
        let (cop, new_list) = match op {
            DisclosureOp::Remove { index } => {
                let i = check(*index, list.len())?;
                let mut l = list.clone();
                l.remove(i);
                (cedit::DisclosureOp::Remove(i), l)
            }
            DisclosureOp::Duplicate { index } => {
                let i = check(*index, list.len())?;
                let mut l = list.clone();
                l.push(l.get(i).cloned().unwrap_or_default());
                (cedit::DisclosureOp::Duplicate(i), l)
            }
            DisclosureOp::Move { from, to } => {
                let (f, t) = (check(*from, list.len())?, check(*to, list.len())?);
                let mut l = list.clone();
                let d = l.remove(f);
                l.insert(t, d);
                (cedit::DisclosureOp::Move { from: f, to: t }, l)
            }
            DisclosureOp::Select { indices } => {
                let idx = indices.iter().map(|i| check(*i, list.len())).collect::<Result<Vec<_>, _>>()?;
                let l = idx.iter().filter_map(|&i| list.get(i).cloned()).collect();
                (cedit::DisclosureOp::Select(idx), l)
            }
            DisclosureOp::Append { encoded } => {
                let b = unhex(encoded).ok_or_else(|| EngineError::new(ErrorCode::InvalidInput, "the disclosure is not hex"))?;
                let mut l = list.clone();
                l.push(b.clone());
                (cedit::DisclosureOp::Append(Cow::Owned(b)), l)
            }
            DisclosureOp::Forge { salt, claim, value } => {
                let salt = match (salt, salt_rng.as_mut()) {
                    (Some(s), _) => unhex(s).ok_or_else(|| EngineError::new(ErrorCode::InvalidInput, "the salt is not hex"))?,
                    (None, Some(r)) => {
                        let mut s = vec![0u8; 16];
                        tokenator_crypto::rand_core::Rng::fill_bytes(r, &mut s);
                        s
                    }
                    (None, None) => return err(ErrorCode::Randomness, "a random salt needs randomness"),
                };
                let value = value.as_deref().map(edn_value).transpose()?;
                let key = claim.as_deref().map(edn_value).transpose()?;
                let bytes = encode_disclosure(&salt, value.as_ref(), key.as_ref()).map_err(|e| cose_error(&e))?;
                let mut l = list.clone();
                l.push(bytes.clone());
                (cedit::DisclosureOp::Append(Cow::Owned(bytes)), l)
            }
            DisclosureOp::ReplaceValue { index, value } => {
                let i = check(*index, list.len())?;
                let current = list.get(i).cloned().unwrap_or_default();
                let item = decode(&current).map_err(|_| EngineError::new(ErrorCode::InvalidInput, "the disclosure is not CBOR"))?;
                let new_value = edn_value(value)?;
                let Value::Array(parts) = &item.value else {
                    return err(ErrorCode::InvalidInput, "the disclosure is not an array");
                };
                let salt = match parts.first().map(|s| &s.value) {
                    Some(Value::Bytes(b)) => b.to_vec(),
                    _ => return err(ErrorCode::InvalidInput, "the disclosure has no salt"),
                };
                let bytes = encode_disclosure(&salt, Some(&new_value), parts.get(2)).map_err(|e| cose_error(&e))?;
                let mut l = list.clone();
                if let Some(slot) = l.get_mut(i) {
                    slot.clone_from(&bytes);
                }
                (cedit::DisclosureOp::Replace { index: i, bytes: Cow::Owned(bytes) }, l)
            }
            DisclosureOp::AddDecoy { .. } | DisclosureOp::RemoveDigest { .. } => {
                return err(ErrorCode::Unsupported, "COSE payload digest edits are not supported yet (#32)");
            }
        };
        ops.push(cop);
        list = new_list;
    }
    cedit::edit_disclosures(&CborBackend, &req.doc.bytes, &ops).map_err(|e| cose_error(&e))
}

pub(crate) fn edit_disclosures(registry: &Registry, req: &EditDisclosuresRequest) -> Result<Document, EngineError> {
    let seed = seed32(req.randomness.as_ref())?;
    let (out, fam) = match req.doc.kind {
        Kind::SdJwt { .. } | Kind::SdJwtJson { .. } => (edit_jose(req, seed.as_ref())?, Family::Jose),
        Kind::SdCwt | Kind::SdKbt => (edit_cose(registry, req, seed.as_ref())?, Family::Cose),
        _ => return err(ErrorCode::UnsupportedKind, format!("a {} has no disclosures", req.doc.kind.label())),
    };
    let mut doc = result_doc(registry, fam, &out, &req.view)?;
    doc.signature_stale = signed_changed(&req.doc.kind, &req.doc.bytes, &out);
    Ok(doc)
}

// ---------------------------------------------------------------- manual decode

pub(crate) fn decode_embedded(registry: &Registry, req: &DecodeEmbeddedRequest) -> Result<ManualDecode, EngineError> {
    let doc = view::document(registry, &req.doc.kind, &req.doc.bytes, Vec::new(), &crate::ViewOptions::default())?;
    let Some(node) = view::find(&doc.tree, &req.node_id) else {
        return Err(EngineError {
            code: ErrorCode::NodeNotFound,
            message: format!("no node {}", req.node_id),
            node_id: Some(req.node_id.clone()),
        });
    };
    let crate::dto::document::RawView::Hex { bytes: buffer, .. } = &doc.raw else {
        return err(ErrorCode::NotBytes, "JSON has no byte strings");
    };
    if node.kind != NodeKind::Bytes && node.kind != NodeKind::Part {
        return err(ErrorCode::NotBytes, format!("{} is not a byte string", req.node_id));
    }
    let Some(raw) = node.raw else {
        return err(ErrorCode::NotBytes, "no bytes");
    };
    let (start, end) = (usize::try_from(raw.start).unwrap_or(0), usize::try_from(raw.end).unwrap_or(0));
    let item = buffer
        .get(start..end)
        .and_then(|b| decode(b).ok())
        .ok_or_else(|| EngineError::new(ErrorCode::NotBytes, "not a byte string"))?;
    let Some((cs, ce)) = bstr_contents(&item, start) else {
        return err(ErrorCode::NotBytes, format!("{} is not a definite byte string", req.node_id));
    };
    let view_res = tokenator_edn::decode_embedded(buffer, cs..ce)
        .map_err(|e| EngineError::new(ErrorCode::Decode, format!("not CBOR: {:?} at byte {}", e.kind, e.offset)))?;
    let mut diagnostics = Vec::new();
    for w in &view_res.warnings {
        let tokenator_edn::EmbeddedWarning::TrailingBytes { offset, len } = w else { continue };
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            code: "cbor.trailing_bytes".to_owned(),
            message: format!("{len} byte(s) after the first item"),
            node_id: Some(req.node_id.clone()),
            main: None,
            raw: Some(ByteRange {
                start: u32_of(*offset),
                end: u32_of(offset + len),
            }),
        });
    }
    let notes = crate::annotate::Notes::new(registry, req.view.annotations);
    let built = view::cbor::build(&view_res.item, buffer, &Role::Plain, notes, &req.view, &MainText::Print);
    let mut tree = built.tree;
    rebase(&mut tree, &req.node_id.decoded(0));
    Ok(ManualDecode {
        text: built.text,
        tree,
        diagnostics,
    })
}

/// Moves a tree rooted at `""` under `base`.
fn rebase(tree: &mut crate::dto::document::Node, base: &NodeId) {
    let mut stack = vec![tree];
    while let Some(n) = stack.pop() {
        n.id = if n.id.is_root() { base.clone() } else { base.push_raw(n.id.as_str()) };
        if let Some(k) = n.key.as_deref_mut() {
            k.id = if k.id.is_root() { base.clone() } else { base.push_raw(k.id.as_str()) };
        }
        stack.extend(n.children.iter_mut());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_names_accept_both_forms() {
        assert_eq!(claim_name("given_name"), "given_name");
        assert_eq!(claim_name("\"x\""), "x");
    }

    #[test]
    fn deep_reencode_of_a_non_sign1_is_a_no_op() {
        let mut item = Item::int(1);
        deepen_sign1(&mut item, EncodeMode::PreferredPlus).unwrap();
        assert_eq!(item, Item::int(1));
    }
}
