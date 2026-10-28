//! Re-signing, tampering, and disclosure editing (SPEC §5).

use std::borrow::Cow;

use tokenator_cbor::{Item, Span, Value, Width, decode};
use tokenator_crypto::{Alg, DeclaredAlg, rand_core::CryptoRng};
use tokenator_keys::Key;

use crate::codepoints::{HDR_ALG, HDR_KCWT, HDR_KID, HDR_SD_CLAIMS};
use crate::sd::encode_disclosure;
use crate::util::{
    bstr, declared_alg, enc, head, int_of, map_get, slice, splice, width_of_head, with_value,
};
use crate::{Bucket, CoseError, Part, Payload, Sign1, Sign1Backend, Sign1Parts, SignOptions};

/// A replacement for one part of a COSE_Sign1.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Edit<'e> {
    /// Keep the original bytes.
    #[default]
    Keep,
    /// Use these bytes verbatim (bstr contents).
    Bytes(Cow<'e, [u8]>),
    /// Encode this item with `EncodeMode::Preserve`, so unedited regions of
    /// a decoded-then-edited item keep their bytes.
    Item(Item<'e>),
}

/// Options for [`resign`].
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ResignOptions<'e> {
    /// New protected header contents.
    pub protected: Edit<'e>,
    /// New unprotected header (`None` keeps it).
    pub unprotected: Option<Item<'e>>,
    /// New payload contents.
    pub payload: Edit<'e>,
    /// Sign with this algorithm instead of the (edited) header `alg`.
    pub alg: Option<Alg>,
    /// RFC 9052 external AAD.
    pub external_aad: Cow<'e, [u8]>,
    /// The payload of a detached message.
    pub detached_payload: Option<Cow<'e, [u8]>>,
}

/// Signs a token again, over its original or edited parts.
///
/// Only edited parts and the signature change: tags, untouched parts, and
/// their byte string heads are copied from the input byte for byte.
pub fn resign(
    backend: &dyn Sign1Backend,
    bytes: &[u8],
    key: &Key,
    opts: &ResignOptions<'_>,
    rng: Option<&mut dyn CryptoRng>,
) -> Result<Vec<u8>, CoseError> {
    let msg = backend.parse(bytes)?;
    let parts = Sign1Parts::from_sign1(&msg)?;
    let protected: Cow<'_, [u8]> = match &opts.protected {
        Edit::Keep => parts.protected.clone(),
        Edit::Bytes(b) => Cow::Borrowed(b),
        Edit::Item(item) => Cow::Owned(enc(item)),
    };
    let unprotected = opts.unprotected.as_ref().unwrap_or(&parts.unprotected);
    let payload: Option<Cow<'_, [u8]>> = match &opts.payload {
        Edit::Keep => parts.payload.clone(),
        Edit::Bytes(b) => Some(Cow::Borrowed(b)),
        Edit::Item(item) => Some(Cow::Owned(enc(item))),
    };
    let alg = match opts.alg {
        Some(alg) => alg,
        None => header_alg(&protected, unprotected)?,
    };
    let signed = backend.sign(
        &Sign1Parts {
            tags: parts.tags.clone(),
            protected: Cow::Borrowed(&protected),
            unprotected: unprotected.clone(),
            payload: payload.as_deref().map(Cow::Borrowed),
            signature: Cow::Borrowed(&[]),
        },
        key,
        &SignOptions {
            alg,
            external_aad: &opts.external_aad,
            detached_payload: opts.detached_payload.as_deref(),
        },
        rng,
    )?;
    let signature = backend
        .parse(&signed)?
        .signature
        .ok_or(CoseError::MalformedPart(Part::Signature))?
        .raw
        .into_owned();

    // Splice the new parts into the input so that everything else, byte
    // string heads included, keeps its bytes.
    let mut edits = Vec::new();
    if let (false, Some(p)) = (matches!(opts.protected, Edit::Keep), &msg.protected) {
        edits.push((p.span, bstr(&protected, width_of_head(p.span.head_len))));
    }
    if let (Some(new), Some(old)) = (&opts.unprotected, &msg.unprotected) {
        edits.push((old.span, enc(new)));
    }
    if let (false, Some(new)) = (matches!(opts.payload, Edit::Keep), &payload) {
        match &msg.payload {
            Payload::Attached(b) => {
                edits.push((b.span, bstr(new, width_of_head(b.span.head_len))));
            }
            Payload::Detached { span } => edits.push((*span, bstr(new, Width::Immediate))),
            Payload::Malformed => {}
        }
    }
    if let Some(sig) = &msg.signature {
        edits.push((sig.span, bstr(&signature, width_of_head(sig.span.head_len))));
    }
    Ok(splice(bytes, edits))
}

/// The `alg` in (edited) protected header contents, else in the
/// unprotected header.
fn header_alg(protected: &[u8], unprotected: &Item<'_>) -> Result<Alg, CoseError> {
    let prot = if protected.is_empty() {
        None
    } else {
        decode(protected).ok()
    };
    let value = prot
        .as_ref()
        .and_then(|m| map_get(m, HDR_ALG))
        .or_else(|| map_get(unprotected, HDR_ALG));
    match value.and_then(declared_alg) {
        None => Err(CoseError::MissingAlg),
        Some(DeclaredAlg::Known(alg)) => Ok(alg),
        Some(other) => Err(CoseError::UnsupportedAlg(other)),
    }
}

/// Ways to re-encode a protected header so that it means the same thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EquivalentEncoding {
    /// Widen the protected *bstr head* by one step (e.g. `0x43` to
    /// `0x58 0x03`). The contents, and so the signature input, are
    /// unchanged.
    WideBstrHead,
    /// Widen every integer argument *inside* the header map by one step
    /// (e.g. `0x26` to `0x38 0x06`). The contents change.
    WideIntegers,
    /// Re-encode the header map with indefinite length (`0xbf ... 0xff`).
    IndefiniteMap,
}

/// A deliberate break. Nothing is re-signed.
#[derive(Debug, Clone, PartialEq)]
pub enum TamperOp<'a> {
    /// Set the protected `alg` to this label (other entries keep their bytes).
    SwapAlg(i64),
    /// Remove `alg` from the protected header.
    RemoveAlg,
    /// Replace the signature with an empty byte string.
    StripSignature,
    /// Flip bit `bit` (0 = MSB of the first byte) of the signature.
    FlipSignatureBit(usize),
    /// Flip bit `bit` (0..8, 0 = MSB) of byte `offset` of the whole token.
    FlipBit {
        /// Byte offset.
        offset: usize,
        /// Bit within the byte.
        bit: u8,
    },
    /// Set `kid` in the unprotected header (removing a protected kid is
    /// not done; use [`TamperOp::RemoveKid`]).
    SetKid(Cow<'a, [u8]>),
    /// Remove `kid` from both buckets (the protected header is re-encoded
    /// without it).
    RemoveKid,
    /// Keep only the first `n` bytes.
    Truncate(usize),
    /// Replace the tags (e.g. `[]`, `[61, 18]`, `[18, 18]`).
    SetTags(Vec<u64>),
    /// Re-encode the protected header equivalently.
    ProtectedEquivalent(EquivalentEncoding),
}

/// Applies a tamper operation and returns the broken token.
pub fn tamper(
    backend: &dyn Sign1Backend,
    bytes: &[u8],
    op: &TamperOp<'_>,
) -> Result<Vec<u8>, CoseError> {
    // Byte-level operations need no parse.
    match op {
        TamperOp::FlipBit { offset, bit } => {
            let mut out = bytes.to_vec();
            let byte = out
                .get_mut(*offset)
                .ok_or(CoseError::NotApplicable("offset past the end"))?;
            *byte ^= 0x80u8
                .checked_shr(u32::from(*bit))
                .filter(|_| *bit < 8)
                .ok_or(CoseError::NotApplicable("bit must be 0..8"))?;
            return Ok(out);
        }
        TamperOp::Truncate(n) => {
            return bytes
                .get(..*n)
                .map(<[u8]>::to_vec)
                .ok_or(CoseError::NotApplicable("truncation past the end"));
        }
        _ => {}
    }

    let msg = backend.parse(bytes)?;
    let edit = match op {
        TamperOp::FlipBit { .. } | TamperOp::Truncate(_) => {
            return Err(CoseError::NotApplicable("handled above"));
        }
        TamperOp::SwapAlg(label) => protected_edit(&msg, |entries| {
            match entries.iter_mut().find(|(k, _)| int_of(k) == Some(HDR_ALG)) {
                Some(entry) => entry.1 = Item::int(*label),
                None => entries.insert(0, (Item::int(HDR_ALG), Item::int(*label))),
            }
        })?,
        TamperOp::RemoveAlg => protected_edit(&msg, |entries| {
            entries.retain(|(k, _)| int_of(k) != Some(HDR_ALG));
        })?,
        TamperOp::StripSignature => (signature(&msg)?.span, vec![0x40]),
        TamperOp::FlipSignatureBit(bit) => {
            let sig = signature(&msg)?;
            let byte = bit / 8;
            if byte >= sig.raw.len() || matches!(sig.raw, Cow::Owned(_)) {
                return Err(CoseError::NotApplicable(
                    "bit past the end of the signature",
                ));
            }
            let mut out = bytes.to_vec();
            if let Some(b) = out.get_mut(sig.span.start + sig.span.head_len + byte) {
                *b ^= 0x80 >> (bit % 8);
            }
            return Ok(out);
        }
        TamperOp::SetKid(kid) => unprotected_edit(&msg, |entries| {
            let value = Item::bytes(kid.to_vec());
            match entries.iter_mut().find(|(k, _)| int_of(k) == Some(HDR_KID)) {
                Some(entry) => entry.1 = value,
                None => entries.push((Item::int(HDR_KID), value)),
            }
        })?,
        TamperOp::RemoveKid => {
            let no_kid = |entries: &mut Vec<(Item<'_>, Item<'_>)>| {
                entries.retain(|(k, _)| int_of(k) != Some(HDR_KID));
            };
            let mut edits = vec![unprotected_edit(&msg, no_kid)?];
            if let Ok(e) = protected_edit(&msg, no_kid) {
                edits.push(e);
            }
            return Ok(splice(bytes, edits));
        }
        TamperOp::SetTags(tags) => {
            let mut out: Vec<u8> = tags.iter().flat_map(|t| head(6, *t)).collect();
            out.extend(slice(bytes, msg.span).unwrap_or_default());
            return Ok(out);
        }
        TamperOp::ProtectedEquivalent(e) => {
            let p = msg
                .protected
                .as_ref()
                .ok_or(CoseError::MalformedPart(Part::Protected))?;
            let width = width_of_head(p.span.head_len);
            match e {
                EquivalentEncoding::WideBstrHead => {
                    let wide = wider(width)
                        .ok_or(CoseError::NotApplicable("the head is already 9 bytes"))?;
                    (p.span, bstr(&p.raw, wide))
                }
                EquivalentEncoding::WideIntegers | EquivalentEncoding::IndefiniteMap => {
                    let mut map = match &p.decoded {
                        Some(Ok(m)) if matches!(m.value, Value::Map(_)) => m.clone(),
                        _ => {
                            return Err(CoseError::NotApplicable(
                                "the protected header is not a non-empty map",
                            ));
                        }
                    };
                    if *e == EquivalentEncoding::WideIntegers {
                        widen_ints(&mut map);
                    } else {
                        map.width = Width::Indefinite;
                    }
                    (p.span, bstr(&enc(&map), width))
                }
            }
        }
    };
    Ok(splice(bytes, vec![edit]))
}

fn signature<'m, 'a>(msg: &'m Sign1<'a>) -> Result<&'m crate::RawBytes<'a>, CoseError> {
    msg.signature
        .as_ref()
        .ok_or(CoseError::MalformedPart(Part::Signature))
}

/// The protected bstr re-encoded after `f` edits its map entries (other
/// entries keep their encoding, the bstr head keeps its width if it fits).
fn protected_edit(
    msg: &Sign1<'_>,
    f: impl FnOnce(&mut Vec<(Item<'_>, Item<'_>)>),
) -> Result<(Span, Vec<u8>), CoseError> {
    let p = msg
        .protected
        .as_ref()
        .ok_or(CoseError::MalformedPart(Part::Protected))?;
    let mut map = match &p.decoded {
        None => Item::map(Vec::new()),
        Some(Ok(m)) if matches!(m.value, Value::Map(_)) => m.clone(),
        Some(_) => {
            return Err(CoseError::NotApplicable(
                "the protected header is not a map",
            ));
        }
    };
    if let Value::Map(entries) = &mut map.value {
        f(entries);
    }
    Ok((p.span, bstr(&enc(&map), width_of_head(p.span.head_len))))
}

/// The unprotected map re-encoded after `f` edits its entries.
fn unprotected_edit(
    msg: &Sign1<'_>,
    f: impl FnOnce(&mut Vec<(Item<'_>, Item<'_>)>),
) -> Result<(Span, Vec<u8>), CoseError> {
    let mut map = msg
        .unprotected
        .clone()
        .ok_or(CoseError::MalformedPart(Part::Unprotected))?;
    let span = map.span;
    if let Value::Map(entries) = &mut map.value {
        f(entries);
    }
    Ok((span, enc(&map)))
}

/// The next wider argument width.
fn wider(w: Width) -> Option<Width> {
    match w {
        Width::Immediate => Some(Width::U8),
        Width::U8 => Some(Width::U16),
        Width::U16 => Some(Width::U32),
        Width::U32 => Some(Width::U64),
        Width::U64 | Width::Indefinite => None,
    }
}

/// Widens every integer argument by one step.
fn widen_ints(item: &mut Item<'_>) {
    match &mut item.value {
        Value::Uint(_) | Value::Nint(_) => {
            if let Some(w) = wider(item.width) {
                item.width = w;
            }
        }
        Value::Array(a) => a.iter_mut().for_each(widen_ints),
        Value::Map(m) => {
            for (k, v) in m {
                widen_ints(k);
                widen_ints(v);
            }
        }
        Value::Tag(_, inner) => widen_ints(inner),
        _ => {}
    }
}

/// An edit of `sd_claims`.
#[derive(Debug, Clone, PartialEq)]
pub enum DisclosureOp<'a> {
    /// Keep these indices, in this order.
    Select(Vec<usize>),
    /// Remove one disclosure.
    Remove(usize),
    /// Append a copy of a disclosure.
    Duplicate(usize),
    /// Move disclosure `from` to position `to`.
    Move {
        /// Current index.
        from: usize,
        /// New index.
        to: usize,
    },
    /// Append raw bstr contents.
    Append(Cow<'a, [u8]>),
    /// Replace one disclosure's bstr contents.
    Replace {
        /// Index.
        index: usize,
        /// New contents.
        bytes: Cow<'a, [u8]>,
    },
    /// Append a forged disclosure built with
    /// [`encode_disclosure`](crate::sd::encode_disclosure); with no value
    /// it is a decoy disclosure `[salt]`.
    Forge {
        /// Salt.
        salt: Cow<'a, [u8]>,
        /// Value.
        value: Option<Item<'a>>,
        /// Claim key.
        key: Option<Item<'a>>,
    },
}

/// Applies disclosure edits in order to an SD-CWT, or to the SD-CWT inside
/// an SD-KBT (which is not re-signed). If no disclosures remain,
/// `sd_claims` is removed. Everything outside `sd_claims` keeps its bytes.
pub fn edit_disclosures(
    backend: &dyn Sign1Backend,
    bytes: &[u8],
    ops: &[DisclosureOp<'_>],
) -> Result<Vec<u8>, CoseError> {
    rewrite_sd_claims(backend, bytes, &mut |list| {
        ops.iter().try_for_each(|op| apply(list, op))
    })
}

/// Applies one disclosure edit to the `sd_claims` elements.
fn apply(list: &mut Vec<Item<'_>>, op: &DisclosureOp<'_>) -> Result<(), CoseError> {
    let check = |i: usize, len: usize| {
        if i < len {
            Ok(())
        } else {
            Err(CoseError::DisclosureIndex(i))
        }
    };
    match op {
        DisclosureOp::Select(indices) => {
            let mut out = Vec::with_capacity(indices.len());
            for &i in indices {
                out.push(list.get(i).cloned().ok_or(CoseError::DisclosureIndex(i))?);
            }
            *list = out;
        }
        DisclosureOp::Remove(i) => {
            check(*i, list.len())?;
            list.remove(*i);
        }
        DisclosureOp::Duplicate(i) => {
            let d = list
                .get(*i)
                .cloned()
                .ok_or(CoseError::DisclosureIndex(*i))?;
            list.push(d);
        }
        DisclosureOp::Move { from, to } => {
            check(*from, list.len())?;
            check(*to, list.len())?;
            let d = list.remove(*from);
            list.insert(*to, d);
        }
        DisclosureOp::Append(b) => list.push(Item::bytes(b.to_vec())),
        DisclosureOp::Replace { index, bytes } => {
            let slot = list
                .get_mut(*index)
                .ok_or(CoseError::DisclosureIndex(*index))?;
            *slot = Item::bytes(bytes.to_vec());
        }
        DisclosureOp::Forge { salt, value, key } => list.push(Item::bytes(encode_disclosure(
            salt,
            value.as_ref(),
            key.as_ref(),
        ))),
    }
    Ok(())
}

/// A function that edits the elements of `sd_claims`.
pub(crate) type SdClaimsEdit<'f> =
    dyn for<'x> FnMut(&mut Vec<Item<'x>>) -> Result<(), CoseError> + 'f;

/// Rewrites `sd_claims` of an SD-CWT, or of the SD-CWT in an SD-KBT's
/// `kcwt` (without re-signing the KBT). Every other byte is copied; an
/// empty `sd_claims` is removed.
pub(crate) fn rewrite_sd_claims(
    backend: &dyn Sign1Backend,
    bytes: &[u8],
    f: &mut SdClaimsEdit<'_>,
) -> Result<Vec<u8>, CoseError> {
    let msg = backend.parse(bytes)?;
    match msg.header(HDR_KCWT) {
        Some((Bucket::Protected, kcwt)) => {
            let p = msg
                .protected
                .as_ref()
                .ok_or(CoseError::MalformedPart(Part::Protected))?;
            let Cow::Borrowed(raw) = &p.raw else {
                return Err(CoseError::NotApplicable(
                    "kcwt in an indefinite-length protected header",
                ));
            };
            let inner = slice(raw, kcwt.span).ok_or(CoseError::NotApplicable("kcwt span"))?;
            let new_inner = rewrite_parsed(&backend.parse(inner)?, inner, f)?;
            let contents = splice(raw, vec![(kcwt.span, new_inner)]);
            Ok(splice(
                bytes,
                vec![(p.span, bstr(&contents, width_of_head(p.span.head_len)))],
            ))
        }
        Some((Bucket::Unprotected, kcwt)) => {
            let inner = slice(bytes, kcwt.span).ok_or(CoseError::NotApplicable("kcwt span"))?;
            let new_inner = rewrite_parsed(&backend.parse(inner)?, inner, f)?;
            Ok(splice(bytes, vec![(kcwt.span, new_inner)]))
        }
        None => rewrite_parsed(&msg, bytes, f),
    }
}

fn rewrite_parsed(
    msg: &Sign1<'_>,
    bytes: &[u8],
    f: &mut SdClaimsEdit<'_>,
) -> Result<Vec<u8>, CoseError> {
    let u = msg
        .unprotected
        .as_ref()
        .ok_or(CoseError::MalformedPart(Part::Unprotected))?;
    let Value::Map(entries) = &u.value else {
        return Err(CoseError::MalformedPart(Part::Unprotected));
    };
    let at = entries
        .iter()
        .position(|(k, _)| int_of(k) == Some(HDR_SD_CLAIMS));
    let old = at.and_then(|i| entries.get(i)).map(|(_, v)| v);
    let mut list = match old.map(|v| &v.value) {
        Some(Value::Array(a)) => a.clone(),
        _ => Vec::new(),
    };
    f(&mut list)?;

    let mut entries = entries.clone();
    match (at, old) {
        (Some(i), _) if list.is_empty() => {
            entries.remove(i);
        }
        (Some(i), Some(old)) => {
            let array = match old.value {
                Value::Array(_) => with_value(old, Value::Array(list)),
                _ => Item::array(list),
            };
            if let Some(entry) = entries.get_mut(i) {
                entry.1 = array;
            }
        }
        _ if !list.is_empty() => {
            entries.push((Item::int(HDR_SD_CLAIMS), Item::array(list)));
        }
        _ => {}
    }
    Ok(splice(
        bytes,
        vec![(u.span, enc(&with_value(u, Value::Map(entries))))],
    ))
}
