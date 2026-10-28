//! Re-signing, tampering, and disclosure editing (SPEC §5).
#![allow(clippy::unimplemented)]

use std::borrow::Cow;

use tokenator_cbor::Item;
use tokenator_crypto::{Alg, rand_core::CryptoRng};
use tokenator_keys::Key;

use crate::{CoseError, Sign1Backend};

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
    let _ = (backend, bytes, key, opts, rng);
    unimplemented!()
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
    let _ = (backend, bytes, op);
    unimplemented!()
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
    let _ = (backend, bytes, ops);
    unimplemented!()
}
