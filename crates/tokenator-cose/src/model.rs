//! The parsed COSE_Sign1 model.
#![allow(clippy::unimplemented)]

use std::borrow::Cow;

use tokenator_cbor::{DecodeError, Item, Span};
use tokenator_crypto::DeclaredAlg;
use tokenator_keys::Label;

/// Which part of a token something refers to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Part {
    /// The tags and the outer array.
    Envelope,
    /// The protected header (bstr and its contents).
    Protected,
    /// The unprotected header map.
    Unprotected,
    /// The payload (bstr and its contents, or `nil`).
    Payload,
    /// The signature bstr.
    Signature,
    /// The SD-CWT disclosure with this index in `sd_claims`.
    Disclosure(usize),
    /// A part of the SD-CWT inside an SD-KBT's `kcwt` header parameter.
    Kcwt(Box<Part>),
}

/// The two header buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bucket {
    /// The protected header.
    Protected,
    /// The unprotected header.
    Unprotected,
}

/// A `typ` or `content type` value (RFC 9596, RFC 9052 §3.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ContentType {
    /// A CoAP content-format number, e.g. 293.
    Uint(u64),
    /// A media type string, e.g. `application/sd-cwt`.
    Text(String),
}

/// What a COSE_Sign1 carries, judged from its headers and payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenKind {
    /// A COSE_Sign1 whose payload is not a CBOR map (or is detached).
    Sign1,
    /// A CWT: the payload is a claims map and there are no SD markers.
    Cwt,
    /// An SD-CWT: `sd_claims` in the unprotected header, `sd_alg` in the
    /// protected header, `typ` 293 / `application/sd-cwt`, or redacted
    /// claim keys / elements in the payload.
    SdCwt,
    /// An SD-KBT: a `kcwt` protected header parameter.
    SdKbt,
}

/// Bytes found in the input with their span.
#[derive(Debug, Clone, PartialEq)]
pub struct RawBytes<'a> {
    /// The whole bstr item (head and contents) in [`Sign1::bytes`].
    pub span: Span,
    /// The contents, exactly as received. Owned only for an
    /// indefinite-length byte string (its chunks concatenated).
    pub raw: Cow<'a, [u8]>,
}

/// A byte string whose contents may be CBOR: a protected header, a payload,
/// or a disclosure.
#[derive(Debug, Clone, PartialEq)]
pub struct Bstr<'a> {
    /// The whole bstr item (head and contents) in the bytes it was parsed
    /// from.
    pub span: Span,
    /// The contents, exactly as received.
    pub raw: Cow<'a, [u8]>,
    /// The contents decoded as one CBOR item. Spans inside are relative to
    /// `raw`. `None` for zero-length contents.
    pub decoded: Option<Result<Item<'a>, DecodeError>>,
}

impl Bstr<'_> {
    /// Offset of the first content byte in the bytes the bstr was parsed
    /// from (`span.start + span.head_len`).
    pub fn content_offset(&self) -> usize {
        unimplemented!()
    }
}

/// The payload slot of a COSE_Sign1.
#[derive(Debug, Clone, PartialEq)]
pub enum Payload<'a> {
    /// A byte string payload.
    Attached(Bstr<'a>),
    /// `nil`: the payload is detached (RFC 9052 §4.1).
    Detached {
        /// The `nil` item.
        span: Span,
    },
    /// Missing (short array) or of the wrong type; see the diagnostics.
    Malformed,
}

/// A structural problem found while parsing. Parsing continues where it
/// can, so a [`Sign1`] may carry several.
#[derive(Debug, Clone, PartialEq)]
pub struct Diagnostic {
    /// Where.
    pub part: Part,
    /// The offending item in [`Sign1::bytes`], when there is one.
    pub span: Option<Span>,
    /// What.
    pub kind: DiagnosticKind,
}

/// Kinds of [`Diagnostic`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum DiagnosticKind {
    /// The COSE_Sign1 array does not have exactly 4 elements.
    WrongArity(usize),
    /// Not a byte string (protected header, payload, signature, disclosure).
    NotBytes,
    /// Not a map (unprotected header, decoded protected header).
    NotMap,
    /// Not an array (`sd_claims`).
    NotArray,
    /// Byte string contents that should be CBOR but do not decode.
    Undecodable(DecodeError),
    /// A tag other than 18 directly inside tag 61, or any other tag
    /// around the COSE_Sign1 array.
    UnexpectedTag(u64),
    /// The same label in both header buckets (RFC 9052 §3).
    LabelInBothBuckets(Label),
    /// `sd_claims` is an empty array (sd-cwt-08 §9 step 2).
    EmptySdClaims,
    /// An SD header parameter in the wrong bucket: `sd_claims` in the
    /// protected header or `sd_alg` in the unprotected header.
    MisplacedSdHeader(i64),
}

/// A parsed COSE_Sign1 that keeps every original byte.
///
/// All spans are relative to [`bytes`](Self::bytes). For an SD-CWT parsed
/// out of an SD-KBT's `kcwt`, `bytes` is the embedded COSE_Sign1 and
/// [`base`](Self::base) is its offset in the outer input.
#[derive(Debug, Clone, PartialEq)]
pub struct Sign1<'a> {
    /// The input this was parsed from.
    pub bytes: &'a [u8],
    /// Offset of `bytes` in the outermost input (0 at top level).
    pub base: usize,
    /// The whole input, decoded (tags included).
    pub item: Item<'a>,
    /// Tags around the array, outermost first (e.g. `[61, 18]`).
    pub tags: Vec<u64>,
    /// The 4-element array (without its tags).
    pub span: Span,
    /// The protected header.
    pub protected: Option<Bstr<'a>>,
    /// The unprotected header map.
    pub unprotected: Option<Item<'a>>,
    /// The payload.
    pub payload: Payload<'a>,
    /// The signature.
    pub signature: Option<RawBytes<'a>>,
    /// Structural problems, in document order.
    pub diagnostics: Vec<Diagnostic>,
}

impl<'a> Sign1<'a> {
    /// The decoded protected header map. A zero-length protected header is
    /// an empty map; a header that is not a map is `None`.
    pub fn protected_header(&self) -> Option<&Item<'a>> {
        unimplemented!()
    }

    /// The value of header parameter `label`, protected bucket first.
    pub fn header(&self, label: i64) -> Option<(Bucket, &Item<'a>)> {
        let _ = label;
        unimplemented!()
    }

    /// The `alg` header parameter (protected first, then unprotected).
    pub fn alg(&self) -> Option<DeclaredAlg> {
        unimplemented!()
    }

    /// The `kid` header parameter bytes (protected first, then unprotected).
    pub fn kid(&self) -> Option<&[u8]> {
        unimplemented!()
    }

    /// The `typ` header parameter.
    pub fn typ(&self) -> Option<ContentType> {
        unimplemented!()
    }

    /// The `content type` header parameter.
    pub fn content_type(&self) -> Option<ContentType> {
        unimplemented!()
    }

    /// The labels listed in `crit`, if present and an array.
    pub fn crit(&self) -> Option<Vec<Label>> {
        unimplemented!()
    }

    /// The attached payload bytes (`None` when detached or malformed).
    pub fn payload_bytes(&self) -> Option<&[u8]> {
        unimplemented!()
    }

    /// The decoded payload, when attached and well-formed CBOR.
    pub fn payload_item(&self) -> Option<&Item<'a>> {
        unimplemented!()
    }

    /// What this token is (see [`TokenKind`]).
    pub fn kind(&self) -> TokenKind {
        unimplemented!()
    }
}
