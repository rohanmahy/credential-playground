//! The parsed token model and [`parse`].

use std::borrow::Cow;

use tokenator_crypto::HashAlg;
use tokenator_json::{JsonError, Node, Span};

use crate::b64::B64Error;
use crate::sd::{DisclosureError, DisclosureView, Processed};

/// How a JWS (or the issuer-signed JWT of an SD-JWT) is serialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Serialization {
    /// `header.payload.signature` (RFC 7515 §7.1), with `~`-separated
    /// disclosures and KB-JWT for an SD-JWT (RFC 9901 §4).
    Compact,
    /// Flattened JWS JSON Serialization (RFC 7515 §7.2.2, RFC 9901 §8.2).
    JsonFlattened,
    /// General JWS JSON Serialization (RFC 7515 §7.2.1, RFC 9901 §8.3).
    JsonGeneral,
}

/// Names one part of a parsed token, for diagnostics and manipulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PartRef {
    /// The JSON serialization envelope (the outer object).
    Envelope,
    /// Protected header of signature `n` (always 0 for compact and flattened).
    ProtectedHeader(usize),
    /// Unprotected `header` of signature `n` (JSON serialization only).
    UnprotectedHeader(usize),
    /// The JWS payload.
    Payload,
    /// Signature `n` (always 0 for compact and flattened).
    Signature(usize),
    /// SD-JWT disclosure `n`, in input order.
    Disclosure(usize),
    /// The KB-JWT as a whole (e.g. a wrong number of segments).
    KbJwt,
    /// The KB-JWT protected header.
    KbProtectedHeader,
    /// The KB-JWT payload.
    KbPayload,
    /// The KB-JWT signature.
    KbSignature,
}

/// Why a part's content could not be read as JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartError {
    /// The base64url text did not decode.
    Base64(B64Error),
    /// The decoded bytes are not valid JSON (RFC 8259) text.
    Json(JsonError),
}

/// One base64url-encoded part, located in the input.
///
/// [`B64Part::text`] is exactly the encoded text, and for compact
/// serialization `&input[span.start..span.end] == text`. Inside a JSON
/// serialization the span covers the string's contents (without quotes);
/// if the JSON string used escapes, `text` is the unescaped string and the
/// span still covers the escaped source.
#[derive(Debug, Clone)]
pub struct B64Part<'a> {
    text: Cow<'a, str>,
    span: Span,
    decoded: Result<Vec<u8>, B64Error>,
}

impl<'a> B64Part<'a> {
    /// A part decoded from `text`, located at `span` in some input.
    pub fn new(text: impl Into<Cow<'a, str>>, span: Span) -> B64Part<'a> {
        unimplemented!()
    }

    /// The encoded text (what signatures and digests are computed over).
    pub fn text(&self) -> &str {
        unimplemented!()
    }

    /// Byte range of the encoded text in the input.
    pub fn span(&self) -> Span {
        unimplemented!()
    }

    /// The decoded bytes.
    pub fn decoded(&self) -> Result<&[u8], B64Error> {
        unimplemented!()
    }

    /// The decoded bytes parsed as JSON. Spans in the tree are relative to
    /// [`B64Part::decoded`], not to the input.
    pub fn json(&self) -> Result<Node<'_>, PartError> {
        unimplemented!()
    }
}

/// One signature of a JWS.
#[derive(Debug, Clone)]
pub struct JwsSignature<'a> {
    /// The protected header. `None` only in a JSON serialization that omits
    /// `protected`.
    pub protected: Option<B64Part<'a>>,
    /// The unprotected `header` object (JSON serialization only). Spans are
    /// relative to the input.
    pub unprotected: Option<Node<'a>>,
    /// The signature.
    pub signature: B64Part<'a>,
}

/// A JWS: a JWT, the issuer-signed JWT of an SD-JWT, or a KB-JWT.
#[derive(Debug, Clone)]
pub struct Jws<'a> {
    /// How it was serialized.
    pub serialization: Serialization,
    /// Byte range of the whole JWS in the input: the three compact
    /// segments with their dots, or the JSON envelope.
    pub span: Span,
    /// The payload.
    pub payload: B64Part<'a>,
    /// One signature for compact and flattened, one or more for general.
    pub signatures: Vec<JwsSignature<'a>>,
}

impl Jws<'_> {
    /// `ASCII(protected) || "." || ASCII(payload)` for signature `index`
    /// (RFC 7515 §5.2), built from the original encoded text. An absent
    /// protected header contributes the empty string.
    pub fn signing_input(&self, index: usize) -> Option<String> {
        unimplemented!()
    }

    /// The decoded protected header of signature `index`.
    pub fn header(&self, index: usize) -> Option<Result<Node<'_>, PartError>> {
        unimplemented!()
    }

    /// The decoded payload as JSON (fails for non-JSON payloads such as
    /// RFC 7515 A.4's `Payload`).
    pub fn claims(&self) -> Result<Node<'_>, PartError> {
        unimplemented!()
    }

    /// Signature 0 in compact form, `protected.payload.signature`, from the
    /// original text. `None` if signature 0 has no protected header.
    pub fn compact(&self) -> Option<String> {
        unimplemented!()
    }
}

/// One SD-JWT disclosure (RFC 9901 §4.2).
#[derive(Debug, Clone)]
pub struct Disclosure<'a> {
    part: B64Part<'a>,
}

impl<'a> Disclosure<'a> {
    /// A disclosure from its base64url text, outside any token (span
    /// `0..text.len()`).
    pub fn new(text: &'a str) -> Disclosure<'a> {
        unimplemented!()
    }

    /// Wraps a located part.
    pub fn from_part(part: B64Part<'a>) -> Disclosure<'a> {
        unimplemented!()
    }

    /// The located base64url part.
    pub fn part(&self) -> &B64Part<'a> {
        unimplemented!()
    }

    /// The base64url text, exactly as received.
    pub fn text(&self) -> &str {
        unimplemented!()
    }

    /// Base64url digest of [`Disclosure::text`]'s ASCII bytes (RFC 9901
    /// §4.2.3). Defined even when the text does not decode.
    pub fn digest(&self, hash: HashAlg) -> String {
        unimplemented!()
    }

    /// The decoded `[salt, name, value]` or `[salt, value]` array.
    pub fn view(&self) -> Result<DisclosureView<'_>, DisclosureError> {
        unimplemented!()
    }
}

/// An SD-JWT or SD-JWT+KB (RFC 9901).
#[derive(Debug, Clone)]
pub struct SdJwt<'a> {
    /// The issuer-signed JWT.
    pub issuer: Jws<'a>,
    /// Disclosures in input order (from `header.disclosures` in a JSON
    /// serialization).
    pub disclosures: Vec<Disclosure<'a>>,
    /// The KB-JWT, always compact (from `header.kb_jwt` in a JSON
    /// serialization). `None` when the compact form ends with `~`.
    pub kb_jwt: Option<Jws<'a>>,
}

impl<'a> SdJwt<'a> {
    /// The string `sd_hash` is computed over (RFC 9901 §4.3.1, §8.1):
    /// `<issuer compact>~<D.1>~...~<D.N>~`, using signature 0 and the
    /// original encoded text. `None` if signature 0 has no protected header.
    pub fn sd_hash_input(&self) -> Option<String> {
        unimplemented!()
    }

    /// Matches disclosures against the issuer payload and reconstructs the
    /// processed claims (see [`crate::process`]).
    pub fn process(&self) -> Result<Processed<'_>, PartError> {
        unimplemented!()
    }
}

/// A parsed token.
#[derive(Debug, Clone)]
pub enum Token<'a> {
    /// A JWS / JWT (no disclosures).
    Jws(Jws<'a>),
    /// An SD-JWT, with or without KB-JWT.
    SdJwt(SdJwt<'a>),
}

impl<'a> Token<'a> {
    /// The JWS, or the issuer-signed JWT of an SD-JWT.
    pub fn jws(&self) -> &Jws<'a> {
        unimplemented!()
    }

    /// The SD-JWT, if this is one.
    pub fn sd_jwt(&self) -> Option<&SdJwt<'a>> {
        unimplemented!()
    }
}

/// A problem with one part that did not stop parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// Which part.
    pub part: PartRef,
    /// Where in the input, when known.
    pub span: Option<Span>,
    /// What is wrong.
    pub kind: DiagnosticKind,
}

/// What a [`Diagnostic`] reports.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiagnosticKind {
    /// The part's base64url did not decode.
    Base64(B64Error),
    /// The decoded part (header, JWT payload, KB-JWT payload, disclosure)
    /// is not valid JSON. Reported for the payload of a plain JWS too,
    /// since the payload need not be JSON.
    Json(JsonError),
    /// A header or the payload is JSON but not an object.
    NotAnObject,
    /// A disclosure decoded to JSON but is not a valid disclosure array.
    Disclosure(DisclosureError),
    /// A compact JWS (the token or the KB-JWT) without exactly three
    /// `.`-separated segments. Missing segments are empty parts; with more
    /// than three, the third part holds the rest (dots included).
    SegmentCount {
        /// Segments found.
        found: usize,
    },
    /// An empty disclosure between two `~`.
    EmptyDisclosure,
    /// A required envelope member is missing (`payload`, `signature`, ...).
    MissingMember(&'static str),
    /// An envelope member has the wrong JSON type.
    WrongType(&'static str),
    /// Both `signature` and `signatures` are present; the general form wins.
    MixedSerialization,
    /// `disclosures` or `kb_jwt` in the header of a signature other than the
    /// first (RFC 9901 §8.3); ignored.
    MisplacedSdMember(&'static str),
}

/// Input that cannot be read as a JWS or SD-JWT at all.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Empty or whitespace-only input.
    Empty,
    /// Neither a JSON object nor text containing `.` or `~`.
    NotAToken,
    /// Input starts with `{` but is not valid JSON.
    Json(JsonError),
    /// A JSON envelope that is not an object, or has no `payload` string.
    NotAJwsEnvelope,
}

/// A parsed token plus everything that went wrong in individual parts.
#[derive(Debug, Clone)]
pub struct Parsed<'a> {
    /// The token. Parts that failed to decode are still present.
    pub token: Token<'a>,
    /// Problems found, in input order.
    pub diagnostics: Vec<Diagnostic>,
}

/// Parses a JWS (compact, flattened or general JSON), SD-JWT, or SD-JWT+KB.
///
/// Leading and trailing ASCII whitespace is ignored; all spans are relative
/// to `input` itself. Input starting with `{` is a JSON serialization; it
/// is an SD-JWT if the first signature's unprotected header has
/// `disclosures` or `kb_jwt`. Compact input is an SD-JWT if it contains
/// `~`. A part that fails to decode does not stop parsing: it is kept as
/// is and reported in [`Parsed::diagnostics`].
pub fn parse(input: &str) -> Result<Parsed<'_>, ParseError> {
    unimplemented!()
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ParseError {}

impl core::fmt::Display for PartError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for PartError {}
