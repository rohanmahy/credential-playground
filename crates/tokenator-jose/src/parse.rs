//! The parsed token model and [`parse`].

use std::borrow::Cow;

use tokenator_crypto::HashAlg;
use tokenator_json::{JsonError, Node, Span, Value};

use crate::b64::{B64Error, b64u_decode};
use crate::sd::{DisclosureError, DisclosureView, Processed, sd_digest};

/// JSON insignificant whitespace (RFC 8259 §2), trimmed around a token.
pub(crate) const JSON_WS: [char; 4] = [' ', '\t', '\n', '\r'];

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
        let text = text.into();
        let decoded = b64u_decode(&text);
        B64Part {
            text,
            span,
            decoded,
        }
    }

    /// The encoded text (what signatures and digests are computed over).
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Byte range of the encoded text in the input.
    pub fn span(&self) -> Span {
        self.span
    }

    /// The decoded bytes.
    pub fn decoded(&self) -> Result<&[u8], B64Error> {
        self.decoded.as_deref().map_err(|e| *e)
    }

    /// The decoded bytes parsed as JSON. Spans in the tree are relative to
    /// [`B64Part::decoded`], not to the input.
    pub fn json(&self) -> Result<Node<'_>, PartError> {
        let bytes = self.decoded().map_err(PartError::Base64)?;
        tokenator_json::parse(bytes).map_err(PartError::Json)
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
    /// The original text, for output that copies untouched bytes.
    pub(crate) source: Source<'a>,
}

/// Where a [`Jws`] came from.
#[derive(Debug, Clone)]
pub(crate) enum Source<'a> {
    /// The compact text (for a KB-JWT inside a JSON serialization, the
    /// unescaped `kb_jwt` string).
    Compact(Cow<'a, str>),
    /// The parsed envelope; spans are relative to the input. Boxed to keep
    /// `Jws` (and `Token`) small.
    Json(Box<Node<'a>>),
}

impl Jws<'_> {
    /// The original compact text (`None` for a JSON serialization).
    pub(crate) fn compact_source(&self) -> Option<&str> {
        match &self.source {
            Source::Compact(text) => Some(text),
            Source::Json(_) => None,
        }
    }

    /// The parsed envelope of a JSON serialization.
    pub(crate) fn envelope(&self) -> Option<&Node<'_>> {
        match &self.source {
            Source::Compact(_) => None,
            Source::Json(root) => Some(root),
        }
    }

    /// `ASCII(protected) || "." || ASCII(payload)` for signature `index`
    /// (RFC 7515 §5.2), built from the original encoded text. An absent
    /// protected header contributes the empty string.
    pub fn signing_input(&self, index: usize) -> Option<String> {
        let sig = self.signatures.get(index)?;
        let protected = sig.protected.as_ref().map_or("", B64Part::text);
        Some(format!("{protected}.{}", self.payload.text()))
    }

    /// The decoded protected header of signature `index`.
    pub fn header(&self, index: usize) -> Option<Result<Node<'_>, PartError>> {
        let sig = self.signatures.get(index)?;
        sig.protected.as_ref().map(B64Part::json)
    }

    /// The decoded payload as JSON (fails for non-JSON payloads such as
    /// RFC 7515 A.4's `Payload`).
    pub fn claims(&self) -> Result<Node<'_>, PartError> {
        self.payload.json()
    }

    /// Signature 0 in compact form, `protected.payload.signature`, from the
    /// original text. `None` if signature 0 has no protected header.
    pub fn compact(&self) -> Option<String> {
        let sig = self.signatures.first()?;
        let protected = sig.protected.as_ref()?;
        Some(format!(
            "{}.{}.{}",
            protected.text(),
            self.payload.text(),
            sig.signature.text()
        ))
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
        Disclosure::from_part(B64Part::new(
            text,
            Span {
                start: 0,
                end: text.len(),
            },
        ))
    }

    /// Wraps a located part.
    pub fn from_part(part: B64Part<'a>) -> Disclosure<'a> {
        Disclosure { part }
    }

    /// The located base64url part.
    pub fn part(&self) -> &B64Part<'a> {
        &self.part
    }

    /// The base64url text, exactly as received.
    pub fn text(&self) -> &str {
        self.part.text()
    }

    /// Base64url digest of [`Disclosure::text`]'s ASCII bytes (RFC 9901
    /// §4.2.3). Defined even when the text does not decode.
    pub fn digest(&self, hash: HashAlg) -> String {
        sd_digest(self.text(), hash)
    }

    /// The decoded `[salt, name, value]` or `[salt, value]` array.
    pub fn view(&self) -> Result<DisclosureView<'_>, DisclosureError> {
        DisclosureView::new(&self.part)
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
        let mut out = self.issuer.compact()?;
        out.push('~');
        for d in &self.disclosures {
            out.push_str(d.text());
            out.push('~');
        }
        Some(out)
    }

    /// Matches disclosures against the issuer payload and reconstructs the
    /// processed claims (see [`crate::process`]).
    pub fn process(&self) -> Result<Processed<'_>, PartError> {
        let payload = self.issuer.claims()?;
        Ok(crate::sd::process(&payload, &self.disclosures))
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
        match self {
            Token::Jws(jws) => jws,
            Token::SdJwt(sd) => &sd.issuer,
        }
    }

    /// The SD-JWT, if this is one.
    pub fn sd_jwt(&self) -> Option<&SdJwt<'a>> {
        match self {
            Token::Jws(_) => None,
            Token::SdJwt(sd) => Some(sd),
        }
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
    let start = input.len() - input.trim_start_matches(JSON_WS).len();
    let end = input.trim_end_matches(JSON_WS).len();
    let Some(text) = input.get(start..end).filter(|t| !t.is_empty()) else {
        return Err(ParseError::Empty);
    };
    let mut diagnostics = Vec::new();
    let token = if text.starts_with('{') {
        let envelope = input.get(..end).unwrap_or_default();
        parse_json(envelope, &mut diagnostics)?
    } else if text.contains(['.', '~']) {
        parse_compact(text, start, &mut diagnostics)
    } else {
        return Err(ParseError::NotAToken);
    };
    Ok(Parsed { token, diagnostics })
}

/// A sub-range of `text`, borrowing when `text` does.
fn sub<'a>(text: &Cow<'a, str>, start: usize, end: usize) -> Cow<'a, str> {
    match text {
        Cow::Borrowed(t) => Cow::Borrowed(t.get(start..end).unwrap_or_default()),
        Cow::Owned(t) => Cow::Owned(t.get(start..end).unwrap_or_default().to_owned()),
    }
}

fn span_at(base: usize, start: usize, end: usize) -> Span {
    Span {
        start: base + start,
        end: base + end,
    }
}

fn diag(
    diagnostics: &mut Vec<Diagnostic>,
    part: PartRef,
    span: Option<Span>,
    kind: DiagnosticKind,
) {
    diagnostics.push(Diagnostic { part, span, kind });
}

/// Reports a header or payload that does not decode to a JSON object.
fn check_object(part: &B64Part<'_>, which: PartRef, diagnostics: &mut Vec<Diagnostic>) {
    let kind = match part.json() {
        Ok(node) if node.members().is_some() => return,
        Ok(_) => DiagnosticKind::NotAnObject,
        Err(PartError::Base64(e)) => DiagnosticKind::Base64(e),
        Err(PartError::Json(e)) => DiagnosticKind::Json(e),
    };
    diag(diagnostics, which, Some(part.span()), kind);
}

fn check_signature(part: &B64Part<'_>, which: PartRef, diagnostics: &mut Vec<Diagnostic>) {
    if let Err(e) = part.decoded() {
        diag(
            diagnostics,
            which,
            Some(part.span()),
            DiagnosticKind::Base64(e),
        );
    }
}

fn check_disclosure(d: &Disclosure<'_>, index: usize, diagnostics: &mut Vec<Diagnostic>) {
    let span = Some(d.part().span());
    let part = PartRef::Disclosure(index);
    if d.text().is_empty() {
        diag(diagnostics, part, span, DiagnosticKind::EmptyDisclosure);
        return;
    }
    let kind = match d.view() {
        Ok(_) => return,
        Err(DisclosureError::Base64(e)) => DiagnosticKind::Base64(e),
        Err(DisclosureError::Json(e)) => DiagnosticKind::Json(e),
        Err(e) => DiagnosticKind::Disclosure(e),
    };
    diag(diagnostics, part, span, kind);
}

/// Parses `header.payload.signature` located at `base` in the input. A
/// KB-JWT reports its parts with the `Kb*` part names.
fn parse_compact_jws<'a>(
    text: Cow<'a, str>,
    base: usize,
    kb: bool,
    diagnostics: &mut Vec<Diagnostic>,
) -> Jws<'a> {
    let len = text.len();
    let dot1 = text.find('.');
    let dot2 = dot1.and_then(|d| text.get(d + 1..)?.find('.').map(|e| d + 1 + e));
    let (h_end, p_start) = dot1.map_or((len, len), |d| (d, d + 1));
    let (p_end, s_start) = dot2.map_or((len, len), |d| (d, d + 1));
    let p_end = p_end.max(p_start);
    let part =
        |start: usize, end: usize| B64Part::new(sub(&text, start, end), span_at(base, start, end));
    let protected = part(0, h_end);
    let payload = part(p_start, p_end);
    let signature = part(s_start, len);

    let (whole, header_ref, payload_ref, sig_ref) = if kb {
        (
            PartRef::KbJwt,
            PartRef::KbProtectedHeader,
            PartRef::KbPayload,
            PartRef::KbSignature,
        )
    } else {
        (
            PartRef::Signature(0),
            PartRef::ProtectedHeader(0),
            PartRef::Payload,
            PartRef::Signature(0),
        )
    };
    let found = text.matches('.').count() + 1;
    if found != 3 {
        let kind = DiagnosticKind::SegmentCount { found };
        diag(diagnostics, whole, Some(span_at(base, 0, len)), kind);
    }
    check_object(&protected, header_ref, diagnostics);
    check_object(&payload, payload_ref, diagnostics);
    check_signature(&signature, sig_ref, diagnostics);

    Jws {
        serialization: Serialization::Compact,
        span: span_at(base, 0, len),
        payload,
        signatures: vec![JwsSignature {
            protected: Some(protected),
            unprotected: None,
            signature,
        }],
        source: Source::Compact(text),
    }
}

/// Parses compact text (already trimmed) found at `base` in the input.
fn parse_compact<'a>(text: &'a str, base: usize, diagnostics: &mut Vec<Diagnostic>) -> Token<'a> {
    if !text.contains('~') {
        return Token::Jws(parse_compact_jws(
            Cow::Borrowed(text),
            base,
            false,
            diagnostics,
        ));
    }
    let mut pieces = Vec::new();
    let mut offset = 0;
    for piece in text.split('~') {
        pieces.push((offset, piece));
        offset += piece.len() + 1;
    }
    let (first, rest) = pieces.split_first().unwrap_or((&(0, ""), &[]));
    let (last, middle) = rest.split_last().unwrap_or((&(0, ""), &[]));
    let issuer = parse_compact_jws(Cow::Borrowed(first.1), base, false, diagnostics);
    let mut disclosures = Vec::with_capacity(middle.len());
    for (i, (start, piece)) in middle.iter().enumerate() {
        let span = span_at(base, *start, start + piece.len());
        let d = Disclosure::from_part(B64Part::new(*piece, span));
        check_disclosure(&d, i, diagnostics);
        disclosures.push(d);
    }
    let kb_jwt = (!last.1.is_empty())
        .then(|| parse_compact_jws(Cow::Borrowed(last.1), base + last.0, true, diagnostics));
    Token::SdJwt(SdJwt {
        issuer,
        disclosures,
        kb_jwt,
    })
}

/// The string value of `node` and the span of its contents (without quotes).
fn string_part<'a>(node: &Node<'a>) -> Option<(Cow<'a, str>, Span)> {
    let Value::String(s) = node.value() else {
        return None;
    };
    let span = node.span().map_or(Span { start: 0, end: 0 }, |sp| Span {
        start: sp.start + 1,
        end: sp.end.saturating_sub(1).max(sp.start + 1),
    });
    Some((s.clone(), span))
}

/// An empty part at the end of `node`, for a missing member.
fn empty_part_at<'a>(node: &Node<'_>) -> B64Part<'a> {
    let end = node.span().map_or(0, |s| s.end);
    B64Part::new("", Span { start: end, end })
}

/// Reads one signature object of a JSON serialization.
fn parse_json_signature<'a>(
    obj: &Node<'a>,
    index: usize,
    diagnostics: &mut Vec<Diagnostic>,
) -> JwsSignature<'a> {
    let protected = match obj.get("protected") {
        None => None,
        Some(node) => match string_part(node) {
            Some((text, span)) => {
                let part = B64Part::new(text, span);
                check_object(&part, PartRef::ProtectedHeader(index), diagnostics);
                Some(part)
            }
            None => {
                let kind = DiagnosticKind::WrongType("protected");
                diag(
                    diagnostics,
                    PartRef::ProtectedHeader(index),
                    node.span(),
                    kind,
                );
                None
            }
        },
    };
    let unprotected = match obj.get("header") {
        None => None,
        Some(node) if node.members().is_some() => Some(node.clone()),
        Some(node) => {
            let kind = DiagnosticKind::WrongType("header");
            diag(
                diagnostics,
                PartRef::UnprotectedHeader(index),
                node.span(),
                kind,
            );
            None
        }
    };
    let which = PartRef::Signature(index);
    let signature = match obj.get("signature") {
        None => {
            let kind = DiagnosticKind::MissingMember("signature");
            diag(diagnostics, which, obj.span(), kind);
            empty_part_at(obj)
        }
        Some(node) => match string_part(node) {
            Some((text, span)) => {
                let part = B64Part::new(text, span);
                check_signature(&part, which, diagnostics);
                part
            }
            None => {
                diag(
                    diagnostics,
                    which,
                    node.span(),
                    DiagnosticKind::WrongType("signature"),
                );
                empty_part_at(node)
            }
        },
    };
    JwsSignature {
        protected,
        unprotected,
        signature,
    }
}

/// Parses a JSON serialization. `input` ends where the trimmed token ends.
fn parse_json<'a>(
    input: &'a str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Token<'a>, ParseError> {
    let root = tokenator_json::parse(input.as_bytes()).map_err(ParseError::Json)?;
    if root.members().is_none() {
        return Err(ParseError::NotAJwsEnvelope);
    }
    let Some((payload_text, payload_span)) = root.get("payload").and_then(string_part) else {
        return Err(ParseError::NotAJwsEnvelope);
    };
    let payload = B64Part::new(payload_text, payload_span);
    let mut signatures = Vec::new();
    let serialization = match root.get("signatures") {
        Some(sigs) => {
            if ["protected", "header", "signature"]
                .iter()
                .any(|k| root.get(k).is_some())
            {
                let kind = DiagnosticKind::MixedSerialization;
                diag(diagnostics, PartRef::Envelope, root.span(), kind);
            }
            check_object(&payload, PartRef::Payload, diagnostics);
            let elements = sigs.elements().unwrap_or_default();
            if sigs.elements().is_none() {
                let kind = DiagnosticKind::WrongType("signatures");
                diag(diagnostics, PartRef::Envelope, sigs.span(), kind);
            }
            for el in elements {
                if el.members().is_some() {
                    let index = signatures.len();
                    signatures.push(parse_json_signature(el, index, diagnostics));
                } else {
                    let kind = DiagnosticKind::WrongType("signatures");
                    diag(diagnostics, PartRef::Envelope, el.span(), kind);
                }
            }
            if signatures.is_empty() {
                if sigs.elements().is_some() {
                    let kind = DiagnosticKind::MissingMember("signature");
                    diag(diagnostics, PartRef::Signature(0), sigs.span(), kind);
                }
                signatures.push(JwsSignature {
                    protected: None,
                    unprotected: None,
                    signature: empty_part_at(sigs),
                });
            }
            Serialization::JsonGeneral
        }
        None => {
            check_object(&payload, PartRef::Payload, diagnostics);
            signatures.push(parse_json_signature(&root, 0, diagnostics));
            Serialization::JsonFlattened
        }
    };

    for (i, sig) in signatures.iter().enumerate().skip(1) {
        for name in ["disclosures", "kb_jwt"] {
            if let Some(node) = sig.unprotected.as_ref().and_then(|h| h.get(name)) {
                let kind = DiagnosticKind::MisplacedSdMember(name);
                diag(
                    diagnostics,
                    PartRef::UnprotectedHeader(i),
                    node.span(),
                    kind,
                );
            }
        }
    }
    let first_header = signatures.first().and_then(|s| s.unprotected.as_ref());
    let sd_members = first_header.map(|h| (h.get("disclosures"), h.get("kb_jwt")));
    let sd = match sd_members {
        Some((d, k)) if d.is_some() || k.is_some() => Some(json_sd_members(d, k, diagnostics)),
        _ => None,
    };

    let issuer = Jws {
        serialization,
        span: root.span().unwrap_or(Span {
            start: 0,
            end: input.len(),
        }),
        payload,
        signatures,
        source: Source::Json(Box::new(root)),
    };
    Ok(match sd {
        None => Token::Jws(issuer),
        Some((disclosures, kb_jwt)) => Token::SdJwt(SdJwt {
            issuer,
            disclosures,
            kb_jwt,
        }),
    })
}

/// Reads `disclosures` and `kb_jwt` from the first unprotected header.
fn json_sd_members<'a>(
    disclosures: Option<&Node<'a>>,
    kb_jwt: Option<&Node<'a>>,
    diagnostics: &mut Vec<Diagnostic>,
) -> (Vec<Disclosure<'a>>, Option<Jws<'a>>) {
    let header = PartRef::UnprotectedHeader(0);
    let mut out = Vec::new();
    if let Some(node) = disclosures {
        if node.elements().is_none() {
            diag(
                diagnostics,
                header,
                node.span(),
                DiagnosticKind::WrongType("disclosures"),
            );
        }
        for el in node.elements().unwrap_or_default() {
            match string_part(el) {
                Some((text, span)) => {
                    let d = Disclosure::from_part(B64Part::new(text, span));
                    check_disclosure(&d, out.len(), diagnostics);
                    out.push(d);
                }
                None => {
                    let kind = DiagnosticKind::WrongType("disclosures");
                    diag(diagnostics, header, el.span(), kind);
                }
            }
        }
    }
    let kb = match kb_jwt {
        None => None,
        Some(node) => match string_part(node) {
            Some((text, _)) if text.is_empty() => None,
            Some((text, span)) => Some(parse_compact_jws(text, span.start, true, diagnostics)),
            None => {
                diag(
                    diagnostics,
                    header,
                    node.span(),
                    DiagnosticKind::WrongType("kb_jwt"),
                );
                None
            }
        },
    };
    (out, kb)
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
