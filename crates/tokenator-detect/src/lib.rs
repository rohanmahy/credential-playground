//! Credential and key format detection and unwrapping.
//!
//! [`detect`] takes whatever the user pasted, dropped, or opened (text or raw
//! binary) and returns ranked [`Candidate`]s. Each candidate records the
//! unwrapping [`Layer`]s it peeled off, outermost first (the UI breadcrumb),
//! the shallowly classified [`Kind`], a confidence, and where the payload
//! sits in the input. [`unwrap_layers`] replays a candidate's layers to get
//! the payload bytes, and [`rewrap`] is its inverse, used by Re-encode to
//! rebuild outer layers around a (possibly re-encoded) payload.
//!
//! ```
//! use tokenator_detect::{Kind, Layer, detect, rewrap, unwrap_layers};
//!
//! let input = b"Authorization: Bearer eyJhbGciOiJub25lIn0.e30.";
//! let top = &detect(input)[0];
//! assert_eq!(top.kind, Kind::Jwt);
//! assert!(matches!(top.layers[0], Layer::AuthorizationHeader { .. }));
//! let payload = unwrap_layers(input, &top.layers)?;
//! assert_eq!(rewrap(&payload, &top.layers), input);
//! # Ok::<(), tokenator_detect::UnwrapError>(())
//! ```
//!
//! Classification is structural only: it checks that headers and claims
//! parse and look sane (for example that a JOSE header has `alg`), never
//! signatures or digests. Full parsing and validation happen in the format
//! crates. Detection never panics and does no I/O.
//!
//! **EDN is not parsed here.** This crate cannot depend on the EDN parser, so
//! text that merely looks like EDN yields a lower-confidence
//! [`Kind::EdnText`] candidate. `tokenator-core` confirms it by parsing.
//!
//! **Ambiguity is surfaced, not resolved.** Every plausible reading becomes a
//! candidate: a CBOR map is always also offered as [`Kind::CborClaims`], a
//! JSON object as [`Kind::JsonClaims`], and a JSON object with several
//! token-looking string fields yields one candidate per field.

use std::fmt;
use std::ops::Range;

mod classify;
mod codec;
mod detect;
mod layers;

/// The maximum number of layers [`detect`] peels off for one candidate. It
/// bounds the work done on nested encodings (base64 of base64 of ...).
pub const MAX_LAYERS: usize = 16;

/// One way of reading the input.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Candidate {
    /// Unwrapping steps, outermost first. Empty if the input is the payload.
    pub layers: Vec<Layer>,
    /// What the payload was classified as.
    pub kind: Kind,
    /// 0 (wild guess) to 100 (certain). Only the relative order is meaningful.
    pub confidence: u8,
    /// The bytes of the input that the first decoding layer (`UrlEncoded`,
    /// `Base64Url`, `Base64Std`, or `Hex`) operates on. If every layer is
    /// positional (`Trim`, `Quotes`, `AuthorizationHeader`, `BearerPrefix`,
    /// `JsonField` without escapes, and `CborTag`), this is exactly the
    /// payload.
    pub payload_range: Range<usize>,
}

/// One unwrapping step. Each variant carries what [`rewrap`] needs to
/// rebuild the original bytes exactly for canonical inputs.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Layer {
    /// Surrounding ASCII whitespace, kept verbatim.
    Trim {
        /// Whitespace before the content.
        leading: String,
        /// Whitespace after the content (often a final newline).
        trailing: String,
    },
    /// A matching pair of `"`, `'`, or `` ` `` around the content. The content
    /// is not unescaped.
    Quotes {
        /// The quote character.
        quote: char,
    },
    /// An HTTP `Authorization:` header name, matched case-insensitively.
    AuthorizationHeader {
        /// The exact text removed, including the colon and following spaces,
        /// e.g. `"Authorization: "`.
        prefix: String,
    },
    /// The `Bearer` authentication scheme, matched case-insensitively.
    BearerPrefix {
        /// The exact text removed, including trailing spaces, e.g. `"Bearer "`.
        prefix: String,
    },
    /// Percent-encoding (`%XX`). `+` is a literal plus, not a space. Only
    /// recorded if the input contains at least one `%XX` escape. [`rewrap`]
    /// escapes every byte outside the RFC 3986 unreserved set
    /// (`A-Z a-z 0-9 - . _ ~`) as `%XX` with upper-case hex digits.
    UrlEncoded,
    /// A string member of a JSON document holding the payload.
    JsonField {
        /// Path from the root to the string.
        path: Vec<PathSegment>,
    },
    /// base64url (RFC 4648 §5). Text using neither `+/` nor `-_` is recorded
    /// as `Base64Url` when unpadded and as [`Layer::Base64Std`] when padded.
    Base64Url {
        /// Whether the text has `=` padding.
        padded: bool,
        /// Line length in characters if the text is wrapped with `\n`.
        wrap: Option<usize>,
    },
    /// Classic base64 (RFC 4648 §4). Text whose length needs no padding is
    /// recorded as padded here, and as unpadded for [`Layer::Base64Url`].
    Base64Std {
        /// Whether the text has `=` padding.
        padded: bool,
        /// Line length in characters if the text is wrapped with `\n`.
        wrap: Option<usize>,
    },
    /// Hexadecimal text. On input any whitespace and `:` are ignored, and
    /// case is free. The fields describe the layout for [`rewrap`].
    Hex {
        /// Upper-case digits.
        upper: bool,
        /// Separator between bytes on a line (`' '` or `':'`).
        separator: Option<char>,
        /// Bytes per line if the text is wrapped with `\n`.
        wrap: Option<usize>,
    },
    /// A CBOR tag around the payload (61 CWT, 18 COSE_Sign1, 55799
    /// self-described CBOR, ...). [`rewrap`] writes the preferred tag head.
    CborTag(u64),
}

/// One step of a [`Layer::JsonField`] path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PathSegment {
    /// An object member name.
    Key(String),
    /// An array index.
    Index(usize),
}

/// What a candidate's payload looks like.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// JWS Compact Serialization whose payload is not a JSON object.
    JwsCompact,
    /// JWS Compact Serialization whose payload is a JSON object (a JWT),
    /// including Unsecured JWTs (`alg: none`).
    Jwt,
    /// SD-JWT in compact (`~`-separated) form.
    SdJwt {
        /// The last part is a non-empty KB-JWT (an SD-JWT+KB).
        kb: bool,
    },
    /// JWS JSON Serialization without SD-JWT `disclosures`.
    JwsJson {
        /// General (`signatures` array) rather than flattened.
        general: bool,
    },
    /// SD-JWT in JWS JSON Serialization (RFC 9901 §8).
    SdJwtJson {
        /// General (`signatures` array) rather than flattened.
        general: bool,
        /// A `kb_jwt` unprotected header is present.
        kb: bool,
    },
    /// COSE_Sign1 whose payload is not a CBOR map (or is detached).
    CoseSign1,
    /// COSE_Sign1 whose payload is a CBOR map of claims.
    Cwt,
    /// A CWT with SD-CWT headers (`sd_alg`, `sd_claims`) or redacted claims.
    SdCwt,
    /// An SD-KBT: COSE_Sign1 with a `kcwt` protected header.
    SdKbt,
    /// An unsigned claim set as JSON text: the catch-all for JSON objects.
    JsonClaims,
    /// An unsigned claim set as a CBOR map: the catch-all for CBOR maps.
    CborClaims,
    /// Text that looks like EDN. Not parsed here; `tokenator-core` confirms.
    EdnText,
    /// A JSON Web Key.
    Jwk,
    /// A JSON Web Key Set.
    JwkSet,
    /// A COSE_Key.
    CoseKey,
    /// A COSE_KeySet.
    CoseKeySet,
    /// One or more PEM blocks.
    Pem {
        /// The label of each block, in order (e.g. `"PUBLIC KEY"`).
        labels: Vec<String>,
    },
}

impl Kind {
    /// Whether this kind belongs in the key panel rather than a credential tab.
    pub fn is_key(&self) -> bool {
        matches!(
            self,
            Kind::Jwk | Kind::JwkSet | Kind::CoseKey | Kind::CoseKeySet | Kind::Pem { .. }
        )
    }
}

/// Renders a JSON field path as an RFC 6901 JSON Pointer (`/vp_token/0`).
///
/// ```
/// use tokenator_detect::{PathSegment, json_pointer};
///
/// let path = [PathSegment::Key("a/b~c".into()), PathSegment::Index(0)];
/// assert_eq!(json_pointer(&path), "/a~1b~0c/0");
/// ```
pub fn json_pointer(path: &[PathSegment]) -> String {
    let mut out = String::new();
    for seg in path {
        out.push('/');
        match seg {
            PathSegment::Key(k) => out.push_str(&k.replace('~', "~0").replace('/', "~1")),
            PathSegment::Index(i) => out.push_str(&i.to_string()),
        }
    }
    out
}

/// Why [`unwrap_layers`] could not apply a layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwrapError {
    /// Index into the layer list of the layer that failed.
    pub layer: usize,
    /// A short human-readable reason.
    pub reason: &'static str,
}

impl fmt::Display for UnwrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot unwrap layer {}: {}", self.layer, self.reason)
    }
}

impl std::error::Error for UnwrapError {}

/// Detects what `input` might be. Returns candidates sorted by descending
/// confidence (ties in a deterministic order); empty if nothing matched.
/// Never panics, whatever the input.
///
/// The work is bounded: at most [`MAX_LAYERS`] layers per candidate, a fixed
/// budget of explored readings (so text that is valid hex *and* base64 at
/// every level cannot blow up), and at most 64 candidates returned.
///
/// A raw CWT (RFC 8392 A.3 shape, `18([<<{1: -7}>>, {}, <<{1: "x"}>>, h'00'])`):
///
/// ```
/// use tokenator_detect::{Kind, Layer, detect};
///
/// let cwt = [0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x44, 0xa1, 0x01, 0x61, 0x78, 0x41, 0x00];
/// let top = &detect(&cwt)[0];
/// assert_eq!(top.kind, Kind::Cwt);
/// assert_eq!(top.layers, [Layer::CborTag(18)]);
/// assert_eq!(top.payload_range, 1..cwt.len()); // the untagged COSE_Sign1
/// ```
///
/// Several readings of one input: a JSON response holding two tokens yields
/// one candidate per field, ranked above the response itself as a claim set.
///
/// ```
/// use tokenator_detect::{Kind, PathSegment, detect, json_pointer};
///
/// let jwt = "eyJhbGciOiJub25lIn0.e30.";
/// let cwt_hex = "d28443a10126a044a10161784100";
/// let input = format!(r#"{{"id_token":"{jwt}","cwt":"{cwt_hex}","state":"xyz"}}"#);
/// let cands = detect(input.as_bytes());
///
/// let summary: Vec<_> = cands
///     .iter()
///     .map(|c| (c.kind.clone(), c.layers.len()))
///     .collect();
/// assert_eq!(
///     summary,
///     [(Kind::Cwt, 3), (Kind::Jwt, 1), (Kind::JsonClaims, 0)],
/// );
/// // The CWT was found as {"cwt": hex( 18( COSE_Sign1 ) )}.
/// let tokenator_detect::Layer::JsonField { path } = &cands[0].layers[0] else { panic!() };
/// assert_eq!(json_pointer(path), "/cwt");
/// assert_eq!(&input[cands[0].payload_range.clone()], cwt_hex);
/// assert!(cands[1].confidence > cands[2].confidence);
/// ```
pub fn detect(input: &[u8]) -> Vec<Candidate> {
    detect::detect(input)
}

/// Applies `layers` to `input`, outermost first, and returns the payload.
///
/// Decoding is lenient about layout (line breaks, hex separators, the case
/// of `%xx` and of header prefixes) but not about content: the error names
/// the first layer that does not apply.
///
/// ```
/// use tokenator_detect::{Layer, unwrap_layers};
///
/// let layers = [Layer::BearerPrefix { prefix: "Bearer ".into() }];
/// assert_eq!(unwrap_layers(b"Bearer abc", &layers)?, b"abc");
/// # Ok::<(), tokenator_detect::UnwrapError>(())
/// ```
///
/// Replaying a stack, and a failure:
///
/// ```
/// use tokenator_detect::{Layer, PathSegment, unwrap_layers};
///
/// let layers = [
///     Layer::JsonField { path: vec![PathSegment::Key("cwt".into())] },
///     Layer::Hex { upper: false, separator: Some(':'), wrap: None },
///     Layer::CborTag(18),
/// ];
/// let payload = unwrap_layers(br#"{"cwt":"d2:80"}"#, &layers)?;
/// assert_eq!(payload, [0x80]); // the untagged item
///
/// let err = unwrap_layers(br#"{"cwt":"d8:3d:80"}"#, &layers).unwrap_err();
/// assert_eq!(err.layer, 2); // tag 61, not 18
/// # Ok::<(), tokenator_detect::UnwrapError>(())
/// ```
pub fn unwrap_layers(input: &[u8], layers: &[Layer]) -> Result<Vec<u8>, UnwrapError> {
    layers::unwrap_all(input, layers)
}

/// Wraps `payload` in `layers`, innermost (last) first. The inverse of
/// [`unwrap_layers`]: for canonical inputs,
/// `rewrap(&unwrap_layers(x, l)?, l) == x`. [`Layer::JsonField`] produces a
/// compact document with only the path (`{"a":[null,"payload"]}`).
///
/// ```
/// use tokenator_detect::{Layer, rewrap};
///
/// let b64 = Layer::Base64Url { padded: false, wrap: None };
/// assert_eq!(rewrap(b"abcd", &[b64]), b"YWJjZA");
/// ```
///
/// Re-encoding: unwrap a base64url CWT and present it as wrapped hex in an
/// `Authorization` header instead.
///
/// ```
/// use tokenator_detect::{Layer, detect, rewrap, unwrap_layers};
///
/// let input = b"0oRDoQEmoEShAWF4QQA"; // base64url of 18([...])
/// let top = &detect(input)[0];
/// let sign1 = unwrap_layers(input, &top.layers)?;
/// let out = rewrap(
///     &sign1,
///     &[
///         Layer::AuthorizationHeader { prefix: "Authorization: ".into() },
///         Layer::BearerPrefix { prefix: "Bearer ".into() },
///         Layer::Hex { upper: true, separator: Some(' '), wrap: Some(8) },
///         Layer::CborTag(18),
///     ],
/// );
/// assert_eq!(
///     String::from_utf8(out).unwrap(),
///     "Authorization: Bearer D2 84 43 A1 01 26 A0 44\nA1 01 61 78 41 00",
/// );
/// # Ok::<(), tokenator_detect::UnwrapError>(())
/// ```
pub fn rewrap(payload: &[u8], layers: &[Layer]) -> Vec<u8> {
    layers.iter().rev().fold(payload.to_vec(), |inner, layer| {
        layers::wrap_one(inner, layer)
    })
}
