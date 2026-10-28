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
//! ```no_run
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

#![allow(clippy::unimplemented)] // skeleton: implemented in a later commit

use std::fmt;
use std::ops::Range;

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
    /// Classic base64 (RFC 4648 §4).
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
        unimplemented!()
    }
}

/// Renders a JSON field path as an RFC 6901 JSON Pointer (`/vp_token/0`).
pub fn json_pointer(path: &[PathSegment]) -> String {
    let _ = path;
    unimplemented!()
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
pub fn detect(input: &[u8]) -> Vec<Candidate> {
    let _ = input;
    unimplemented!()
}

/// Applies `layers` to `input`, outermost first, and returns the payload.
pub fn unwrap_layers(input: &[u8], layers: &[Layer]) -> Result<Vec<u8>, UnwrapError> {
    let _ = (input, layers);
    unimplemented!()
}

/// Wraps `payload` in `layers`, innermost (last) first. The inverse of
/// [`unwrap_layers`]: for canonical inputs,
/// `rewrap(&unwrap_layers(x, l)?, l) == x`. [`Layer::JsonField`] produces a
/// compact document with only the path (`{"a":[null,"payload"]}`).
pub fn rewrap(payload: &[u8], layers: &[Layer]) -> Vec<u8> {
    let _ = (payload, layers);
    unimplemented!()
}
