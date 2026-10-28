//! Playground manipulation: re-signing, raw assembly, tampering, editing
//! disclosures, and converting between serializations.

use tokenator_crypto::rand_core::CryptoRng;
use tokenator_json::Node;
use tokenator_keys::Key;

use crate::error::JoseError;
use crate::issue::JsonStyle;
use crate::parse::{PartRef, SdJwt, Token};

/// Edited trees to re-sign. `None` keeps that part's original encoded text.
#[derive(Debug, Clone, Copy, Default)]
pub struct Edits<'e, 'n> {
    /// A replacement protected header (signature 0).
    pub header: Option<&'e Node<'n>>,
    /// A replacement payload.
    pub payload: Option<&'e Node<'n>>,
}

/// Re-signs signature 0 with `key`, using the `alg` of the (possibly
/// edited) protected header.
///
/// Edited trees are printed with `tokenator_json::PrintStyle::Original`, so
/// unedited bytes inside them stay identical; parts without an edit keep
/// their encoded text exactly. Disclosures and any KB-JWT are copied
/// unchanged (so a KB-JWT goes stale), and so are other signatures of a
/// general JSON serialization. The output has the input's serialization.
pub fn resign(
    token: &Token<'_>,
    edits: &Edits<'_, '_>,
    key: &Key,
    rng: &mut dyn CryptoRng,
) -> Result<String, JoseError> {
    unimplemented!()
}

/// Raw text parts of a compact token, joined without any checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawParts<'r> {
    /// Header segment.
    pub header: &'r str,
    /// Payload segment.
    pub payload: &'r str,
    /// Signature segment.
    pub signature: &'r str,
    /// `None` for a JWS; `Some` for an SD-JWT (each followed by `~`).
    pub disclosures: Option<&'r [&'r str]>,
    /// Appended after the last `~` (SD-JWT only).
    pub kb_jwt: Option<&'r str>,
}

/// `header.payload.signature`, plus `~D1~...~DN~[KB]` for an SD-JWT.
///
/// ```
/// use tokenator_jose::{RawParts, assemble_compact};
/// let raw = RawParts { header: "h", payload: "p", signature: "", disclosures: Some(&["d"]), kb_jwt: None };
/// assert_eq!(assemble_compact(&raw), "h.p.~d~");
/// ```
pub fn assemble_compact(parts: &RawParts<'_>) -> String {
    unimplemented!()
}

/// A deliberate break, applied without re-signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tamper {
    /// Flip bit `bit` of the decoded bytes of `part` (byte `bit / 8`, mask
    /// `0x80 >> (bit % 8)`) and re-encode it. Parts: protected header,
    /// payload, signature, disclosure, and the KB-JWT parts.
    FlipBit {
        /// Which part.
        part: PartRef,
        /// Bit index.
        bit: usize,
    },
    /// Set the protected header's `alg` (added at the end if absent). Other
    /// header bytes are kept (`Original` printing).
    SetAlg(String),
    /// Empty the signature segment.
    StripSignature,
    /// Set (or add) the protected header's `kid`, or remove it with `None`.
    SetKid(Option<String>),
    /// Keep only the first `n` bytes of the token text.
    Truncate(usize),
    /// Append a copy of disclosure `n` after the last disclosure.
    DuplicateDisclosure(usize),
    /// Re-encode the protected header as equivalent JSON with different
    /// bytes (`Pretty`, or `Compact` if that would not change the bytes).
    ReencodeHeader,
}

/// Applies `op` to a compact JWS or SD-JWT (with surrounding whitespace
/// ignored). Everything not targeted is copied byte for byte.
pub fn tamper(token: &str, op: &Tamper) -> Result<String, JoseError> {
    unimplemented!()
}

/// One edit of an SD-JWT's disclosures or digests.
#[derive(Debug, Clone)]
pub enum DisclosureOp {
    /// Remove disclosure `n`.
    Remove(usize),
    /// Append this base64url text as a disclosure.
    Append(String),
    /// Reorder: the new list is these indexes (repeats and omissions allowed).
    Reorder(Vec<usize>),
    /// Append a new disclosure (property with `name`, array element
    /// without). `salt: None` draws 16 random bytes.
    Forge {
        /// Salt.
        salt: Option<String>,
        /// Claim name.
        name: Option<String>,
        /// Value.
        value: Node<'static>,
    },
    /// Replace the value of disclosure `index`, keeping its salt and name.
    /// The new disclosure's digest no longer matches.
    ReplaceValue {
        /// Disclosure index.
        index: usize,
        /// New value.
        value: Node<'static>,
    },
    /// Add a digest (random if `None`) to the `_sd` of the payload object at
    /// pointer `at`, or as a `{"...": digest}` element appended to the array
    /// at `at`. Changes the payload, so the signature goes stale.
    AddDigest {
        /// Pointer into the issuer payload.
        at: String,
        /// The digest.
        digest: Option<String>,
    },
    /// Remove every occurrence of this digest from the payload (`_sd`
    /// entries and `{"...": digest}` elements). The signature goes stale.
    RemoveDigest(String),
}

/// Applies `ops` in order. Indexes refer to the disclosure list as it is
/// when each op runs. Payload edits print the payload with `Original` style
/// and keep the old signature; new disclosures use `style`. Any KB-JWT is
/// copied unchanged. The output has the input's serialization.
pub fn edit_disclosures(
    sd: &SdJwt<'_>,
    ops: &[DisclosureOp],
    style: JsonStyle,
    rng: &mut dyn CryptoRng,
) -> Result<String, JoseError> {
    unimplemented!()
}

/// A token in another serialization, plus what could not be carried over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Converted {
    /// The token text.
    pub text: String,
    /// Unprotected header members that compact serialization cannot hold
    /// (by name, in order; `disclosures` and `kb_jwt` are carried over and
    /// not listed).
    pub dropped: Vec<String>,
}

/// Which JSON serialization to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonSerialization {
    /// Flattened (RFC 7515 §7.2.2).
    Flattened,
    /// General (RFC 7515 §7.2.1).
    General,
}

/// Converts to compact serialization, using signature `index`. An SD-JWT's
/// disclosures and KB-JWT belong to the token, so they are appended whichever
/// signature is chosen.
pub fn to_compact(token: &Token<'_>, index: usize) -> Result<Converted, JoseError> {
    unimplemented!()
}

/// Converts to a JSON serialization (compact JSON text). An SD-JWT's
/// disclosures and KB-JWT go into the first unprotected header as
/// `disclosures` (always, possibly empty) and `kb_jwt`. Encoded parts and
/// other unprotected header members are copied verbatim. A general
/// serialization with several signatures cannot become flattened.
pub fn to_json(token: &Token<'_>, form: JsonSerialization) -> Result<String, JoseError> {
    unimplemented!()
}
