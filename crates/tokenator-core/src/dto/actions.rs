//! Requests and results of the Engine actions (SPEC §5, §6).

use serde::{Deserialize, Serialize};

use super::common::{Bytes, HashName, KidValue, NodeId, Nonce};
use super::detect::{Kind, Layer};
use super::document::{Diagnostic, Document, Node, ViewOptions};
use super::keys::KeyRef;

/// A document as the UI holds it: kind plus bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct DocRef {
    /// `Document.kind`.
    pub kind: Kind,
    /// `Document.bytes`.
    pub bytes: Bytes,
}

impl DocRef {
    /// A document reference.
    pub fn new(kind: Kind, bytes: impl Into<Bytes>) -> DocRef {
        DocRef {
            kind,
            bytes: bytes.into(),
        }
    }
}

impl From<&Document> for DocRef {
    fn from(doc: &Document) -> DocRef {
        DocRef {
            kind: doc.kind.clone(),
            bytes: doc.bytes.clone(),
        }
    }
}

/// Input of [`Engine::render`](crate::Engine::render).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
pub struct RenderRequest {
    /// The document.
    pub doc: DocRef,
    /// Outer layers to record in the result (from the original `open`).
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<Vec<Layer>>", optional))]
    pub layers: Vec<Layer>,
    /// View options.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<ViewOptions>", optional))]
    pub view: ViewOptions,
}

/// Input of [`Engine::parse_edit`](crate::Engine::parse_edit).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
pub struct EditRequest {
    /// The kind being edited.
    pub kind: Kind,
    /// The bytes before the edit (for unedited regions and the stale flag).
    pub base: Bytes,
    /// The edited main pane text.
    pub text: String,
    /// View options for the returned document.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<ViewOptions>", optional))]
    pub view: ViewOptions,
}

/// The result of a live edit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct EditResult {
    /// The text parsed and bytes were built.
    pub ok: bool,
    /// The new bytes.
    pub bytes: Option<Bytes>,
    /// The re-rendered document.
    pub document: Option<Document>,
    /// Signed content differs from `base` (the signature was kept).
    pub signature_stale: bool,
    /// Parse errors (with their `main` position) and warnings.
    pub diagnostics: Vec<Diagnostic>,
}

/// Input of [`Engine::issue`](crate::Engine::issue) and
/// [`Engine::redact`](crate::Engine::redact).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
pub struct IssueRequest {
    /// The claim set: `json_claims` issues JOSE, `edn_claims` and
    /// `cbor_claims` issue COSE.
    pub claims: DocRef,
    /// The issuer's private key.
    pub issuer: KeyRef,
    /// JOSE alg name (`ES256`, `Ed25519`, `ML-DSA-44`); derived from the key
    /// when absent.
    #[serde(default)]
    pub alg: Option<String>,
    /// Header options.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<HeaderOptions>", optional))]
    pub header: HeaderOptions,
    /// Selective disclosure options.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<SdOptions>", optional))]
    pub sd: SdOptions,
    /// Holder confirmation (`cnf`).
    #[serde(default)]
    pub cnf: Option<CnfChoice>,
    /// JOSE output serialization.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<JoseSerialization>", optional))]
    pub jose_serialization: JoseSerialization,
    /// COSE tags, outermost first (default `[18]`).
    #[serde(default)]
    pub cose_tags: Option<Vec<u64>>,
    /// 32-byte seed for salts, decoys, and randomized signatures. Without
    /// it, signing is deterministic and SD needs `sd.fixed_salts`.
    #[serde(default)]
    pub randomness: Option<Bytes>,
    /// View options for the result.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<ViewOptions>", optional))]
    pub view: ViewOptions,
}

/// Header options for Issue.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
#[serde(default)]
pub struct HeaderOptions {
    /// `typ`.
    #[cfg_attr(feature = "ts", ts(as = "Option<TypChoice>", optional))]
    pub typ: TypChoice,
    /// `kid`.
    #[cfg_attr(feature = "ts", ts(as = "Option<KidChoice>", optional))]
    pub kid: KidChoice,
    /// JOSE `x5c` (base64 DER), in order.
    #[cfg_attr(feature = "ts", ts(as = "Option<Vec<String>>", optional))]
    pub x5c: Vec<String>,
    /// More protected header members: a JSON object (JOSE) or EDN map
    /// (COSE), appended in order.
    pub extra: Option<String>,
    /// COSE unprotected header extras (EDN map).
    pub unprotected_extra: Option<String>,
}

/// `typ` choice.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TypChoice {
    /// The format default (`tokenator-jose` / `tokenator-cose`: none for a
    /// plain JWT/CWT, 293 for an SD-CWT).
    #[default]
    Auto,
    /// No `typ`.
    Omit,
    /// This value (a media type, or a CoAP content-format number as text
    /// for COSE).
    Value {
        /// The value.
        value: String,
    },
}

/// `kid` choice.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KidChoice {
    /// No kid.
    #[default]
    None,
    /// The signing key's kid, if it has one.
    FromKey,
    /// This kid.
    Value {
        /// The kid.
        kid: KidValue,
    },
}

/// Selective disclosure options for Issue/Redact.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
#[serde(default)]
pub struct SdOptions {
    /// NodeIds of JSON claims to make selectively disclosable (marking a
    /// claim and something inside it gives recursive disclosures). EDN uses
    /// tags 58/62 instead.
    #[cfg_attr(feature = "ts", ts(as = "Option<Vec<NodeId>>", optional))]
    pub marks: Vec<NodeId>,
    /// Decoy digests (JOSE).
    #[cfg_attr(feature = "ts", ts(as = "Option<Vec<DecoyRequest>>", optional))]
    pub decoys: Vec<DecoyRequest>,
    /// SD hash (`_sd_alg` / `sd_alg`).
    pub sd_alg: Option<HashName>,
    /// Fixed salts in creation order: JOSE salt strings, COSE hex.
    #[cfg_attr(feature = "ts", ts(as = "Option<Vec<String>>", optional))]
    pub fixed_salts: Vec<String>,
    /// `_sd` order.
    #[cfg_attr(feature = "ts", ts(as = "Option<DigestOrder>", optional))]
    pub digest_order: DigestOrder,
    /// Issue SD form even if nothing is marked.
    #[cfg_attr(feature = "ts", ts(as = "Option<bool>", optional))]
    pub force_sd: bool,
}

/// Decoys to add at one object or array.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct DecoyRequest {
    /// NodeId of the object or array in the claim set (`""` for the top).
    pub at: NodeId,
    /// How many.
    pub count: u32,
}

/// `_sd` digest order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum DigestOrder {
    /// Sorted (RFC 9901 §4.2.4.1).
    #[default]
    Sorted,
    /// Creation order (reveals claim order).
    Creation,
}

/// Holder confirmation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CnfChoice {
    /// Embed this key's public part (JWK / COSE_Key).
    Key {
        /// The holder key.
        key: KeyRef,
    },
    /// Refer to a kid.
    Kid {
        /// The kid.
        kid: KidValue,
    },
}

/// JOSE serializations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum JoseSerialization {
    /// Compact.
    #[default]
    Compact,
    /// Flattened JWS JSON.
    JsonFlattened,
    /// General JWS JSON.
    JsonGeneral,
}

/// Input of [`Engine::disclose`](crate::Engine::disclose).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
pub struct DiscloseRequest {
    /// The SD credential.
    pub doc: DocRef,
    /// Disclosure indexes to keep, in order.
    pub keep: Vec<u32>,
    /// View options.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<ViewOptions>", optional))]
    pub view: ViewOptions,
}

/// Input of [`Engine::present`](crate::Engine::present).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
pub struct PresentRequest {
    /// The credential (SD-JWT, SD-CWT, or a plain CWT).
    pub doc: DocRef,
    /// Disclosure indexes to keep, in order.
    pub keep: Vec<u32>,
    /// The holder's private key.
    pub holder: KeyRef,
    /// KB alg (JOSE name); derived from the key when absent.
    #[serde(default)]
    pub alg: Option<String>,
    /// `aud`.
    #[serde(default)]
    pub aud: Option<String>,
    /// `nonce` (JOSE, text) / `cnonce` (COSE, bytes).
    #[serde(default)]
    pub nonce: Option<Nonce>,
    /// `iat`.
    pub iat: i64,
    /// 32-byte seed for randomized signatures.
    #[serde(default)]
    pub randomness: Option<Bytes>,
    /// View options.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<ViewOptions>", optional))]
    pub view: ViewOptions,
}

/// Input of [`Engine::validate`](crate::Engine::validate).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
pub struct ValidateRequest {
    /// The credential.
    pub doc: DocRef,
    /// Candidate keys from the panel.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<Vec<KeyRef>>", optional))]
    pub keys: Vec<KeyRef>,
    /// The clock (seconds since the epoch).
    pub now: i64,
    /// Allowed skew in seconds.
    #[serde(default = "default_skew")]
    #[cfg_attr(feature = "ts", ts(as = "Option<u64>", optional))]
    pub skew: u64,
    /// Expected KB `aud`.
    #[serde(default)]
    pub expected_aud: Option<String>,
    /// Expected KB `nonce` / `cnonce`.
    #[serde(default)]
    pub expected_nonce: Option<Nonce>,
    /// Maximum KB `iat` age in seconds.
    #[serde(default)]
    pub max_kb_age: Option<u64>,
}

fn default_skew() -> u64 {
    60
}

impl ValidateRequest {
    /// No keys, skew 60 s, no expectations.
    pub fn new(doc: DocRef, now: i64) -> ValidateRequest {
        ValidateRequest {
            doc,
            keys: Vec::new(),
            now,
            skew: default_skew(),
            expected_aud: None,
            expected_nonce: None,
            max_kb_age: None,
        }
    }
}

/// Input of [`Engine::lint`](crate::Engine::lint).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
pub struct LintRequest {
    /// The document.
    pub doc: DocRef,
    /// Keys to check against the header `alg` (the verifying key).
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<Vec<KeyRef>>", optional))]
    pub keys: Vec<KeyRef>,
}

/// Input of [`Engine::resign`](crate::Engine::resign).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
pub struct ResignRequest {
    /// The (edited) credential.
    pub doc: DocRef,
    /// The signing key.
    pub key: KeyRef,
    /// Sign with this alg (JOSE name) instead of the header alg.
    #[serde(default)]
    pub alg: Option<String>,
    /// 32-byte seed for randomized signatures; deterministic without.
    #[serde(default)]
    pub randomness: Option<Bytes>,
    /// View options.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<ViewOptions>", optional))]
    pub view: ViewOptions,
}

/// Input of [`Engine::tamper`](crate::Engine::tamper).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
pub struct TamperRequest {
    /// The credential.
    pub doc: DocRef,
    /// What to break.
    pub op: TamperOp,
    /// View options.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<ViewOptions>", optional))]
    pub view: ViewOptions,
}

/// A deliberate break (never re-signed).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TamperOp {
    /// Flip bit `bit` (0 = MSB of the first byte) of a part's decoded bytes.
    FlipBit {
        /// Which part.
        part: PartRef,
        /// Bit index.
        bit: u32,
    },
    /// Flip bit `bit` (0..8, 0 = MSB) of byte `offset` of `doc.bytes`.
    FlipByteBit {
        /// Byte offset.
        offset: u32,
        /// Bit in the byte.
        bit: u8,
    },
    /// Set the protected `alg` (JOSE name incl. `none`, or a COSE label).
    SetAlg {
        /// The alg.
        alg: AlgValue,
    },
    /// Remove `alg` (COSE).
    RemoveAlg,
    /// Empty the signature.
    StripSignature,
    /// Set the kid (JOSE: protected header; COSE: unprotected header), or
    /// remove it with `None`.
    SetKid {
        /// The kid.
        kid: Option<KidValue>,
    },
    /// Keep only the first `len` bytes.
    Truncate {
        /// Bytes kept.
        len: u32,
    },
    /// Append a copy of a disclosure.
    DuplicateDisclosure {
        /// Disclosure index.
        index: u32,
    },
    /// Re-encode the protected header equivalently.
    ReencodeProtected {
        /// How (COSE); JOSE always re-formats the JSON.
        how: EquivalentEncoding,
    },
    /// Replace the COSE tags (`[]` drops them).
    SetTags {
        /// Tags, outermost first.
        tags: Vec<u64>,
    },
}

/// A token part.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PartRef {
    /// Protected header.
    Protected,
    /// Unprotected header.
    Unprotected,
    /// Payload.
    Payload,
    /// Signature.
    Signature,
    /// A disclosure.
    Disclosure {
        /// Index.
        index: u32,
    },
    /// KB-JWT protected header.
    KbProtected,
    /// KB-JWT payload.
    KbPayload,
    /// KB-JWT signature.
    KbSignature,
}

/// An algorithm by JOSE name or COSE label.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(untagged)]
pub enum AlgValue {
    /// JOSE name (`ES256`, `none`).
    Name(String),
    /// COSE label (`-7`).
    Label(i64),
}

/// Equivalent re-encodings of a protected header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum EquivalentEncoding {
    /// JOSE: re-formatted JSON; COSE: `wide_integers`.
    #[default]
    Auto,
    /// COSE: widen the bstr head (contents and signature input unchanged).
    WideBstrHead,
    /// COSE: widen integers inside the header map.
    WideIntegers,
    /// COSE: indefinite-length header map.
    IndefiniteMap,
}

/// Input of [`Engine::reencode`](crate::Engine::reencode).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
pub struct ReencodeRequest {
    /// The credential.
    pub doc: DocRef,
    /// Outer layers for the output, outermost first (no `cbor_tag` layers;
    /// use `cose_tags`).
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<Vec<Layer>>", optional))]
    pub layers: Vec<Layer>,
    /// New COSE tags; `None` keeps them.
    #[serde(default)]
    pub cose_tags: Option<Vec<u64>>,
    /// CBOR serialization.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<CborSerialization>", optional))]
    pub cbor: CborSerialization,
    /// Also re-serialize the protected header, payload, and disclosure
    /// contents (may make the signature stale).
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<bool>", optional))]
    pub deep: bool,
    /// New JOSE serialization; `None` keeps it.
    #[serde(default)]
    pub jose: Option<JoseSerialization>,
    /// View options.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<ViewOptions>", optional))]
    pub view: ViewOptions,
}

/// CBOR serializations (draft-ietf-cbor-serialization-11).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum CborSerialization {
    /// As received.
    #[default]
    Preserve,
    /// §4 preferred-plus.
    PreferredPlus,
    /// §5 deterministic.
    Deterministic,
}

/// The result of a re-encode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Reencoded {
    /// The full output, with the new outer layers applied.
    pub output: Bytes,
    /// The re-encoded credential (layers set to the request's).
    pub document: Document,
}

/// Input of [`Engine::edit_disclosures`](crate::Engine::edit_disclosures).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
pub struct EditDisclosuresRequest {
    /// The SD credential.
    pub doc: DocRef,
    /// Edits, applied in order.
    pub ops: Vec<DisclosureOp>,
    /// 32-byte seed for forged salts and random digests.
    #[serde(default)]
    pub randomness: Option<Bytes>,
    /// View options.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<ViewOptions>", optional))]
    pub view: ViewOptions,
}

/// One disclosure edit. Indexes refer to the list as it is when the op runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DisclosureOp {
    /// Remove one.
    Remove {
        /// Index.
        index: u32,
    },
    /// Append a copy.
    Duplicate {
        /// Index.
        index: u32,
    },
    /// Move one.
    Move {
        /// From.
        from: u32,
        /// To.
        to: u32,
    },
    /// Keep these, in this order.
    Select {
        /// Indexes.
        indices: Vec<u32>,
    },
    /// Append an encoded disclosure (JOSE base64url text, COSE hex of the
    /// bstr contents).
    Append {
        /// The encoded disclosure.
        encoded: String,
    },
    /// Append a forged disclosure. `claim` and `value` are JSON (JOSE) or
    /// EDN (COSE) text; no `claim` is an array element; COSE without a
    /// value is a decoy `[salt]`.
    Forge {
        /// Salt (JOSE string, COSE hex); random when absent.
        salt: Option<String>,
        /// Claim name / key.
        claim: Option<String>,
        /// Value.
        value: Option<String>,
    },
    /// Replace a disclosure's value (its digest no longer matches).
    ReplaceValue {
        /// Index.
        index: u32,
        /// JSON / EDN text.
        value: String,
    },
    /// Add a decoy digest at an object or array of the payload (JOSE).
    AddDecoy {
        /// NodeId of the object/array in the decoded payload.
        at: NodeId,
        /// The digest; random when absent.
        digest: Option<String>,
    },
    /// Remove every occurrence of a digest from the payload (JOSE).
    RemoveDigest {
        /// The digest.
        digest: String,
    },
}

/// Input of [`Engine::decode_embedded`](crate::Engine::decode_embedded).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
pub struct DecodeEmbeddedRequest {
    /// The document.
    pub doc: DocRef,
    /// A byte string node.
    pub node_id: NodeId,
    /// View options.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<ViewOptions>", optional))]
    pub view: ViewOptions,
}

/// A manually decoded byte string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct ManualDecode {
    /// EDN of the first data item.
    pub text: String,
    /// Its tree, rooted at `<node_id>/~e`, with ranges into `text` and the
    /// document's raw buffer.
    pub tree: Node,
    /// `cbor.trailing_bytes` and other warnings.
    pub diagnostics: Vec<Diagnostic>,
}
