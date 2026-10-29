//! Stateless Engine facade for The Tokenator.
//!
//! [`Engine`] is the single entry point used by `tokenator-wasm`, the Tauri
//! commands, and (later) a CLI. It composes the format crates and returns
//! serde DTOs ([`dto`]); it does no I/O, reads no clock, and uses no
//! ambient randomness. Callers pass `now`, 32-byte randomness seeds, and
//! key bytes ([`KeyRef`]) explicitly, so the same inputs always give the
//! same serialized outputs (the WASM/native parity contract).
//!
//! The document model ([`Document`], [`Node`], [`NodeId`]) and the wire
//! conventions are specified in `TEST-PLAN.md`:
//!
//! - NodeIds are paths into what the main pane shows (`payload/~e/iss`,
//!   `protected/~e/1`, `unprotected/17/0/~e`), stable across re-renders
//!   and edits, so both panes can key collapse state on them.
//! - Text ranges are UTF-16 code units; byte ranges are byte offsets.
//! - Bytes are unpadded base64url strings on the wire; JSON is snake_case.
//!
//! Feature `ts` derives `ts_rs::TS` for every DTO and adds [`ts::bindings`].
//!
//! # Examples
//!
//! Paste, detect, open, and validate the RFC 7515 A.3 JWT with its key:
//!
//! ```
//! use tokenator_core::{DocRef, Engine, KeyRef, Kind, Status, ValidateRequest, ViewOptions};
//!
//! let engine = Engine::new()?;
//! let pasted = b"Bearer eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAs\
//!     DQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4G\
//!     awxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
//! let top = engine.detect(pasted).into_iter().next().expect("a candidate");
//! assert_eq!(top.kind, Kind::Jwt);
//! assert_eq!(top.breadcrumb, ["Bearer", "JWT"]);
//!
//! let doc = engine.open(pasted, &top, &ViewOptions::default())?;
//! // The main pane shows the decoded payload verbatim (CRLFs included).
//! let exp = doc.tree.children[1].children[0].children[1].clone();
//! assert_eq!(exp.id.as_str(), "payload/~e/exp");
//! assert_eq!(exp.time.unwrap().rfc3339, "2011-03-22T18:43:00Z");
//!
//! let key = KeyRef::new(&br#"{"kty":"EC","crv":"P-256",
//!     "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
//!     "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#[..]);
//! let mut req = ValidateRequest::new(DocRef::from(&doc), 1_300_819_000);
//! req.keys = vec![key];
//! let report = engine.validate(&req)?;
//! assert_eq!(report.items[0].id, "signature");
//! assert_eq!(report.items[0].status, Status::Pass);
//! assert_eq!(report.overall, Status::Pass);
//! # Ok::<(), tokenator_core::EngineError>(())
//! ```
//!
//! Issue an SD-CWT from EDN with a redacted claim, present it in an SD-KBT
//! to a verifier, and validate the presentation. Keys and randomness are
//! seeded, so the output is reproducible:
//!
//! ```
//! use tokenator_core::*;
//!
//! let engine = Engine::new()?;
//! let key = |n: u8| {
//!     engine.key_generate(&KeyGenRequest {
//!         spec: KeySpec::P256,
//!         role: None,
//!         seed: KeySeed::Seed { bytes: Bytes(vec![n; 32]) },
//!         kid: None,
//!     })
//! };
//! let (issuer, holder) = (key(1)?, key(2)?);
//!
//! // 58(…) marks a claim key to redact (draft-ietf-spice-sd-cwt §11.1).
//! let claims = r#"{1: "https://issuer.example", 2: "alice", 58(500): "secret"}"#;
//! let sd_cwt = engine.issue(&IssueRequest {
//!     claims: DocRef::new(Kind::EdnClaims, claims.as_bytes().to_vec()),
//!     issuer: issuer.key.clone(),
//!     alg: None, // ES256, from the key
//!     header: HeaderOptions::default(),
//!     sd: SdOptions::default(),
//!     cnf: Some(CnfChoice::Key { key: engine.key_public(&holder.key)?.key }),
//!     jose_serialization: JoseSerialization::Compact,
//!     cose_tags: None, // tag 18
//!     randomness: Some(Bytes(vec![7; 32])),
//!     view: ViewOptions::default(),
//! })?;
//! assert_eq!(sd_cwt.kind, Kind::SdCwt);
//! assert_eq!(sd_cwt.disclosures[0].claim.as_deref(), Some("500"));
//!
//! let kbt = engine.present(&PresentRequest {
//!     doc: DocRef::from(&sd_cwt),
//!     keep: vec![0],
//!     holder: holder.key.clone(),
//!     alg: None,
//!     aud: Some("https://verifier.example".into()),
//!     nonce: Some(Nonce::Bytes { value: Bytes(b"n-1".to_vec()) }),
//!     iat: 1_800_000_000,
//!     randomness: None, // deterministic signatures (RFC 6979)
//!     view: ViewOptions::default(),
//! })?;
//! assert_eq!(kbt.kind, Kind::SdKbt);
//!
//! let mut req = ValidateRequest::new(DocRef::from(&kbt), 1_800_000_010);
//! req.keys = vec![engine.key_public(&issuer.key)?.key];
//! req.expected_aud = Some("https://verifier.example".into());
//! req.expected_nonce = Some(Nonce::Bytes { value: Bytes(b"n-1".to_vec()) });
//! let report = engine.validate(&req)?;
//! let status = |id: &str| report.items.iter().find(|i| i.id == id).map(|i| i.status);
//! assert_eq!(status("signature"), Some(Status::Pass));
//! assert_eq!(status("sd.match"), Some(Status::Pass));
//! assert_eq!(status("kb.signature"), Some(Status::Pass));
//! assert_eq!(status("kb.nonce"), Some(Status::Pass));
//! assert!(report.items.iter().all(|i| i.status != Status::Fail));
//! # Ok::<(), tokenator_core::EngineError>(())
//! ```

mod actions;
mod annotate;
mod cbor;
mod convert;
mod datetime;
mod detect;
pub mod dto;
mod edit;
mod engine;
mod keyring;
mod manipulate;
mod reg;
#[cfg(feature = "ts")]
pub mod ts;
mod util;
mod validate;
mod view;

pub use dto::actions::{
    AlgValue, CborSerialization, CnfChoice, ConvertClaimsRequest, ConvertClaimsResult,
    DecodeEmbeddedRequest, DecoyRequest, DigestOrder, DiscloseRequest, DisclosureOp, DocRef,
    EditDisclosuresRequest, EditRequest, EditResult, EquivalentEncoding, HeaderOptions,
    IssueRequest, JoseSerialization, KidChoice, LintRequest, ManualDecode, PartRef, PresentRequest,
    ReencodeRequest, Reencoded, RenderRequest, ResignRequest, SdOptions, TamperOp, TamperRequest,
    TypChoice, ValidateRequest,
};
pub use dto::common::{
    ByteRange, Bytes, HashName, KidValue, NodeId, Nonce, RawRange, TextRange, escape_segment,
    unescape_segment,
};
pub use dto::datetime::{
    DateFormKind, DateTimeFormView, DateTimeForms, DateTimeInput, DateTimeRequest,
};
pub use dto::detect::{Candidate, Family, JsonPathSegment, Kind, Layer};
pub use dto::document::{
    Annotation, ByteStyle, Diagnostic, DisclosureInfo, DisclosureStatus, Document, HexRow,
    HexRowKind, JsonLayout, Language, Layout, Node, NodeKind, RawView, Rendered, SdMark, Segment,
    Severity, SlotInfo, SpecLink, TimeHint, ViewOptions,
};
pub use dto::error::{EngineError, ErrorCode};
pub use dto::keys::{
    AssignKidRequest, KeyConvertRequest, KeyExport, KeyExportRequest, KeyFormat, KeyGenRequest,
    KeyImportRequest, KeyInfo, KeyRef, KeySeed, KeySpec, KidSource, PemEncoding, Role, Thumbprint,
    ThumbprintKind, ThumbprintRequest, Visibility,
};
pub use dto::registry::{
    EngineInfo, RegistryEntry, RegistryId, RegistryKind, RegistryLabel, RegistryMergeRequest,
    RegistryMergeResult, RegistryQuery, RegistrySource, RegistryStats,
};
pub use dto::report::{
    Category, CheckDetail, CheckItem, FetchHint, FetchKind, KeySelection, Status, ValidationReport,
};
pub use engine::Engine;
