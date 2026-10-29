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
//! ```no_run
//! use tokenator_core::{Engine, ValidateRequest, DocRef, ViewOptions};
//!
//! let engine = Engine::new()?;
//! let input = std::fs::read("token.txt").unwrap_or_default();
//! let top = engine.detect(&input).into_iter().next().expect("something");
//! let doc = engine.open(&input, &top, &ViewOptions::default())?;
//! let report = engine.validate(&ValidateRequest::new(DocRef::from(&doc), 1_800_000_000))?;
//! println!("{:?}", report.overall);
//! # Ok::<(), tokenator_core::EngineError>(())
//! ```

mod actions;
mod annotate;
mod cbor;
mod datetime;
mod detect;
pub mod dto;
mod edit;
mod engine;
mod keyring;
mod manipulate;
mod reg;
mod util;
mod validate;
mod view;
#[cfg(feature = "ts")]
pub mod ts;

pub use dto::actions::{
    AlgValue, CborSerialization, CnfChoice, DecodeEmbeddedRequest, DecoyRequest, DigestOrder,
    DiscloseRequest, DisclosureOp, DocRef, EditDisclosuresRequest, EditRequest, EditResult,
    EquivalentEncoding, HeaderOptions, IssueRequest, JoseSerialization, KidChoice, LintRequest,
    ManualDecode, PartRef, PresentRequest, ReencodeRequest, Reencoded, RenderRequest,
    ResignRequest, SdOptions, TamperOp, TamperRequest, TypChoice, ValidateRequest,
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
