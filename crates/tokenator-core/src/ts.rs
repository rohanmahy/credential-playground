//! TypeScript declarations for every DTO (feature `ts`).
//!
//! Pure: nothing is written to disk. A build step (or the wasm crate)
//! writes [`bindings`] to `app/src/lib/engine/types/`.

use ts_rs::{Config, TS};

use crate::dto::actions::*;
use crate::dto::common::*;
use crate::dto::datetime::*;
use crate::dto::detect::*;
use crate::dto::document::*;
use crate::dto::error::*;
use crate::dto::keys::*;
use crate::dto::registry::*;
use crate::dto::report::*;

/// The ts-rs configuration: `i64`/`u64` are `number` (times and tags).
pub fn config() -> Config {
    Config::new().with_large_int("number")
}

/// `(type name, TypeScript declaration)` for every exported DTO, in a fixed
/// order. Each declaration is `export type Name = …;` (or `export interface`).
pub fn bindings() -> Vec<(String, String)> {
    let cfg = config();
    let mut out = Vec::new();
    macro_rules! decl {
        ($($t:ty),* $(,)?) => {
            $( out.push((<$t as TS>::name(&cfg), format!("export {}", <$t as TS>::decl(&cfg)))); )*
        };
    }
    decl!(
        // common
        Bytes,
        NodeId,
        TextRange,
        ByteRange,
        RawRange,
        Nonce,
        KidValue,
        HashName,
        // detect
        Kind,
        Family,
        Layer,
        JsonPathSegment,
        Candidate,
        // document
        Document,
        Rendered,
        Language,
        Node,
        NodeKind,
        Annotation,
        SpecLink,
        TimeHint,
        SdMark,
        DisclosureInfo,
        DisclosureStatus,
        SlotInfo,
        Diagnostic,
        Severity,
        RawView,
        HexRow,
        HexRowKind,
        Segment,
        ViewOptions,
        Layout,
        ByteStyle,
        JsonLayout,
        // report
        ValidationReport,
        CheckItem,
        Status,
        Category,
        CheckDetail,
        KeySelection,
        FetchHint,
        FetchKind,
        // actions
        DocRef,
        RenderRequest,
        EditRequest,
        EditResult,
        IssueRequest,
        HeaderOptions,
        TypChoice,
        KidChoice,
        SdOptions,
        DecoyRequest,
        DigestOrder,
        CnfChoice,
        JoseSerialization,
        DiscloseRequest,
        PresentRequest,
        ValidateRequest,
        LintRequest,
        ResignRequest,
        TamperRequest,
        TamperOp,
        PartRef,
        AlgValue,
        EquivalentEncoding,
        ReencodeRequest,
        CborSerialization,
        Reencoded,
        EditDisclosuresRequest,
        DisclosureOp,
        DecodeEmbeddedRequest,
        ManualDecode,
        ConvertClaimsRequest,
        ConvertClaimsResult,
        // keys
        KeyRef,
        KeyFormat,
        PemEncoding,
        Role,
        Visibility,
        KeyInfo,
        KeyImportRequest,
        KeyExportRequest,
        KeyExport,
        KeyGenRequest,
        KeySpec,
        KeySeed,
        KidSource,
        ThumbprintRequest,
        ThumbprintKind,
        Thumbprint,
        AssignKidRequest,
        KeyConvertRequest,
        // datetime
        DateTimeRequest,
        DateTimeInput,
        DateTimeForms,
        DateTimeFormView,
        DateFormKind,
        // registry
        RegistryQuery,
        RegistryKind,
        RegistryLabel,
        RegistryEntry,
        RegistrySource,
        RegistryId,
        RegistryMergeRequest,
        RegistryMergeResult,
        RegistryStats,
        EngineInfo,
        // errors
        EngineError,
        ErrorCode,
    );
    out
}
