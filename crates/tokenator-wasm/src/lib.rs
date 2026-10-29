//! wasm-bindgen bindings over the [`tokenator_core::Engine`].
//!
//! One export per Engine method, on the [`TokenatorEngine`] class, with the
//! core method's snake_case name. Requests and responses cross as JSON
//! text in the core wire format (crates/tokenator-core/TEST-PLAN.md §2);
//! raw `detect`/`open` input crosses as a `Uint8Array` (#34). Every method
//! returns a JSON envelope string, never throws for engine errors:
//!
//! ```text
//! {"ok":<response DTO>}                     success
//! {"err":{"code":…,"message":…,"node_id":…}} EngineError (code invalid_input
//!                                            for a request that does not
//!                                            deserialize)
//! ```
//!
//! The envelope is compact `serde_json` output, byte-identical to what the
//! native parity runner (`tools/parity`) writes for the same request.
//! No logic lives here beyond (de)serialization and error mapping.
//!
//! Panics never cross silently: the release build aborts the call with a
//! wasm trap (a `WebAssembly.RuntimeError` in JS, which `WasmEngine` maps
//! to an `EngineFailure` with code `internal`); debug builds also log the
//! message through `console_error_panic_hook`. The stack size is set in
//! `build.rs` (#27). See `TEST-PLAN.md`.

use tokenator_core::{
    AssignKidRequest, Candidate, ConvertClaimsRequest, DateTimeRequest, DecodeEmbeddedRequest,
    DiscloseRequest, EditDisclosuresRequest, EditRequest, Engine, EngineError, ErrorCode,
    IssueRequest, KeyConvertRequest, KeyExportRequest, KeyGenRequest, KeyImportRequest, KeyRef,
    LintRequest, PresentRequest, ReencodeRequest, RegistryMergeRequest, RegistryQuery,
    RenderRequest, ResignRequest, TamperRequest, ThumbprintRequest, ValidateRequest, ViewOptions,
};
use wasm_bindgen::prelude::*;

/// The envelope text of a `Result<impl Serialize, EngineError>`: compact
/// `{"ok":…}` or `{"err":…}`, the same bytes serde writes for an externally
/// tagged enum (what `tools/parity` produces). A macro, so the `Serialize`
/// bound needs no direct serde dependency.
macro_rules! envelope {
    ($result:expr) => {
        serialized(match $result {
            Ok(value) => serde_json::to_string(&value).map(|v| format!(r#"{{"ok":{v}}}"#)),
            Err(e) => serde_json::to_string(&e).map(|v| format!(r#"{{"err":{v}}}"#)),
        })
    };
}

/// DTOs always serialize (string map keys, no custom errors); a failure is
/// a bug, and trapping reports it to JS as `internal`.
#[allow(clippy::panic)]
fn serialized(text: Result<String, serde_json::Error>) -> String {
    text.unwrap_or_else(|e| panic!("tokenator-wasm: cannot serialize the response: {e}"))
}

/// A request of type `$ty` from its JSON text, as `Result<$ty, EngineError>`;
/// a malformed request is `invalid_input`.
macro_rules! parse {
    ($ty:ty, $text:expr) => {
        serde_json::from_str::<$ty>($text)
            .map_err(|e| EngineError::new(ErrorCode::InvalidInput, e.to_string()))
    };
}

/// Installs the panic hook in debug builds.
#[wasm_bindgen(start)]
pub fn start() {
    #[cfg(debug_assertions)]
    console_error_panic_hook::set_once();
}

/// The Engine, holding only its registry (bundled or a refreshed snapshot).
#[wasm_bindgen]
pub struct TokenatorEngine {
    engine: Engine,
}

impl TokenatorEngine {
    /// `Engine::new()` without a snapshot, else
    /// `Engine::with_registry_snapshot`. The error is the `{"err":…}`
    /// envelope text. Usable natively (the tests use it).
    pub fn create(snapshot: Option<&[u8]>) -> Result<TokenatorEngine, String> {
        let engine = match snapshot {
            None => Engine::new(),
            Some(snapshot) => Engine::with_registry_snapshot(snapshot),
        };
        match engine {
            Ok(engine) => Ok(TokenatorEngine { engine }),
            Err(e) => Err(envelope!(Err::<(), _>(e))),
        }
    }

    /// The wrapped core engine.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}

#[wasm_bindgen]
impl TokenatorEngine {
    /// `new TokenatorEngine(snapshot?)`. Throws the `{"err":…}` envelope
    /// text (a JS string) when the snapshot cannot be read.
    #[wasm_bindgen(constructor)]
    pub fn new(snapshot: Option<Box<[u8]>>) -> Result<TokenatorEngine, JsValue> {
        TokenatorEngine::create(snapshot.as_deref()).map_err(|e| JsValue::from_str(&e))
    }

    /// `Engine::info`.
    pub fn info(&self) -> String {
        envelope!(Ok::<_, EngineError>(self.engine.info()))
    }

    /// `Engine::detect` on raw input bytes.
    pub fn detect(&self, input: &[u8]) -> String {
        envelope!(Ok::<_, EngineError>(self.engine.detect(input)))
    }

    /// `Engine::open` on raw input bytes; `candidate` and `view` are JSON.
    pub fn open(&self, input: &[u8], candidate: &str, view: &str) -> String {
        envelope!(parse!(Candidate, candidate).and_then(|candidate| {
            let view = parse!(ViewOptions, view)?;
            self.engine.open(input, &candidate, &view)
        }))
    }

    /// `Engine::render` (`RenderRequest` JSON).
    pub fn render(&self, req: &str) -> String {
        envelope!(parse!(RenderRequest, req).and_then(|r| self.engine.render(&r)))
    }

    /// `Engine::parse_edit` (`EditRequest` JSON). Always `{"ok":…}` for a
    /// well-formed request.
    pub fn parse_edit(&self, req: &str) -> String {
        envelope!(parse!(EditRequest, req).map(|r| self.engine.parse_edit(&r)))
    }

    /// `Engine::convert_claims` (`ConvertClaimsRequest` JSON). Always
    /// `{"ok":…}` for a well-formed request.
    pub fn convert_claims(&self, req: &str) -> String {
        envelope!(parse!(ConvertClaimsRequest, req).map(|r| self.engine.convert_claims(&r)))
    }

    /// `Engine::issue` (`IssueRequest` JSON).
    pub fn issue(&self, req: &str) -> String {
        envelope!(parse!(IssueRequest, req).and_then(|r| self.engine.issue(&r)))
    }

    /// `Engine::redact` (`IssueRequest` JSON).
    pub fn redact(&self, req: &str) -> String {
        envelope!(parse!(IssueRequest, req).and_then(|r| self.engine.redact(&r)))
    }

    /// `Engine::disclose` (`DiscloseRequest` JSON).
    pub fn disclose(&self, req: &str) -> String {
        envelope!(parse!(DiscloseRequest, req).and_then(|r| self.engine.disclose(&r)))
    }

    /// `Engine::present` (`PresentRequest` JSON).
    pub fn present(&self, req: &str) -> String {
        envelope!(parse!(PresentRequest, req).and_then(|r| self.engine.present(&r)))
    }

    /// `Engine::validate` (`ValidateRequest` JSON).
    pub fn validate(&self, req: &str) -> String {
        envelope!(parse!(ValidateRequest, req).and_then(|r| self.engine.validate(&r)))
    }

    /// `Engine::lint` (`LintRequest` JSON).
    pub fn lint(&self, req: &str) -> String {
        envelope!(parse!(LintRequest, req).and_then(|r| self.engine.lint(&r)))
    }

    /// `Engine::resign` (`ResignRequest` JSON).
    pub fn resign(&self, req: &str) -> String {
        envelope!(parse!(ResignRequest, req).and_then(|r| self.engine.resign(&r)))
    }

    /// `Engine::tamper` (`TamperRequest` JSON).
    pub fn tamper(&self, req: &str) -> String {
        envelope!(parse!(TamperRequest, req).and_then(|r| self.engine.tamper(&r)))
    }

    /// `Engine::reencode` (`ReencodeRequest` JSON).
    pub fn reencode(&self, req: &str) -> String {
        envelope!(parse!(ReencodeRequest, req).and_then(|r| self.engine.reencode(&r)))
    }

    /// `Engine::edit_disclosures` (`EditDisclosuresRequest` JSON).
    pub fn edit_disclosures(&self, req: &str) -> String {
        envelope!(
            parse!(EditDisclosuresRequest, req).and_then(|r| self.engine.edit_disclosures(&r))
        )
    }

    /// `Engine::decode_embedded` (`DecodeEmbeddedRequest` JSON).
    pub fn decode_embedded(&self, req: &str) -> String {
        envelope!(parse!(DecodeEmbeddedRequest, req).and_then(|r| self.engine.decode_embedded(&r)))
    }

    /// `Engine::key_import` (`KeyImportRequest` JSON).
    pub fn key_import(&self, req: &str) -> String {
        envelope!(parse!(KeyImportRequest, req).and_then(|r| self.engine.key_import(&r)))
    }

    /// `Engine::key_export` (`KeyExportRequest` JSON).
    pub fn key_export(&self, req: &str) -> String {
        envelope!(parse!(KeyExportRequest, req).and_then(|r| self.engine.key_export(&r)))
    }

    /// `Engine::key_public` (`KeyRef` JSON).
    pub fn key_public(&self, key: &str) -> String {
        envelope!(parse!(KeyRef, key).and_then(|r| self.engine.key_public(&r)))
    }

    /// `Engine::key_generate` (`KeyGenRequest` JSON).
    pub fn key_generate(&self, req: &str) -> String {
        envelope!(parse!(KeyGenRequest, req).and_then(|r| self.engine.key_generate(&r)))
    }

    /// `Engine::key_thumbprint` (`ThumbprintRequest` JSON).
    pub fn key_thumbprint(&self, req: &str) -> String {
        envelope!(parse!(ThumbprintRequest, req).and_then(|r| self.engine.key_thumbprint(&r)))
    }

    /// `Engine::key_assign_kid` (`AssignKidRequest` JSON).
    pub fn key_assign_kid(&self, req: &str) -> String {
        envelope!(parse!(AssignKidRequest, req).and_then(|r| self.engine.key_assign_kid(&r)))
    }

    /// `Engine::key_to_jwk` (`KeyConvertRequest` JSON); `ok` is the JWK
    /// text as a JSON string.
    pub fn key_to_jwk(&self, req: &str) -> String {
        envelope!(parse!(KeyConvertRequest, req).and_then(|r| self.engine.key_to_jwk(&r)))
    }

    /// `Engine::key_to_cwk` (`KeyConvertRequest` JSON).
    pub fn key_to_cwk(&self, req: &str) -> String {
        envelope!(parse!(KeyConvertRequest, req).and_then(|r| self.engine.key_to_cwk(&r)))
    }

    /// `Engine::datetime` (`DateTimeRequest` JSON).
    pub fn datetime(&self, req: &str) -> String {
        envelope!(parse!(DateTimeRequest, req).and_then(|r| self.engine.datetime(&r)))
    }

    /// `Engine::registry_lookup` (`RegistryQuery` JSON).
    pub fn registry_lookup(&self, query: &str) -> String {
        envelope!(parse!(RegistryQuery, query).map(|r| self.engine.registry_lookup(&r)))
    }

    /// `Engine::registry_merge` (`RegistryMergeRequest` JSON).
    pub fn registry_merge(&self, req: &str) -> String {
        envelope!(parse!(RegistryMergeRequest, req).and_then(|r| self.engine.registry_merge(&r)))
    }

    /// A test hook: panics with `message` inside a method call, so tests
    /// can check that a panic surfaces as an error in JS and that the
    /// engine still answers afterwards (TEST-PLAN.md §1). Never called by
    /// the app.
    #[doc(hidden)]
    #[allow(clippy::panic)]
    pub fn panic_for_tests(&self, message: &str) {
        panic!("panic_for_tests: {message}")
    }
}
