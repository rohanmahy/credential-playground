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

use wasm_bindgen::prelude::*;

/// Installs the panic hook in debug builds.
#[wasm_bindgen(start)]
pub fn start() {
    #[cfg(debug_assertions)]
    console_error_panic_hook::set_once();
}

/// The Engine, holding only its registry (bundled or a refreshed snapshot).
#[wasm_bindgen]
pub struct TokenatorEngine {
    engine: tokenator_core::Engine,
}

impl TokenatorEngine {
    /// `Engine::new()` without a snapshot, else
    /// `Engine::with_registry_snapshot`. The error is the `{"err":…}`
    /// envelope text. Usable natively (the tests use it).
    pub fn create(snapshot: Option<&[u8]>) -> Result<TokenatorEngine, String> {
        let _ = snapshot;
        unimplemented!("tokenator-wasm: TokenatorEngine::create")
    }

    /// The wrapped core engine.
    pub fn engine(&self) -> &tokenator_core::Engine {
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
        unimplemented!("tokenator-wasm: info")
    }

    /// `Engine::detect` on raw input bytes.
    pub fn detect(&self, input: &[u8]) -> String {
        let _ = input;
        unimplemented!("tokenator-wasm: detect")
    }

    /// `Engine::open` on raw input bytes; `candidate` and `view` are JSON.
    pub fn open(&self, input: &[u8], candidate: &str, view: &str) -> String {
        let _ = (input, candidate, view);
        unimplemented!("tokenator-wasm: open")
    }

    /// `Engine::render` (`RenderRequest` JSON).
    pub fn render(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: render")
    }

    /// `Engine::parse_edit` (`EditRequest` JSON). Always `{"ok":…}` for a
    /// well-formed request.
    pub fn parse_edit(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: parse_edit")
    }

    /// `Engine::issue` (`IssueRequest` JSON).
    pub fn issue(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: issue")
    }

    /// `Engine::redact` (`IssueRequest` JSON).
    pub fn redact(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: redact")
    }

    /// `Engine::disclose` (`DiscloseRequest` JSON).
    pub fn disclose(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: disclose")
    }

    /// `Engine::present` (`PresentRequest` JSON).
    pub fn present(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: present")
    }

    /// `Engine::validate` (`ValidateRequest` JSON).
    pub fn validate(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: validate")
    }

    /// `Engine::lint` (`LintRequest` JSON).
    pub fn lint(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: lint")
    }

    /// `Engine::resign` (`ResignRequest` JSON).
    pub fn resign(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: resign")
    }

    /// `Engine::tamper` (`TamperRequest` JSON).
    pub fn tamper(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: tamper")
    }

    /// `Engine::reencode` (`ReencodeRequest` JSON).
    pub fn reencode(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: reencode")
    }

    /// `Engine::edit_disclosures` (`EditDisclosuresRequest` JSON).
    pub fn edit_disclosures(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: edit_disclosures")
    }

    /// `Engine::decode_embedded` (`DecodeEmbeddedRequest` JSON).
    pub fn decode_embedded(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: decode_embedded")
    }

    /// `Engine::key_import` (`KeyImportRequest` JSON).
    pub fn key_import(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: key_import")
    }

    /// `Engine::key_export` (`KeyExportRequest` JSON).
    pub fn key_export(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: key_export")
    }

    /// `Engine::key_public` (`KeyRef` JSON).
    pub fn key_public(&self, key: &str) -> String {
        let _ = key;
        unimplemented!("tokenator-wasm: key_public")
    }

    /// `Engine::key_generate` (`KeyGenRequest` JSON).
    pub fn key_generate(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: key_generate")
    }

    /// `Engine::key_thumbprint` (`ThumbprintRequest` JSON).
    pub fn key_thumbprint(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: key_thumbprint")
    }

    /// `Engine::key_assign_kid` (`AssignKidRequest` JSON).
    pub fn key_assign_kid(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: key_assign_kid")
    }

    /// `Engine::key_to_jwk` (`KeyConvertRequest` JSON); `ok` is the JWK
    /// text as a JSON string.
    pub fn key_to_jwk(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: key_to_jwk")
    }

    /// `Engine::key_to_cwk` (`KeyConvertRequest` JSON).
    pub fn key_to_cwk(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: key_to_cwk")
    }

    /// `Engine::datetime` (`DateTimeRequest` JSON).
    pub fn datetime(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: datetime")
    }

    /// `Engine::registry_lookup` (`RegistryQuery` JSON).
    pub fn registry_lookup(&self, query: &str) -> String {
        let _ = query;
        unimplemented!("tokenator-wasm: registry_lookup")
    }

    /// `Engine::registry_merge` (`RegistryMergeRequest` JSON).
    pub fn registry_merge(&self, req: &str) -> String {
        let _ = req;
        unimplemented!("tokenator-wasm: registry_merge")
    }

    /// A test hook: panics with `message` inside a method call, so tests
    /// can check that a panic surfaces as an error in JS and that the
    /// engine still answers afterwards (TEST-PLAN.md §1). Never called by
    /// the app.
    #[doc(hidden)]
    pub fn panic_for_tests(&self, message: &str) {
        let _ = message;
        unimplemented!("tokenator-wasm: panic_for_tests")
    }
}
