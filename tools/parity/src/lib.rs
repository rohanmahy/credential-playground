//! The WASM ↔ native parity corpus (SPEC §11, `crates/tokenator-wasm/TEST-PLAN.md` §3).
//!
//! A corpus case is one Engine call with fixed inputs: seeds, `now`, and
//! keys all come from the request, built from `testdata/tokens/` and
//! `testdata/keys/` by [`corpus::build`]. Each case is stored as
//! `testdata/parity/cases/<id>.json` ([`Case`]); its golden is
//! `testdata/parity/expected/<id>.json`, the exact response envelope the
//! native engine produced:
//!
//! ```text
//! {"ok":<response DTO>}  or  {"err":<EngineError>}   (compact serde_json)
//! ```
//!
//! Goldens longer than [`DIGEST_OVER`] bytes (max-depth documents, registry
//! snapshots) are stored as `expected/<id>.sha256` instead, holding
//! `<sha256 hex> <length>\n` of the envelope text ([`Golden::Digest`]).
//!
//! `tokenator-wasm` returns the same envelope text from every binding, so
//! the wasm half of the suite (`app/src/test/wasm/parity.test.ts`) compares
//! strings byte for byte (or their SHA-256 and length).

pub mod corpus;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokenator_core::{
    AssignKidRequest, Candidate, ConvertClaimsRequest, DateTimeRequest, DecodeEmbeddedRequest,
    DiscloseRequest, EditDisclosuresRequest, EditRequest, Engine, EngineError, IssueRequest,
    KeyConvertRequest, KeyExportRequest, KeyGenRequest, KeyImportRequest, KeyRef, LintRequest,
    PresentRequest, ReencodeRequest, RegistryMergeRequest, RegistryQuery, RenderRequest,
    ResignRequest, TamperRequest, ThumbprintRequest, ValidateRequest, ViewOptions,
};

/// Every Engine method, by its core name (which is also the binding name
/// on `TokenatorEngine`).
pub const METHODS: [&str; 28] = [
    "info",
    "detect",
    "open",
    "render",
    "parse_edit",
    "convert_claims",
    "issue",
    "redact",
    "disclose",
    "present",
    "validate",
    "lint",
    "resign",
    "tamper",
    "reencode",
    "edit_disclosures",
    "decode_embedded",
    "key_import",
    "key_export",
    "key_public",
    "key_generate",
    "key_thumbprint",
    "key_assign_kid",
    "key_to_jwk",
    "key_to_cwk",
    "datetime",
    "registry_lookup",
    "registry_merge",
];

/// One positional argument of a binding call.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arg {
    /// Raw input (`detect`/`open`): unpadded base64url here, a `Uint8Array`
    /// at the wasm boundary.
    Bytes(String),
    /// A request DTO: passed to the binding as `JSON.stringify(value)`.
    Json(serde_json::Value),
}

/// One corpus case: an Engine call.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Case {
    /// The Engine method ([`METHODS`]).
    pub method: String,
    /// Where the inputs come from (fixture paths, or how they were built).
    pub source: String,
    /// Part of the stack audit (#27): must run in the release wasm build
    /// under the configured stack without trapping.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stack: bool,
    /// The binding's arguments, in order.
    pub args: Vec<Arg>,
}

/// The response envelope (see the crate docs).
#[derive(Serialize)]
enum Envelope<'a, T: Serialize> {
    #[serde(rename = "ok")]
    Ok(&'a T),
    #[serde(rename = "err")]
    Err(&'a EngineError),
}

/// The envelope text of a successful call.
pub fn ok<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(&Envelope::Ok(value)).map_err(|e| e.to_string())
}

/// The envelope text of a call's result.
pub fn envelope<T: Serialize>(result: &Result<T, EngineError>) -> Result<String, String> {
    match result {
        Ok(v) => ok(v),
        Err(e) => serde_json::to_string(&Envelope::<()>::Err(e)).map_err(|e| e.to_string()),
    }
}

impl Case {
    fn bytes(&self, i: usize) -> Result<Vec<u8>, String> {
        match self.args.get(i) {
            Some(Arg::Bytes(s)) => {
                Base64UrlUnpadded::decode_vec(s).map_err(|e| format!("arg {i}: {e}"))
            }
            other => Err(format!("arg {i}: expected bytes, got {other:?}")),
        }
    }

    fn json<T: DeserializeOwned>(&self, i: usize) -> Result<T, String> {
        match self.args.get(i) {
            Some(Arg::Json(v)) => {
                // Deserialize from text, as the binding does.
                let text = serde_json::to_string(v).map_err(|e| e.to_string())?;
                serde_json::from_str(&text).map_err(|e| format!("arg {i}: {e}"))
            }
            other => Err(format!("arg {i}: expected json, got {other:?}")),
        }
    }

    /// Runs the case through the native engine and returns the envelope.
    pub fn run(&self, e: &Engine) -> Result<String, String> {
        match self.method.as_str() {
            "info" => ok(&e.info()),
            "detect" => ok(&e.detect(&self.bytes(0)?)),
            "open" => envelope(&e.open(
                &self.bytes(0)?,
                &self.json::<Candidate>(1)?,
                &self.json::<ViewOptions>(2)?,
            )),
            "render" => envelope(&e.render(&self.json::<RenderRequest>(0)?)),
            "parse_edit" => ok(&e.parse_edit(&self.json::<EditRequest>(0)?)),
            "convert_claims" => ok(&e.convert_claims(&self.json::<ConvertClaimsRequest>(0)?)),
            "issue" => envelope(&e.issue(&self.json::<IssueRequest>(0)?)),
            "redact" => envelope(&e.redact(&self.json::<IssueRequest>(0)?)),
            "disclose" => envelope(&e.disclose(&self.json::<DiscloseRequest>(0)?)),
            "present" => envelope(&e.present(&self.json::<PresentRequest>(0)?)),
            "validate" => envelope(&e.validate(&self.json::<ValidateRequest>(0)?)),
            "lint" => envelope(&e.lint(&self.json::<LintRequest>(0)?)),
            "resign" => envelope(&e.resign(&self.json::<ResignRequest>(0)?)),
            "tamper" => envelope(&e.tamper(&self.json::<TamperRequest>(0)?)),
            "reencode" => envelope(&e.reencode(&self.json::<ReencodeRequest>(0)?)),
            "edit_disclosures" => {
                envelope(&e.edit_disclosures(&self.json::<EditDisclosuresRequest>(0)?))
            }
            "decode_embedded" => {
                envelope(&e.decode_embedded(&self.json::<DecodeEmbeddedRequest>(0)?))
            }
            "key_import" => envelope(&e.key_import(&self.json::<KeyImportRequest>(0)?)),
            "key_export" => envelope(&e.key_export(&self.json::<KeyExportRequest>(0)?)),
            "key_public" => envelope(&e.key_public(&self.json::<KeyRef>(0)?)),
            "key_generate" => envelope(&e.key_generate(&self.json::<KeyGenRequest>(0)?)),
            "key_thumbprint" => envelope(&e.key_thumbprint(&self.json::<ThumbprintRequest>(0)?)),
            "key_assign_kid" => envelope(&e.key_assign_kid(&self.json::<AssignKidRequest>(0)?)),
            "key_to_jwk" => envelope(&e.key_to_jwk(&self.json::<KeyConvertRequest>(0)?)),
            "key_to_cwk" => envelope(&e.key_to_cwk(&self.json::<KeyConvertRequest>(0)?)),
            "datetime" => envelope(&e.datetime(&self.json::<DateTimeRequest>(0)?)),
            "registry_lookup" => ok(&e.registry_lookup(&self.json::<RegistryQuery>(0)?)),
            "registry_merge" => envelope(&e.registry_merge(&self.json::<RegistryMergeRequest>(0)?)),
            other => Err(format!("unknown method {other}")),
        }
    }
}

/// `testdata/` of this repository.
pub fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

/// `testdata/parity/`.
pub fn parity_dir() -> PathBuf {
    testdata().join("parity")
}

/// The committed corpus: id → case, in id order.
pub fn read_cases(dir: &Path) -> Result<BTreeMap<String, Case>, String> {
    let mut out = BTreeMap::new();
    for (id, text) in read_dir_json(&dir.join("cases"))? {
        let case: Case = serde_json::from_str(&text).map_err(|e| format!("{id}: {e}"))?;
        out.insert(id, case);
    }
    Ok(out)
}

/// Goldens longer than this are stored as a digest.
pub const DIGEST_OVER: usize = 32 * 1024;

/// A committed golden.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Golden {
    /// `expected/<id>.json`: the exact envelope text.
    Text(String),
    /// `expected/<id>.sha256`: SHA-256 (hex) and length of the envelope.
    Digest {
        /// SHA-256 of the envelope text, lower-case hex.
        sha256: String,
        /// Length of the envelope text in bytes.
        len: usize,
    },
}

impl Golden {
    /// The golden for an envelope text.
    pub fn of(out: &str) -> Golden {
        if out.len() > DIGEST_OVER {
            Golden::Digest {
                sha256: sha256_hex(out.as_bytes()),
                len: out.len(),
            }
        } else {
            Golden::Text(out.to_owned())
        }
    }

    /// The file name (under `expected/`) and contents.
    pub fn file(&self, id: &str) -> (String, String) {
        match self {
            Golden::Text(t) => (format!("{id}.json"), t.clone()),
            Golden::Digest { sha256, len } => (format!("{id}.sha256"), format!("{sha256} {len}\n")),
        }
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The committed goldens by id.
pub fn read_expected(dir: &Path) -> Result<BTreeMap<String, Golden>, String> {
    let mut out: BTreeMap<String, Golden> = read_dir_ext(&dir.join("expected"), ".json")?
        .into_iter()
        .map(|(id, t)| (id, Golden::Text(t)))
        .collect();
    for (id, text) in read_dir_ext(&dir.join("expected"), ".sha256")? {
        let mut parts = text.split_whitespace();
        let (Some(sha256), Some(len)) = (parts.next(), parts.next()) else {
            return Err(format!("{id}.sha256: expected `<sha256> <len>`"));
        };
        let len = len.parse().map_err(|e| format!("{id}.sha256: {e}"))?;
        let digest = Golden::Digest {
            sha256: sha256.to_owned(),
            len,
        };
        if out.insert(id.clone(), digest).is_some() {
            return Err(format!("{id}: both .json and .sha256 goldens"));
        }
    }
    Ok(out)
}

fn read_dir_json(dir: &Path) -> Result<Vec<(String, String)>, String> {
    read_dir_ext(dir, ".json")
}

fn read_dir_ext(dir: &Path, ext: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        let Some(id) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(ext))
        else {
            continue;
        };
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        out.push((id.to_owned(), text));
    }
    out.sort();
    Ok(out)
}

/// The text a case file holds (pretty JSON, trailing newline).
pub fn case_text(case: &Case) -> Result<String, String> {
    serde_json::to_string_pretty(case)
        .map(|s| s + "\n")
        .map_err(|e| e.to_string())
}

/// Runs `f` on a thread with a large stack: debug builds of the deep
/// (stack audit) cases need more than the default 2 MiB test thread.
pub fn with_big_stack<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(f)
        .map_err(|e| e.to_string())?
        .join()
        .map_err(|_| "parity thread panicked".to_owned())
}
