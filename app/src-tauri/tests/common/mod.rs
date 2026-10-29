//! Shared helpers: a mock-runtime app running the real command layer with
//! fake dialogs and clipboard, IPC calls, a plain-HTTP test server, and
//! testdata access.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tauri::ipc::{CallbackFn, InvokeBody, InvokeResponseBody};
use tauri::test::{
    INVOKE_KEY, MockRuntime, get_ipc_response, mock_builder, mock_context, noop_assets,
};
use tauri::webview::InvokeRequest;
use tauri::{App, WebviewUrl, WebviewWindow, WebviewWindowBuilder};
use tempfile::TempDir;
use tokenator_desktop::{
    Clipboard, ClipboardState, EngineState, FetchPolicy, Fetcher, FileDialog, Files, PlatformError,
    RegistryCacheFile, Services,
};

/// What the fake dialog was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DialogCall {
    Open(Vec<String>),
    Save(String),
}

/// A dialog that "picks" preset paths and records its calls.
#[derive(Default)]
pub struct FakeDialog {
    pub open_pick: Mutex<Option<PathBuf>>,
    pub save_pick: Mutex<Option<PathBuf>>,
    pub calls: Mutex<Vec<DialogCall>>,
}

struct DialogHandle(Arc<FakeDialog>);

impl FileDialog for DialogHandle {
    fn pick_open(&self, extensions: &[String]) -> Result<Option<PathBuf>, PlatformError> {
        self.0
            .calls
            .lock()
            .unwrap()
            .push(DialogCall::Open(extensions.to_vec()));
        Ok(self.0.open_pick.lock().unwrap().clone())
    }

    fn pick_save(&self, suggested_name: &str) -> Result<Option<PathBuf>, PlatformError> {
        self.0
            .calls
            .lock()
            .unwrap()
            .push(DialogCall::Save(suggested_name.to_owned()));
        Ok(self.0.save_pick.lock().unwrap().clone())
    }
}

/// An in-memory clipboard that records writes (`text`, `sensitive`).
#[derive(Default)]
pub struct FakeClipboard {
    pub text: Mutex<String>,
    pub writes: Mutex<Vec<(String, bool)>>,
}

struct ClipboardHandle(Arc<FakeClipboard>);

impl Clipboard for ClipboardHandle {
    fn read_text(&self) -> Result<String, PlatformError> {
        Ok(self.0.text.lock().unwrap().clone())
    }

    fn write_text(&self, text: &str, sensitive: bool) -> Result<(), PlatformError> {
        *self.0.text.lock().unwrap() = text.to_owned();
        self.0
            .writes
            .lock()
            .unwrap()
            .push((text.to_owned(), sensitive));
        Ok(())
    }
}

/// The policy the tests use: loopback http admitted, short limits.
pub fn test_policy() -> FetchPolicy {
    FetchPolicy {
        timeout: Duration::from_millis(1500),
        connect_timeout: Duration::from_millis(1000),
        max_bytes: 64 * 1024,
        max_redirects: 5,
        allow_loopback_http: true,
    }
}

/// The mock app with the real command layer.
pub struct Harness {
    pub app: App<MockRuntime>,
    pub webview: WebviewWindow<MockRuntime>,
    pub dialog: Arc<FakeDialog>,
    pub clipboard: Arc<FakeClipboard>,
    /// Stands in for the app data dir (the registry cache's dir).
    pub data_dir: TempDir,
}

impl Harness {
    pub fn new() -> Harness {
        Harness::with(test_policy(), Files::DEFAULT_MAX_BYTES)
    }

    pub fn with(policy: FetchPolicy, max_file_bytes: u64) -> Harness {
        let app = tokenator_desktop::register(mock_builder())
            .build(mock_context(noop_assets()))
            .expect("mock app");
        let dialog = Arc::new(FakeDialog::default());
        let clipboard = Arc::new(FakeClipboard::default());
        let data_dir = tempfile::tempdir().unwrap();
        tokenator_desktop::manage(
            &app,
            EngineState::bundled().expect("bundled registry"),
            Services {
                fetcher: Fetcher::new(policy).expect("fetcher"),
                files: Files::new(Box::new(DialogHandle(dialog.clone())), max_file_bytes),
                clipboard: ClipboardState(Box::new(ClipboardHandle(clipboard.clone()))),
                cache: RegistryCacheFile::in_dir(data_dir.path()),
            },
        );
        let webview = WebviewWindowBuilder::new(&app, "main", WebviewUrl::default())
            .build()
            .expect("webview");
        Harness {
            app,
            webview,
            dialog,
            clipboard,
            data_dir,
        }
    }

    /// Invokes `cmd` with JSON `args`; `Ok` is the exact JSON text of the
    /// response body, `Err` the error value.
    pub fn invoke(&self, cmd: &str, args: Value) -> Result<String, Value> {
        invoke_in(&self.webview, cmd, args)
    }

    /// Like [`Harness::invoke`], parsed.
    pub fn call(&self, cmd: &str, args: Value) -> Result<Value, Value> {
        self.invoke(cmd, args)
            .map(|s| serde_json::from_str(&s).unwrap())
    }
}

/// Sends one IPC request from `webview` (local origin).
pub fn invoke_in(
    webview: &WebviewWindow<MockRuntime>,
    cmd: &str,
    args: Value,
) -> Result<String, Value> {
    invoke_from(webview, cmd, args, local_origin())
}

pub fn local_origin() -> &'static str {
    if cfg!(windows) {
        "http://tauri.localhost"
    } else {
        "tauri://localhost"
    }
}

/// Sends one IPC request as if from `origin`.
pub fn invoke_from(
    webview: &WebviewWindow<MockRuntime>,
    cmd: &str,
    args: Value,
    origin: &str,
) -> Result<String, Value> {
    let response = get_ipc_response(
        webview,
        InvokeRequest {
            cmd: cmd.into(),
            callback: CallbackFn(0),
            error: CallbackFn(1),
            url: origin.parse().unwrap(),
            body: InvokeBody::Json(args),
            headers: Default::default(),
            invoke_key: INVOKE_KEY.to_string(),
        },
    );
    response.map(|body| match body {
        InvokeResponseBody::Json(text) => text,
        InvokeResponseBody::Raw(bytes) => {
            panic!("{cmd}: unexpected raw response ({} bytes)", bytes.len())
        }
    })
}

/// Unpadded base64url, as `tokenator_core::Bytes` serializes.
pub fn b64u(bytes: &[u8]) -> Value {
    serde_json::to_value(tokenator_core::Bytes(bytes.to_vec())).unwrap()
}

/// Decodes a base64url JSON string.
pub fn from_b64u(value: &Value) -> Vec<u8> {
    serde_json::from_value::<tokenator_core::Bytes>(value.clone())
        .unwrap()
        .0
}

/// The repository's `testdata/` dir.
pub fn testdata(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(rel)
}

pub fn read_testdata(rel: &str) -> Vec<u8> {
    std::fs::read(testdata(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// This crate's dir (`app/src-tauri`).
pub fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every file under `dir`, relative, sorted.
pub fn files_under(dir: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                out.push(
                    path.strip_prefix(base)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    let mut out = Vec::new();
    if dir.exists() {
        walk(dir, dir, &mut out);
    }
    out.sort();
    out
}

/// What the test server sends for one request.
pub enum Reply {
    /// A response with `Content-Length`.
    Full {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// A 200 without `Content-Length`: `chunks` written one by one, then close.
    Stream { chunks: Vec<Vec<u8>> },
    /// Waits, then replies.
    Delay(Duration, Box<Reply>),
}

impl Reply {
    pub fn ok(content_type: &str, body: impl Into<Vec<u8>>) -> Reply {
        Reply::Full {
            status: 200,
            headers: vec![("Content-Type".into(), content_type.into())],
            body: body.into(),
        }
    }

    pub fn status(status: u16) -> Reply {
        Reply::Full {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn redirect(location: &str) -> Reply {
        Reply::Full {
            status: 302,
            headers: vec![("Location".into(), location.into())],
            body: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Reply {
        if let Reply::Full { headers, .. } = &mut self {
            headers.push((name.into(), value.into()));
        }
        self
    }
}

type Handler = dyn Fn(&str) -> Reply + Send + Sync;

/// A plain HTTP/1.1 server on 127.0.0.1 (std only). The handler gets the
/// request path; every request head is recorded.
pub struct TestServer {
    pub addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
}

impl TestServer {
    pub fn start(handler: impl Fn(&str) -> Reply + Send + Sync + 'static) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let handler: Arc<Handler> = Arc::new(handler);
        let log = requests.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let (handler, log) = (handler.clone(), log.clone());
                std::thread::spawn(move || serve(stream, &*handler, &log));
            }
        });
        TestServer { addr, requests }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    /// The request heads received so far (request line + headers).
    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

fn serve(stream: TcpStream, handler: &Handler, log: &Mutex<Vec<String>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        if line == "\r\n" {
            break;
        }
        head.push_str(&line);
    }
    let path = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
    log.lock().unwrap().push(head);
    write_reply(stream, handler(&path));
}

fn write_reply(mut stream: TcpStream, reply: Reply) {
    match reply {
        Reply::Full {
            status,
            headers,
            body,
        } => {
            let mut out = format!(
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            for (name, value) in headers {
                out.push_str(&format!("{name}: {value}\r\n"));
            }
            out.push_str("\r\n");
            let _ = stream.write_all(out.as_bytes());
            let _ = stream.write_all(&body);
        }
        Reply::Stream { chunks } => {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n");
            for chunk in chunks {
                if stream.write_all(&chunk).is_err() {
                    return;
                }
                let _ = stream.flush();
            }
        }
        Reply::Delay(delay, reply) => {
            std::thread::sleep(delay);
            write_reply(stream, *reply);
        }
    }
}

/// Core-built fixtures (core is the reference the commands must match).
pub struct Fx {
    pub engine: tokenator_core::Engine,
    /// RFC 7515 A.3 (ES256 JWT) and its public key.
    pub jwt: Vec<u8>,
    pub jwt_doc: tokenator_core::Document,
    pub jwt_key: tokenator_core::KeyRef,
    /// RFC 8392 A.3 (signed CWT).
    pub cwt: Vec<u8>,
    pub cwt_doc: tokenator_core::Document,
    /// RFC 9901 §5.1 SD-JWT.
    pub sd_jwt_doc: tokenator_core::Document,
    /// Seeded P-256 issuer and holder keys.
    pub issuer: tokenator_core::KeyInfo,
    pub holder: tokenator_core::KeyInfo,
    /// An SD-CWT issued from EDN with one redacted claim (seeded).
    pub sd_cwt_doc: tokenator_core::Document,
}

pub const RFC7515_A3_KEY: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
pub const SD_CWT_CLAIMS: &str = r#"{1: "https://issuer.example", 2: "alice", 58(500): "secret"}"#;

impl Fx {
    pub fn new() -> Fx {
        use tokenator_core::*;
        let engine = Engine::new().unwrap();
        let open = |bytes: &[u8]| {
            let top = engine
                .detect(bytes)
                .into_iter()
                .next()
                .expect("a candidate");
            engine.open(bytes, &top, &ViewOptions::default()).unwrap()
        };
        let jwt = read_testdata("tokens/rfc7515-a3-jws-es256.txt");
        let cwt = read_testdata("tokens/rfc8392-a3-signed-cwt.cbor");
        let (jwt_doc, cwt_doc) = (open(&jwt), open(&cwt));
        let sd_jwt_doc = open(&read_testdata("tokens/rfc9901-s5.1-sd-jwt.txt"));
        let key = |n: u8| {
            engine
                .key_generate(&KeyGenRequest {
                    spec: KeySpec::P256,
                    role: None,
                    seed: KeySeed::Seed {
                        bytes: Bytes(vec![n; 32]),
                    },
                    kid: None,
                })
                .unwrap()
        };
        let (issuer, holder) = (key(1), key(2));
        let sd_cwt_doc = engine
            .issue(&Fx::issue_request(&issuer, &holder, &engine))
            .unwrap();
        Fx {
            jwt_key: KeyRef::new(RFC7515_A3_KEY.as_bytes()),
            engine,
            jwt,
            jwt_doc,
            cwt,
            cwt_doc,
            sd_jwt_doc,
            issuer,
            holder,
            sd_cwt_doc,
        }
    }

    /// The seeded SD-CWT issuance request.
    pub fn issue_request(
        issuer: &tokenator_core::KeyInfo,
        holder: &tokenator_core::KeyInfo,
        engine: &tokenator_core::Engine,
    ) -> tokenator_core::IssueRequest {
        use tokenator_core::*;
        IssueRequest {
            claims: DocRef::new(Kind::EdnClaims, SD_CWT_CLAIMS.as_bytes().to_vec()),
            issuer: issuer.key.clone(),
            alg: None,
            header: HeaderOptions::default(),
            sd: SdOptions::default(),
            cnf: Some(CnfChoice::Key {
                key: engine.key_public(&holder.key).unwrap().key,
            }),
            jose_serialization: JoseSerialization::Compact,
            cose_tags: None,
            randomness: Some(Bytes(vec![7; 32])),
            view: ViewOptions::default(),
        }
    }
}

/// `serde_json::to_value`, for building IPC args from core DTOs.
pub fn v<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap()
}

/// The exact JSON text Tauri would send for a direct core result: the
/// value for `Ok`, the `EngineError` value for `Err`.
pub fn core_json<T: serde::Serialize>(
    result: Result<T, tokenator_core::EngineError>,
) -> Result<String, Value> {
    result
        .map(|t| serde_json::to_string(&t).unwrap())
        .map_err(|e| v(&e))
}
