# app/src-tauri test plan

`app/src-tauri` is the macOS desktop shell: a Tauri 2 app that exposes
`tokenator-core` as native commands (the desktop `Engine`) and does the
desktop side effects (the desktop `Platform`). It must add no logic of its
own to the engine, persist nothing but the registry cache (SPEC §1, §7), and
let the webview do as little as possible (SPEC §9). This file is the
contract for the implementer; the tests pin it.

## Layout and design

| Path | What |
|---|---|
| `Cargo.toml` | package `tokenator-desktop` (lib `tokenator_desktop`, bin `tokenator`), a member of the root Cargo workspace |
| `build.rs` | `tauri_build` with an explicit app manifest, so every command needs a permission |
| `tauri.conf.json` | product name, identifier, window, CSP, bundle (`.app`) |
| `capabilities/main.json` | the only capability: the `main` window, local content, our commands |
| `src/lib.rs` | `run()` (plugins + `setup`), and `register(builder)` (state + invoke handler) that the tests reuse with the mock runtime |
| `src/engine.rs` | `EngineState` and one `engine_*` command per `tokenator_core::Engine` method, plus `engine_init` |
| `src/fetch.rs` | `Fetcher` (reqwest + rustls) and its `FetchPolicy` |
| `src/files.rs` | `open_file` / `save_file` over a `FileDialog` trait |
| `src/clipboard.rs` | `read_clipboard` / `write_clipboard` over a `Clipboard` trait |
| `src/cache.rs` | `RegistryCacheFile`: the one file in the app data dir |
| `src/error.rs` | `PlatformError` (the wire error of every non-engine command) |

**Workspace member.** `app/src-tauri` is listed in the root
`[workspace] members`: it depends on `tokenator-core` by path, shares
`Cargo.lock` (one resolution for the crypto crates, so native parity is
about the same code), and shares `target/`. Tauri's CLI supports workspace
members. The cost is that `cargo build --workspace` on Linux needs the
WebKitGTK development packages; CI that only wants the crates can use
`--exclude tokenator-desktop` (see the issue).

**Thin commands.** Each engine command takes the core request DTO(s) with
the core parameter names (`req`, `input`, `candidate`, `view`, `key`,
`query`), calls the same-named `Engine` method on the current engine, and
returns the DTO or the core `EngineError` unchanged. Commands use
`rename_all = "snake_case"`, so the IPC argument keys match the Rust names.
They are `async`, so long calls (RSA-4096 or ML-DSA keygen) run off the main
thread, which is also why the infallible core methods return
`Result<_, EngineError>` at the command layer (Tauri requires it for async
commands that borrow `State`).

**Raw input bytes (#34 item 2).** `detect` and `open` take the raw input as
an unpadded base64url string (core `Bytes`), the same encoding as every
other byte field. Tauri's raw binary IPC carries a single body per call, and
`open` needs three arguments; base64url also keeps the WASM and Tauri
wrappers identical. Inputs are token-sized, so the 4/3 overhead does not
matter.

**Registry snapshot.** `EngineState` holds `RwLock<Arc<Engine>>`.
`engine_init { snapshot: Bytes | null }` replaces it with
`Engine::with_registry_snapshot(snapshot)` or `Engine::new()`. On error the
previous engine stays and the command returns the `EngineError` (code
`registry`). `TauriEngine` calls `engine_init` once, before its first
engine call, with the snapshot it was constructed with (also `null`, so a
reloaded webview never inherits an older snapshot). After _Update
registries_, building a new `TauriEngine(snapshot)` swaps the shell's
engine.

**No dialog, clipboard, or fs permissions for the webview.** The webview
never names a path. `open_file` and `save_file` show the native dialog from
Rust (dialog plugin, `DialogExt`) and read or write exactly the picked file
with `std::fs`, so no fs plugin and no fs scope exist at all. The clipboard
plugin is likewise used from Rust only. The capability therefore grants only
our own `allow-*` command permissions; no `core:*`, `dialog:*`,
`clipboard-manager:*`, `fs:*`, `shell:*`, or `http:*` permission.

**`now` and `random_bytes` are not commands.** `Platform.now()` and
`Platform.randomBytes()` are synchronous in the TS interface, so an `invoke`
cannot serve them. `TauriPlatform` keeps `Date.now()` and
`crypto.getRandomValues()` (WKWebView backs it with the OS CSPRNG). Adding
unused commands would only widen the IPC surface (see the issue).

## Commands

Engine (one per method; 27 + `engine_init`):

| Command | Arguments (IPC keys) | Core call |
|---|---|---|
| `engine_init` | `snapshot: Bytes \| null` | `Engine::with_registry_snapshot` / `Engine::new` |
| `engine_info` | — | `info` |
| `engine_detect` | `input: Bytes` | `detect` |
| `engine_open` | `input: Bytes, candidate, view` | `open` |
| `engine_render`, `engine_parse_edit`, `engine_issue`, `engine_redact`, `engine_disclose`, `engine_present`, `engine_validate`, `engine_lint`, `engine_resign`, `engine_tamper`, `engine_reencode`, `engine_edit_disclosures`, `engine_decode_embedded`, `engine_key_import`, `engine_key_export`, `engine_key_generate`, `engine_key_thumbprint`, `engine_key_assign_kid`, `engine_key_to_jwk`, `engine_key_to_cwk`, `engine_datetime`, `engine_registry_merge` | `req` | same name |
| `engine_key_public` | `key: KeyRef` | `key_public` |
| `engine_registry_lookup` | `query: RegistryQuery` | `registry_lookup` |

Errors: the serialized core `EngineError` (`{code, message, node_id}`).

Platform:

| Command | Arguments | Returns | Notes |
|---|---|---|---|
| `fetch_url` | `url` | `{url, status, content_type, bytes}` | https only (also after redirects), no cookies, no referrer, timeout, size cap |
| `open_file` | `accept: string[] \| null` | `{name, bytes} \| null` | native dialog; reads only the picked file; size cap |
| `save_file` | `suggested_name, data: Bytes` | `bool` | native dialog; writes only the picked file |
| `read_clipboard` | — | `string` | clipboard plugin from Rust |
| `write_clipboard` | `text, sensitive` | — | `sensitive` is accepted; no expiry yet (see the issue) |
| `registry_cache_get` | — | `Bytes \| null` | `<app data dir>/registry-snapshot.bin` |
| `registry_cache_put` | `snapshot: Bytes` | — | atomic: temp file in the same dir, then rename |
| `registry_cache_clear` | — | — | removes the file; no error if absent |

Platform errors are `PlatformError {kind, message, url, status}` with
`kind` one of `blocked`, `network`, `http` (the TS `FetchErrorKind`s the
desktop can produce), `io`, `dialog`, `clipboard`, `invalid_argument`.

**Fetch policy** (`FetchPolicy::default()`): scheme `https` only (any other
scheme, or a redirect to one, is `blocked` before connecting); at most 5
redirects; total timeout 30 s, connect timeout 10 s (`network`); body cap
8 MiB, checked against `Content-Length` and while streaming (`blocked`,
"larger than 8 MiB"); non-2xx is `http` with the status; no cookie store
(reqwest built without `cookies`), `referer(false)`, no auth, no default
headers beyond a `User-Agent` of `the-tokenator/<version>`. `rustls` with
the platform verifier (macOS trust store). The tests use
`FetchPolicy { allow_loopback_http: true, .. }` with short limits against a
local plain-HTTP server; `allow_loopback_http` only admits `http://127.0.0.1`
and `http://[::1]` and is never set by `run()`. "Only on explicit user
action" is enforced in the UI (app TEST-PLAN, `fetch` tests); the shell
cannot tell a click from a script, which is why the webview's CSP and the
capability are locked down.

## Test files

Rust (`cargo test -p tokenator-desktop`):

| File | Tests |
|---|---|
| `tests/common/mod.rs` | mock app (`tauri::test::mock_builder()` + `register`), `invoke(cmd, args) -> Result<String, Value>` through `get_ipc_response`, fake dialog and clipboard, the plain-HTTP test server (std `TcpListener`, no extra crate), testdata helpers |
| `tests/engine_commands.rs` | every engine command delegates to core (same JSON as calling core); the argument keys are snake_case; `EngineError` comes back unchanged as the error value; malformed args are rejected without panicking; `engine_init` with a merged snapshot changes `info`/`registry_lookup`, `null` restores the bundled registry, a bad snapshot keeps the previous engine |
| `tests/parity.rs` | a corpus of requests (detect/open of every `testdata/tokens` sample, seeded key generation, issue/present/validate, keys, datetime, registry, error cases) through IPC vs `serde_json::to_string` of the direct core call: byte-identical |
| `tests/fetch.rs` | https-only (http, file, data, ftp, invalid URL → `blocked` without a connection); redirects to http blocked; size cap by `Content-Length` and by streaming; timeout; non-2xx → `http`; no `Cookie` even after `Set-Cookie`; no `Referer`; final URL, status, content type, and bytes reported; the `fetch_url` command maps to `PlatformError` |
| `tests/files.rs` | `open_file` reads exactly the picked file (name and bytes), cancel → `null`, size cap, `accept` → dialog extension filters; `save_file` writes exactly the picked file, cancel → `false`; no command takes a path argument (an extra `path` key is ignored) |
| `tests/clipboard.rs` | read and write through the `Clipboard` backend; `sensitive` passed through |
| `tests/cache.rs` | location is `<dir>/registry-snapshot.bin`; get on empty → `null`; put/get round trip; put replaces atomically (no temp file left); clear; after a full session of commands the data dir contains only that file |
| `tests/config.rs` | `tauri.conf.json`: product name, identifier, `withGlobalTauri` false, one window `main` with a local URL and `incognito`, CSP directives, bundle target `app`, no updater/shell plugin config; `capabilities/`: exactly one file, `windows: ["main"]`, no `remote`, permissions exactly the expected set; `build.rs` manifest lists the same commands as `generate_handler!` |
| `tests/hygiene.rs` | no logging in the command layer (`println!`, `eprintln!`, `dbg!`, `log::`, `tracing::`, `{:?}` of requests); no `log`/`tracing`/`tauri-plugin-log`/fs/shell/http plugin in `Cargo.toml`; tauri built without its `tracing` feature; reqwest without `cookies`/`native-tls`; no `std::fs` outside `files.rs` and `cache.rs` |

TS (`pnpm test`, Vitest, `@tauri-apps/api/mocks` `mockIPC`):

| File | Tests |
|---|---|
| `src/test/unit/tauriEngine.test.ts` | each of the 27 methods invokes `engine_<snake>` with the right argument object; `Uint8Array` input → base64url; `engine_init` runs once before the first call, with the snapshot as base64url or `null`; an `EngineError` rejection becomes `EngineFailure` (code, message, node_id kept); a string rejection (Tauri arg error) becomes `EngineFailure` with code `invalid_input`; an `engine_init` failure rejects calls with `EngineFailure` |
| `src/test/unit/tauriPlatform.test.ts` | `fetchUrl` → `fetch_url` and decodes bytes; `PlatformError` kinds → `FetchError(kind, url, message, status)`; `openFile` passes `accept`, decodes, `null` on cancel; `saveFile` encodes strings as UTF-8 and bytes as base64url; clipboard read/write with `sensitive`; registry cache get/put/clear; `now`/`randomBytes` stay local (no invoke) |
| `src/test/unit/tauriConfig.test.ts` | the Tauri CSP equals the web CSP (`csp.config.ts`) except `script-src 'self'` (no `'wasm-unsafe-eval'`) and `connect-src` `ipc: http://ipc.localhost` instead of `https:`, plus `frame-ancestors 'none'`; no command logs (`console.`) in `TauriEngine.ts`/`TauriPlatform.ts` |
| `src/test/scaffold/engine.test.ts` | selection: Tauri 2 exposes `window.__TAURI_INTERNALS__` (and `__TAURI__` only with `withGlobalTauri`, which stays off), so `isTauri` checks `__TAURI_INTERNALS__` |

## Not covered (future work)

- **tauri-driver end-to-end.** tauri-driver needs a WebDriver server for
  the platform webview; macOS (WKWebView) has none that tauri-driver
  supports, so the Playwright flows (app TEST-PLAN) are not run against the
  `.app` yet. Revisit when tauri-driver supports macOS, or run the same
  flows on Linux (WebKitGTK) in CI.
- **The real dialog and clipboard plugins** are exercised by hand
  (`pnpm tauri dev`); the tests replace them with the `FileDialog` and
  `Clipboard` traits.
- **Real TLS.** The fetch tests use plain HTTP on loopback through
  `allow_loopback_http`; the https code path differs only in the scheme
  check and in rustls, which is not ours to test.
- **WKWebView's own data store.** `incognito: true` gives the webview a
  non-persistent store; that it writes nothing is Apple's behaviour, checked
  by hand (`~/Library/WebKit/<identifier>` stays absent).
- **Parity corpus.** `tests/parity.rs` has its own small corpus; it should
  be unified with `testdata/parity/` from `feat/wasm` once both land.

## Bundling

`pnpm tauri build --bundles app` (a wrapper for `cargo tauri build`) runs
`pnpm build`, then produces an unsigned
`target/release/bundle/macos/The Tokenator.app`. `tests/config.rs` pins the
config; building the bundle is a manual/CI step, not a unit test.
