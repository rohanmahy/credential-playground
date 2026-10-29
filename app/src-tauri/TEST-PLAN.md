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
| `src/lib.rs` | `COMMANDS`, `register(builder)` (invoke handler), `manage(app, engine, services)` (state), `run()` (plugins, `setup` resolving the app data dir); the tests reuse `register`/`manage` on the mock runtime |
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
`--exclude tokenator-desktop` (#36).

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
unused commands would only widen the IPC surface (#36).

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
| `write_clipboard` | `text, sensitive` | — | `sensitive` is required on the wire; no expiry yet (#36) |
| `registry_cache_get` | — | `Bytes \| null` | `<app data dir>/registry-snapshot.bin` |
| `registry_cache_put` | `snapshot: Bytes` | — | atomic: temp file in the same dir, then rename |
| `registry_cache_clear` | — | — | removes the file; no error if absent |

Platform errors are `PlatformError {kind, message, url, status}` with
`kind` one of `blocked`, `network`, `http` (the TS `FetchErrorKind`s the
desktop can produce), `io`, `dialog`, `clipboard`, `invalid_argument`.

**Fetch policy** (`FetchPolicy::default()`): scheme `https` only (any other
scheme, a redirect to one, or a URL with `user:pass@` is `blocked` before
connecting); at most 5 redirects (more is `blocked`); total timeout 30 s,
connect timeout 10 s (`network`); body cap
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
| `tests/common/mod.rs` | mock app (`tauri::test::mock_builder()` + `register` + `manage`), `invoke(cmd, args) -> Result<String, Value>` returning the exact IPC JSON text, fake `FileDialog` and `Clipboard` that record calls, the plain-HTTP test server (std `TcpListener`, no extra crate), core-built fixtures (`Fx`) |
| `tests/engine_commands.rs` (31) | each engine command gives the same JSON as the direct core call, including errors (the `EngineError` value unchanged); TS-style requests with omitted defaults are accepted; `engine_init` with a merged snapshot changes `info`/`registry_lookup`, `null` restores the bundled registry, a second snapshot replaces the first, a bad snapshot keeps the previous engine; camelCase keys are rejected; malformed args are string errors and don't break the app; every `COMMANDS` entry is registered |
| `tests/parity.rs` (3) | a 100+ request corpus (detect and open of every `testdata/tokens` sample in two views, seeded keygen for every family, issue/redact/present/validate, manipulation, key import/export/convert, datetime, registry, error cases) covering every engine command: IPC JSON vs `serde_json::to_string` of the direct call, byte-identical; repeated requests identical; the corpus itself well-formed |
| `tests/fetch.rs` (21) | default policy values; https only (http, loopback http, file, data, ftp, ws, tauri, invalid, scheme-relative, `user:pass@` → `blocked`, with no connection made); `allow_loopback_http` admits only `127.0.0.1`/`[::1]`; URL, status, content type, and exact bytes reported; redirects followed with the final URL; redirects to http/file `blocked`; more than 5 redirects `blocked`; non-2xx → `http` with the status; size cap by `Content-Length` and while streaming; timeout and refused connection → `network`; no `Cookie` after `Set-Cookie`, no `Referer`/`Authorization`; `User-Agent: the-tokenator/<version>`; the command's wire shape and `PlatformError`s |
| `tests/files.rs` (13) | `open_file` reads exactly the picked file (name and exact bytes), cancel → `null`, size cap → `invalid_argument`, missing file → `io`, `accept` → dialog extension filters (`extension_filters` rules); `save_file` writes exactly the picked file (replacing it), cancel → `false` and nothing written, unwritable → `io`; an extra `path` argument is ignored; no command signature takes a path |
| `tests/clipboard.rs` (3) | read; write with `sensitive` passed to the backend; `sensitive` required |
| `tests/cache.rs` (7) | location `<dir>/registry-snapshot.bin`; get/clear on an empty cache create nothing; put/get round trip creating the dir, atomic replace leaves no temp file; clear; the commands round-trip base64url and the file holds the raw snapshot; put failure → `io`; after a session of engine, clipboard, cache, and file commands the data dir holds only the cache file |
| `tests/acl.rs` (4) | the real ACL (`generate_context!` with tauri.conf.json, capabilities, and the build.rs manifest) on the mock runtime: `main` may call every command; another window may call none; remote origins may call none; plugin and core commands (dialog, clipboard, fs, shell, http, app, path, event, window, webview) are unreachable |
| `tests/config.rs` (13) | `tauri.conf.json`: product name, binary name, identifier, build commands, `withGlobalTauri` false, one window `main` with `url: index.html` and `incognito`, security settings (`capabilities: ["main"]`, no asset protocol, `devCsp: null`), the exact CSP, bundle target `app` unsigned with existing icons, no plugin config; `capabilities/`: one file, `windows: ["main"]`, `local`, no `remote`, permissions exactly `allow-<command>` for `COMMANDS`; `build.rs` and `generate_handler!` list the same commands |
| `tests/hygiene.rs` (8) | no logging or Debug formatting in `src/` (`println!`, `eprintln!`, `dbg!`, `log::`, `tracing::`, `{:?}`); no log/tracing crates; no fs/shell/http/store/updater/opener plugins; reqwest `default-features = false` with `rustls`, without cookies or native-tls; tauri without `tracing`/`devtools`/`protocol-asset`; file system access only in `files.rs` and `cache.rs`; no `unsafe` or env reads |

Rust total: 103 tests; 24 pass against the skeleton (config, hygiene, the
corpus check, the default policy, the signature scan) and 79 fail on the
`unimplemented!()` stubs.

TS (`pnpm test`, Vitest, `@tauri-apps/api/mocks` `mockIPC`):

| File | Tests |
|---|---|
| `src/test/unit/tauriEngine.test.ts` (39) | a `Record<keyof Engine, …>` table: each of the 27 methods invokes `engine_<snake>` with the right argument object and resolves with the response; `Uint8Array` input → base64url (also a subarray view); `engine_init` is not called by the constructor, runs once before the first call (also for concurrent first calls) with the snapshot as base64url or `null`, and each new `TauriEngine` re-inits; an `engine_init` failure rejects calls with `EngineFailure` and sends nothing else; an `EngineError` rejection becomes `EngineFailure` (code, message, node_id kept); a string or other rejection becomes `EngineFailure` with code `invalid_input` |
| `src/test/unit/tauriPlatform.test.ts` (20) | `fetchUrl` → `fetch_url`, decodes bytes, keeps a null content type; `PlatformError` kinds `blocked`/`network`/`http` → `FetchError(kind, url, message, status)`, the requested URL when the error has none, string rejections → `network` (never `cors`); `openFile` passes `accept` (or `null`), decodes, `null` on cancel; `saveFile` sends bytes as base64url and strings as UTF-8; clipboard read/write with `sensitive` (default false); registry cache get/put/clear; other errors → `Error(message)`; `now`/`localOffsetMinutes`/`randomBytes` stay local (no invoke) |
| `src/test/unit/tauriConfig.test.ts` (4) | the Tauri CSP equals the web CSP (`csp.config.ts`) except `script-src 'self'`, `connect-src ipc: http://ipc.localhost`, and `frame-ancestors 'none'`; no network or eval sources; `TauriEngine.ts`/`TauriPlatform.ts` never use `console.`, import `invoke` from `@tauri-apps/api/core`, and use neither `window.__TAURI__` nor plugin JS packages |
| `src/test/scaffold/engine.test.ts` (changed) | selection: Tauri 2 always injects `window.__TAURI_INTERNALS__`; `__TAURI__` exists only with `withGlobalTauri`, which stays off, so `isTauri` must check `__TAURI_INTERNALS__` |

TS: 63 new tests plus the changed selection test; 6 new ones pass
against the stubs, and 58 fail (57 new + the selection test). The
other app suites are unchanged.

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

## Notes for the implementer

- `run()`: `tauri::Builder::default()` + the dialog and clipboard plugins +
  `register`, and a `setup` that resolves `app.path().app_data_dir()` and
  calls `manage` with `EngineState::bundled()`, `Fetcher::new(FetchPolicy::default())`,
  `TauriFileDialog`/`TauriClipboard` over the app handle, and
  `RegistryCacheFile::in_dir(data_dir)`. `generate_context!()` must build
  without `../dist` in dev (it does today: `tests/acl.rs` uses it).
- `engine.rs`: fill in the `req_command!` macro body
  (`Ok(state.current().$method(&req)?)`-style) and the explicit commands;
  no other logic.
- reqwest: a `redirect::Policy::custom` that applies `check_url` to every
  hop and stops after `max_redirects`; `referer(false)`; `user_agent`;
  stream with `Response::chunk()` and stop at `max_bytes`.
- `select.ts`: `isTauri` checks `'__TAURI_INTERNALS__' in win`.
- `pnpm tauri dev` / `pnpm tauri build --bundles app` wrap `cargo tauri`
  (no `@tauri-apps/cli` npm package).

## Decisions (issues filed)

- #36: bundle identifier (`io.github.rohanmahy.tokenator`), workspace
  membership, `now`/`random_bytes` staying local, no clipboard expiry yet,
  fetch limits and error kinds, IPC error mapping, base64url raw input
  (#34 item 2), `devCsp: null`.
