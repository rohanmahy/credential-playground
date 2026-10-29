# app/src-tauri architecture

The macOS desktop shell. The contract (commands, wire shapes, policies) is
in `TEST-PLAN.md`; this file records how it is built and why.

## Shape

- `register(builder)` adds the 36 commands; `manage(app, engine, services)`
  adds their state. `run()` is `Builder::default()` + the dialog and
  clipboard plugins + `register`, with a `setup` that resolves the app data
  dir and calls `manage` with the real services. The tests call the same
  `register`/`manage` on Tauri's mock runtime with fake dialog and
  clipboard backends, so the command layer under test is the shipped one.
- **Engine commands** are one-line wrappers: `state.current().method(&req)`.
  `EngineState` is a `RwLock<Arc<Engine>>`; `current()` clones the `Arc`, so
  no lock is held during a (possibly slow) call, and `engine_init` swaps the
  `Arc` only after the new engine was built (a bad snapshot keeps the old one).
- **Dialogs and clipboard run in Rust.** The webview has no plugin
  permission and never names a path; `open_file`/`save_file` use
  `DialogExt` blocking pickers (fine: commands are async, off the main
  thread) and `std::fs` on the picked path only.
- **`fetch_url`** is a `reqwest::Client` built per `FetchPolicy`: a
  `redirect::Policy::custom` re-runs the scheme check on every hop and
  stops after `max_redirects` (a policy error surfaces as
  `reqwest::Error::is_redirect`, mapped to `blocked`); `referer(false)`; a
  fixed `User-Agent`; client-wide total and connect timeouts; the body is
  read with `Response::chunk()` and abandoned past `max_bytes`. reqwest
  returns a 3xx whose `Location` has a scheme it cannot fetch (`file:`,
  `data:`) without consulting the policy, so any 3xx with a `Location` that
  reaches us is also `blocked`.
- **Registry cache**: `<app data dir>/registry-snapshot.bin`, written to a
  sibling temp file, fsynced, and renamed. It is the only file the app
  writes on its own; nothing else (including private keys) touches disk.
- No logging anywhere, and no `Debug` formatting in messages: requests carry
  private keys (enforced by `tests/hygiene.rs`).

## Dependencies

| Crate | Why |
|---|---|
| `tauri` 2 (no extra features) | the shell |
| `tauri-plugin-dialog` | native open/save panels, called from Rust only |
| `tauri-plugin-clipboard-manager` | the system clipboard, from Rust only |
| `reqwest` (`default-features = false`, `rustls`, `http2`, `system-proxy`) | `fetch_url`; rustls with the platform verifier (macOS trust store), no cookie store, no native-tls |
| `serde` | wire DTOs (`PlatformError`, `FetchResponse`, `OpenedFile`) |
| `tokenator-core` | the engine |

Nothing was added beyond the skeleton's list. `tauri-plugin-dialog` pulls in
`tauri-plugin-fs` as a library dependency; it is never registered as a
plugin, and `tests/acl.rs` checks that no `fs:*` command is reachable.

## Bundling

`cargo tauri build --bundles app` (from `app/src-tauri`, or `pnpm tauri
build --bundles app` in `app/`) runs `pnpm build` and writes an unsigned
`target/release/bundle/macos/The Tokenator.app` (about 22 MiB).
