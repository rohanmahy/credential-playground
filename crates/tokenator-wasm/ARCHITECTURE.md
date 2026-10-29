# tokenator-wasm

wasm-bindgen bindings over `tokenator_core::Engine`, consumed by
`app/src/lib/engine/WasmEngine.ts`. See the top-level `ARCHITECTURE.md` for
its role and `TEST-PLAN.md` for the decisions the tests pin (#27, #37, #38).

| file | contents |
|---|---|
| `src/lib.rs` | `TokenatorEngine` (one method per Engine method, plus the hidden `panic_for_tests`), the `envelope!`/`parse!` macros |
| `build.rs` | `-zstack-size` for the wasm32 cdylib (`STACK_SIZE`, 2 MiB) |
| `tests/native.rs` | the bindings compiled natively, replaying `testdata/parity` |

## Design

- **JSON text in, envelope text out.** Each method deserializes its JSON
  argument(s) with `serde_json` (failure: `invalid_input`), calls the core,
  and returns `{"ok":…}` or `{"err":…}`. The envelope is built by
  formatting the `serde_json` output of the DTO, which is byte-identical
  to serde's externally tagged enum (what `tools/parity` writes), so the
  crate needs no direct `serde` dependency. The macros exist only to
  avoid naming the `Serialize`/`Deserialize` bounds.
- **No logic.** Nothing is computed here. Randomness and time come in the
  requests; the module imports nothing but the wasm-bindgen glue.
- **Panics trap.** `wasm-release` uses `panic = "abort"`, so a panic is a
  `WebAssembly.RuntimeError` in JS; `WasmEngine` maps it to an
  `EngineFailure` with code `internal` (#38). A DTO that fails to
  serialize (impossible for the current DTOs) panics for the same reason.
  `console_error_panic_hook` is installed in debug builds only.
- **One instance, built lazily.** `WasmEngine.load()` resolves at once; the
  first call imports the glue, instantiates the module (fetching the
  same-origin asset, or the bytes passed as `{ wasm }`), and constructs
  `TokenatorEngine` (from the registry snapshot, if any). Concurrent first
  calls share that promise; a failure sticks, like `TauriEngine`'s
  `engine_init`.

## Build and size

`pnpm build:wasm` runs `wasm-pack build --target web --profile wasm-release
--no-opt --no-pack` into the gitignored `pkg/`. The profile (root
`Cargo.toml`) is `opt-level = "s"`, LTO, one codegen unit, `panic =
"abort"`, and `strip = "symbols"`: rustc otherwise keeps a 2 MB `name`
section. Measured: **2.48 MB raw, 0.80 MB gzip** (budget 3.5 MiB / 1.1 MiB).
`wasm-opt` stays off: wasm-pack would download binaryen during the build,
and the size is within budget without it.

`--no-pack` also stops a wasm-pack quirk: when it writes `package.json`, it
copies the workspace `license-file` (`../../LICENSE`, relative to the
crate) to `pkg/../../LICENSE`, that is `crates/LICENSE`. `.gitignore` lists
that path in case someone runs `wasm-pack build` by hand.

## Stack (#27)

The release module runs on a 2 MiB stack (`build.rs`). Peak use over the
whole parity corpus, measured by filling the stack region with a pattern
before each call: **460 KiB** (ML-DSA-87 signing; the JOSE/COSE issue
cases), so about 1.55 MiB of headroom. The deep cases stay small: a CWT
nested to `MAX_DEPTH - 8` peaks at 295 KiB while issuing, the 120-level
SD-JWT disclosure chain at 148 KiB while validating, and max-depth
CBOR/EDN render, lint, and detect under 60 KiB.

## Dependencies

`wasm-bindgen` (the boundary), `serde_json` (the wire format), and
`console_error_panic_hook` (debug builds only). No `js-sys` and no
`getrandom`.
