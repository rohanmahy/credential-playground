# Web wiring test plan (tokenator-wasm, WasmEngine, parity, e2e)

Work in progress. This file will cover:

1. `crates/tokenator-wasm`: the wasm-bindgen surface, error envelope,
   panics, stack size, and release size.
2. `app/src/lib/engine/WasmEngine.ts`: lazy loading, one binding call per
   Engine method, `EngineFailure` mapping.
3. The WASM ↔ native parity suite (SPEC §11) and the stack audit (#27).
4. Playwright end-to-end specs against the production web build, and the
   CSP with wasm.
