# The Tokenator (credential-playground)

A local-only playground for issuing, presenting, validating, viewing, and
manipulating JWT, SD-JWT, CWT, and SD-CWT credentials and their keys, for the
web and macOS (Tauri). See [SPEC.md](SPEC.md) and [ARCHITECTURE.md](ARCHITECTURE.md).

## Building and testing

Needs Rust (with the `wasm32-unknown-unknown` target), wasm-pack 0.15,
Node 22+, and pnpm.

```sh
cargo test --workspace            # Rust unit tests, vectors, native parity
cd app && pnpm install
pnpm build:wasm                   # crates/tokenator-wasm → crates/tokenator-wasm/pkg (gitignored)
pnpm dev                          # build:wasm, then the Vite dev server
pnpm build                        # build:wasm, then the static site in app/dist
pnpm test                         # UI unit tests (no Rust build needed)
pnpm test:wasm                    # WasmEngine, the binary, and WASM ↔ native parity
pnpm test:e2e                     # Playwright against the production build
                                  # (first time: pnpm exec playwright install chromium)
pnpm parity:regen                 # rewrite testdata/parity goldens after a deliberate core change
```

The web build uses the `wasm-release` Cargo profile (size-optimized).
See `crates/tokenator-wasm/TEST-PLAN.md` for the parity corpus and the
WASM stack and size budgets.

## Progress

Phase 1: foundations
- [x] `tokenator-cbor`: span-preserving CBOR, preferred/deterministic findings
- [x] `tokenator-json`: span- and order-preserving JSON
- [x] `tokenator-crypto`: sign/verify/digest, alg ↔ key requirements
- [x] `tokenator-registry`: IANA snapshot generator + lookups

Phase 2
- [x] `tokenator-edn`: EDN parser/printer with span maps
- [x] `tokenator-keys`: PEM/JWK/CWK, to_jwk/to_cwk, thumbprints, keygen
- [x] `tokenator-detect`: unwrapping chain + classification

Phase 3
- [x] `tokenator-jose`: JWS, JWT, SD-JWT, KB-JWT
- [x] `tokenator-cose`: COSE_Sign1, CWT, SD-CWT, SD-KBT

Phase 4
- [x] `tokenator-core`: Engine facade, document model, actions, lint, datetime
- [ ] `tokenator-wasm`: wasm-bindgen bindings
- [x] `app/src-tauri`: Tauri commands + Platform
- [ ] `app/`: Svelte UI (tabs, key panel, synced panes, chits)
- [ ] WASM ↔ native parity suite
- [ ] Playwright e2e (web + Tauri)
- [ ] Fuzz targets
- [ ] CI (fmt, clippy, tests, Pages deploy, `.app` release)
