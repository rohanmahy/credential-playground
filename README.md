# The Tokenator (credential-playground)

A local-only playground for issuing, presenting, validating, viewing, and
manipulating JWT, SD-JWT, CWT, and SD-CWT credentials and their keys, for the
web and macOS (Tauri). See [SPEC.md](SPEC.md) and [ARCHITECTURE.md](ARCHITECTURE.md).

## Progress

Phase 1: foundations
- [x] `tokenator-cbor`: span-preserving CBOR, preferred/deterministic findings
- [x] `tokenator-json`: span- and order-preserving JSON
- [ ] `tokenator-crypto`: sign/verify/digest, alg ↔ key requirements
- [x] `tokenator-registry`: IANA snapshot generator + lookups

Phase 2
- [ ] `tokenator-edn`: EDN parser/printer with span maps
- [ ] `tokenator-keys`: PEM/JWK/CWK, to_jwk/to_cwk, thumbprints, keygen
- [ ] `tokenator-detect`: unwrapping chain + classification

Phase 3
- [ ] `tokenator-jose`: JWS, JWT, SD-JWT, KB-JWT
- [ ] `tokenator-cose`: COSE_Sign1, CWT, SD-CWT, SD-KBT

Phase 4
- [ ] `tokenator-core`: Engine facade, document model, actions, lint, datetime
- [ ] `tokenator-wasm`: wasm-bindgen bindings
- [ ] `app/src-tauri`: Tauri commands + Platform
- [ ] `app/`: Svelte UI (tabs, key panel, synced panes, chits)
- [ ] WASM ↔ native parity suite
- [ ] Playwright e2e (web + Tauri)
- [ ] Fuzz targets
- [ ] CI (fmt, clippy, tests, Pages deploy, `.app` release)
