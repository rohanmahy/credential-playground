# The Tokenator (credential-playground)

A local-only playground for issuing, presenting, validating, viewing, and
manipulating JWT, SD-JWT, CWT, and SD-CWT credentials and their keys, for the
web and macOS (Tauri). See [SPEC.md](SPEC.md) and [ARCHITECTURE.md](ARCHITECTURE.md).

## Building and testing

Needs Rust (with the `wasm32-unknown-unknown` target), wasm-pack 0.15,
Node 22+, and pnpm. CI (`.github/workflows/ci.yml`) runs exactly these
commands.

```sh
# Rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features   # unit tests, vectors, native parity
cargo test --workspace                  # default features (tokenator-edn without `hash`)
# On Linux without the WebKitGTK dev packages (scripts/linux-deps.sh), add
# --exclude tokenator-desktop.
cargo build --target wasm32-unknown-unknown -p tokenator-core -p tokenator-wasm
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

# The app
cd app && pnpm install
pnpm build:wasm                   # crates/tokenator-wasm → crates/tokenator-wasm/pkg (gitignored)
pnpm dev                          # build:wasm, then the Vite dev server
pnpm typecheck && pnpm lint       # svelte-check; ESLint + Prettier
pnpm test                         # UI unit tests (no Rust build needed)
pnpm check:types                  # the TS bindings match tokenator-core
pnpm build                        # build:wasm, then the static site in app/dist
pnpm test:wasm                    # WasmEngine, the binary, and WASM ↔ native parity
pnpm test:e2e                     # Playwright against the production build
                                  # (first time: pnpm exec playwright install chromium)
pnpm parity:regen                 # rewrite testdata/parity goldens after a deliberate core change
node scripts/check-dist.mjs       # dist/ keeps its CSP and only relative URLs (Pages)
scripts/package-macos-app.sh v0.1.0   # the unsigned .app, zipped (needs cargo-tauri)

# The desktop app on Linux (Ubuntu 24.04; app/src-tauri/TEST-PLAN.md)
scripts/linux-deps.sh --e2e       # WebKitGTK 4.1, libsoup 3, …; --e2e adds WebKitWebDriver, Xvfb
cargo install --locked tauri-cli@2.12.4 tauri-driver@2.1.0
cd app && cargo tauri build       # target/release/tokenator; --bundles deb for a .deb
pnpm build:desktop-e2e            # the binaries the desktop e2e suite uses
xvfb-run pnpm test:e2e:desktop    # WebdriverIO → tauri-driver → the real app
scripts/desktop-e2e.sh            # all of the above (after linux-deps.sh)
scripts/desktop-e2e-docker.sh     # the same in a Linux container, e.g. on macOS
                                  # (--clean removes its image and cache volumes)

# Fuzzing (nightly + cargo-fuzz; see fuzz/README.md)
fuzz/seed-corpora.sh && fuzz/smoke.sh 60
```

The web build uses the `wasm-release` Cargo profile (size-optimized).
See `crates/tokenator-wasm/TEST-PLAN.md` for the parity corpus and the
WASM stack and size budgets.

Releases: pushing a `v*` tag builds the unsigned universal macOS `.app` and
the Linux `.deb` (x86_64), and attaches them to the GitHub release
(`.github/workflows/release.yml`).
Pushing to `main` deploys the web app to
<https://rohanmahy.github.io/credential-playground/>.

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
- [x] `tokenator-wasm`: wasm-bindgen bindings
- [x] `app/src-tauri`: Tauri commands + Platform
- [x] `app/`: Svelte UI (tabs, key panel, synced panes, chits)
- [x] WASM ↔ native parity suite
- [x] Playwright e2e (web)
- [x] Desktop e2e: Linux via tauri-driver (`app/e2e-desktop`); macOS manual ([checklist](Mac-smoketest-checklist.md))
- [x] Fuzz targets
- [x] CI (fmt, clippy, tests, Pages deploy, `.app` release)
