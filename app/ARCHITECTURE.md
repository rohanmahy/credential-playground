# app/ — UI architecture

The Svelte 5 + TypeScript front end of The Tokenator. It owns all state and
all I/O; the Rust engine (`tokenator-core`, via WASM or Tauri) is a pure,
stateless function of its DTO arguments. See the root `ARCHITECTURE.md`
(the "app/" section and the Engine vs Platform seam) and `SPEC.md` §3–§6, §9.

## Layout

```
app/
  index.html                 the CSP <meta> is injected here at build time
  csp.config.ts              the Content-Security-Policy (one place)
  scripts/gen-types.mjs      runs tools/ts-bindings → src/lib/engine/types/
  src/
    main.ts, App.svelte      bootstraps Engine + Platform, puts stores in context
    lib/engine/              Engine interface, WasmEngine, TauriEngine, selectEngine
      types/index.ts         GENERATED from tokenator-core DTOs (ts-rs); committed
      bytes.ts, defaults.ts  base64url helpers; DTO defaults (ViewOptions …)
    lib/platform/            Platform interface, WebPlatform, TauriPlatform,
                             registryCache (the only persistent storage)
    lib/stores/              Workspace (tabs + provenance), KeyStore, Settings
    lib/logic/               pure functions: actions, lines, provenance, hover,
                             kinds, keys, fetch (unit-tested without the DOM)
    lib/editor/              CodeMirror 6 setup, JSON + EDN language modes
    lib/components/          Svelte components (see below)
    test/                    MockEngine, MockPlatform, fixtures, render helpers
  e2e/                       Playwright specs (need the WASM build)
```

## Seams

- **Engine** (`lib/engine/Engine.ts`): one async method per `Engine` method in
  `tokenator-core` (camelCase names, generated DTO types). Failures reject
  with `EngineFailure` carrying the core `EngineError`. `selectEngine()`
  picks `TauriEngine` when `window.__TAURI__` exists, else `WasmEngine`.
- **Platform** (`lib/platform/Platform.ts`): `fetchUrl`, `openFile`,
  `saveFile`, `readClipboard`, `writeClipboard`, `registryCache`, `now`,
  `localOffsetMinutes`, `randomBytes`. Web: `fetch`, File System Access API
  with `<input type=file>`/download fallbacks, Clipboard API, IndexedDB for
  the registry cache. Tauri: commands (reqwest, dialog-scoped fs, clipboard
  plugin). The engine never sees the clock or an RNG except through
  arguments the stores fill from the Platform.
- **Stores** are plain classes with Svelte 5 runes (`*.svelte.ts`), one
  instance per app, handed down through Svelte context (`lib/context.ts`),
  so tests build fresh instances around a `MockEngine`/`MockPlatform`.
  - `Workspace`: tabs (document, candidates, provenance, collapse set,
    selection, live-edit text, stale flag, SD marks, last report) and the
    split. Every action opens a derived tab whose provenance points at its
    parent (`{type: "derived", parent, action}`).
  - `KeyStore`: key cards (`KeyInfo` + role + label + provenance). Keys
    cross into the engine as `KeyRef` bytes on every call.
  - `Settings`: clock override, skew, expected `aud`/`nonce`, view toggles,
    theme. `Settings.now()` is the override or `Platform.now()`.

## Panes and tree sync

Both panes of a tab read the same `Tab.collapsed` (a set of `NodeId`) and
`Tab.selected`, so expanding, collapsing, and selecting are synchronized by
construction, and survive re-renders and edits because NodeIds are
path-based (core TEST-PLAN §4).

- **Main pane, read-only:** `Document.main.text` rendered line by line
  (`role="tree"`, one `treeitem` per line). A line's node is the outermost
  node whose `main.line_start` is that line. A node spanning several lines is
  foldable; folding hides its inner lines. Registry annotations come from
  `Node.annotation` (hover text via `logic/hover.ts`), time hints from
  `Node.time`.
- **Main pane, live edit:** CodeMirror 6 (JSON, or the EDN mode). Each change
  calls `engine.parseEdit`; a successful parse replaces the document, and
  signed content changes mark the tab *modified – signature stale*.
- **Raw pane, hex (COSE):** `logic/lines.ts#alignRows` maps every `HexRow`
  to the main-pane line of its node (`node.main.line_start`; key rows use
  the key node). The pane renders one block per main-pane line, empty when
  no row maps to it, so rows line up with the EDN text and hide with the
  same folds.
- **Raw pane, segments (JOSE):** one block per `Segment`; a selected node's
  `raw` range is highlighted inside its segment.

## Security

- **CSP** (`csp.config.ts`, injected into the built `index.html` only, so the
  Vite dev server keeps HMR): `default-src 'self'; script-src 'self'
  'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'
  https:; img-src 'self' data:; object-src 'none'; base-uri 'none';
  form-action 'none'; frame-ancestors 'none'`. `connect-src https:` is the
  deliberate tradeoff for user-confirmed key URL fetches (root
  ARCHITECTURE.md). `style-src 'unsafe-inline'` is for CodeMirror's injected
  styles. The Tauri CSP goes into `src-tauri/tauri.conf.json` later.
- **Never persist:** only `platform/registryCache.ts` touches IndexedDB; a
  static test fails if any other source file mentions `localStorage`,
  `sessionStorage`, `indexedDB`, or `document.cookie`.
- **No third-party network:** only `WebPlatform.fetchUrl` calls `fetch`, and
  only after the user confirmed the URL. No analytics, fonts, or CDNs.

## Dependencies

Runtime (bundled):

| Package | Why |
|---|---|
| `svelte` 5 | UI framework (runes) |
| `@codemirror/state`, `view`, `commands`, `language`, `lang-json` 6 | Live-edit editor: JSON mode, folding, and `StreamLanguage` for the EDN mode. The individual packages rather than the `codemirror` meta package keep the bundle to what is used |

Later, for the desktop build only: `@tauri-apps/api` (and the clipboard and
dialog plugins' JS bindings), loaded by `TauriEngine`/`TauriPlatform`.

Development only: Vite, `@sveltejs/vite-plugin-svelte`, TypeScript 6
(`typescript-eslint` and `svelte-check` do not support TS 7 yet),
`svelte-check`, ESLint (+ `typescript-eslint`, `eslint-plugin-svelte`,
`eslint-config-prettier`, `globals`), Prettier (+ `prettier-plugin-svelte`),
Vitest, `@testing-library/svelte`, `@testing-library/jest-dom`,
`@testing-library/user-event`, `jsdom`, `fake-indexeddb` (tests of the
registry cache), `@playwright/test`.

## Generated types

`pnpm gen:types` runs `cargo run -p ts-bindings` (which prints
`tokenator_core::ts::bindings()`), formats the result with Prettier, and
writes `src/lib/engine/types/index.ts`. `pnpm check:types` fails when the
committed file differs. Never edit the generated file; change the Rust DTOs.
ts-rs types `#[serde(default)]` fields as required `T | null`, so callers
build requests from `lib/engine/defaults.ts`.
