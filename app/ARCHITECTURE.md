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
                             kinds, keys, fetch, registry, tree, viewport
                             (unit-tested without the DOM)
    lib/editor/              CodeMirror 6 setup, JSON + EDN language modes
    lib/components/          Svelte components (see below)
    test/                    MockEngine, MockPlatform, fixtures, render helpers
  e2e/                       Playwright specs (need the WASM build)
```

## Seams

- **Engine** (`lib/engine/Engine.ts`): one async method per `Engine` method in
  `tokenator-core` (camelCase names, generated DTO types). Failures reject
  with `EngineFailure` carrying the core `EngineError`. `selectEngine()`
  picks `TauriEngine` when `window.__TAURI__` exists, else `WasmEngine`,
  and hands it the cached registry snapshot (if any) that `main.ts` reads
  from `Platform.registryCache` at start-up. Both stay stubs until
  `tokenator-wasm` and `app/src-tauri` exist.
- **Platform** (`lib/platform/Platform.ts`): `fetchUrl`, `openFile`,
  `saveFile`, `readClipboard`, `writeClipboard`, `registryCache`, `now`,
  `localOffsetMinutes`, `randomBytes`. Web: `fetch`, File System Access API
  with `<input type=file>`/download fallbacks, Clipboard API, IndexedDB for
  the registry cache (`WebPlatform` is implemented; `fetchUrl` refuses
  non-https URLs, sends no credentials or referrer, and reports a `TypeError`
  as `cors`). Tauri: commands (reqwest, dialog-scoped fs, clipboard
  plugin), still a stub. The engine never sees the clock or an RNG except through
  arguments the stores fill from the Platform.
- **Stores** are plain classes with Svelte 5 runes (`*.svelte.ts`), one
  instance per app, handed down through Svelte context (`lib/context.ts`),
  so tests build fresh instances around a `MockEngine`/`MockPlatform`.
  - `Workspace`: tabs (document, candidates, provenance, collapse set,
    selection, live-edit text, stale flag, SD marks, last report, the
    per-tab `manual_decode`/`hide_decoded` lists) and the split, plus the
    open date/time chit. Drafts started with New (#43) carry `Tab.draft`
    (format, detected kind, explicit type; rules in `logic/drafts.ts` and
    TEST-PLAN.md); `engine/pending.ts` holds the proposed core
    `convert_claims` (#44) until core has it. Every action opens a derived tab whose provenance
    points at its parent (`{type: "derived", parent, action}`); a derived
    tab whose document has `signature_stale` (Tamper) is labelled
    _tampered_. Live edits are parsed against the bytes the tab had when
    live edit started (`editBase`), so reverting an edit clears the stale
    flag.
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
  (`role="tree"`; lines where a node starts are `treeitem`s, folded lines are
  not rendered). A line's node is the outermost
  node whose `main.line_start` is that line. A node spanning several lines is
  foldable; folding hides its inner lines. Registry annotations come from
  `Node.annotation` (hover text via `logic/hover.ts`), time hints from
  `Node.time`.
- **Main pane, live edit:** CodeMirror 6 (JSON, or the EDN mode). Each change
  calls `engine.parseEdit`; a successful parse replaces the document, and
  signed content changes mark the tab _modified – signature stale_.
- **Raw pane, hex (COSE):** `logic/lines.ts#alignRows` maps every `HexRow`
  to the main-pane line of its node (`node.main.line_start`; key rows use
  the key node). The pane renders one block per main-pane line, empty when
  no row maps to it, so rows line up with the EDN text and hide with the
  same folds.
- **Raw pane, segments (JOSE):** one block per `Segment`; a selected node's
  `raw` range is highlighted inside its segment.
- **Hex blocks are one line high.** A block's rows sit side by side (key
  row, value row), with the main pane's line height, and the main pane and
  a hex raw pane share one vertical scroll container. So every block stays
  beside its EDN line without measuring anything.
- **Long documents** (`logic/viewport.ts`): from 400 visible lines, both
  panes render only the window of visible lines in view (plus overscan),
  with spacers above and below. Fixed line heights make the window plain
  arithmetic. Keyboard moves outside the window scroll it first. Hex rows
  cut payloads after 48 bytes (the decoded view shows the content).
- **Keyboard:** trees use a roving `tabindex` with arrow keys, Left/Right to
  fold, Enter to select, and Shift+F10 / the context-menu key for the node
  menu (SD mark, date/time chit, decode as CBOR, hide decoded view, copy).
  Tabs and the action toolbar use roving focus too.

## Components

`AppShell` (input area, tools, drop target) → `KeyPanel` (`KeyCard`,
`KeyCreateDialog`, `KeyImportDialog`, `KeyExportDialog`, `KeyConvertView`,
`UrlFetch`) and `TabArea` → `CredentialTab` → `TabHeader` (`DetectedAsMenu`,
`ActionBar` with `IssueDialog`, `PresentDialog` for Present and Disclose,
`EditDisclosuresDialog`, `KeyChoiceDialog`), `MainPane` (`CodeEditor` in
live edit), `RawPane`, `DisclosuresView`, `ValidationReport`. Tools:
`DateTimeChit`, `SettingsDialog` (with `RegistryUpdate`), `AboutBox`.
`Dialog` and `Menu` are the shared primitives: dialogs take focus, trap Tab,
close on Escape, and give focus back; menus focus their first item and
close on Escape or a click outside. Components read stores through
context and keep only transient UI state (open dialogs, form fields).

## Styling

Plain CSS: `app.css` defines colour tokens with `light-dark()` (the theme
follows the OS through `color-scheme`; Settings can force light or dark via
`data-theme`) and a few shared classes; components use scoped `<style>`.
No CSS framework: the UI is a handful of panes and dialogs, and a framework
would add bundle weight and a build step for little gain.

## Security

- **CSP** (`csp.config.ts`, injected into the built `index.html` only, so the
  Vite dev server keeps HMR): `default-src 'self'; script-src 'self'
'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'
https:; img-src 'self' data:; object-src 'none'; base-uri 'none';
form-action 'none'`. `connect-src https:` is the
  deliberate tradeoff for user-confirmed key URL fetches (root
  ARCHITECTURE.md). `style-src 'unsafe-inline'` is for CodeMirror's injected
  styles. The Tauri CSP goes into `src-tauri/tauri.conf.json` later.
- **Never persist:** only `platform/registryCache.ts` touches IndexedDB; a
  static test fails if any other source file mentions `localStorage`,
  `sessionStorage`, `indexedDB`, or `document.cookie`.
- **No third-party network:** only `WebPlatform.fetchUrl` calls `fetch`, and
  only after the user confirmed the URL. No analytics, fonts, or CDNs.
  _Update registries_ (Settings) asks once for the four IANA URLs, merges
  them with `registryMerge`, and caches the snapshot; it applies at the
  next start.
- **Private keys:** export defaults to public; private needs the
  confirmation checkbox, and the copy goes out with `sensitive: true` and a
  "Private key copied" status. The Convert view shows private material only
  after its _Private_ switch is turned on.

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
Request DTO fields that are `#[serde(default)]` in Rust are optional in
TypeScript (`field?: T | null` for `Option`, `field?: T` otherwise; never
send `null` for the latter). Requests omit what they don't set; only
`ViewOptions` is built in full, from `defaultViewOptions()` and Settings.
