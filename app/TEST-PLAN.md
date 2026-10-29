# app/ test plan

The UI tests pin behaviour from `SPEC.md` §3–§6 and §9 against a
`MockEngine` and a `MockPlatform`, so they run without the Rust engine. The
engine contract itself (DTO shapes, NodeIds, ranges, report rules) is tested
in `crates/tokenator-core`; here we only check that the UI uses it
correctly. `app/ARCHITECTURE.md` describes the modules under test.

## Tooling

| Command | What |
|---|---|
| `pnpm test` | Vitest: unit (pure logic and stores) and component tests in jsdom |
| `pnpm test:e2e` | Playwright against `vite preview` of the production build; skipped unless `TOKENATOR_E2E=1` |
| `pnpm typecheck` | `svelte-check` (strict TS), which also type-checks fixtures against the generated DTOs |
| `pnpm lint` | ESLint + Prettier check |
| `pnpm check:types` | Generated DTO types are up to date with `tokenator-core` |

Tests live in `src/test/` (`unit/`, `components/`, `scaffold/`); shared code
in `src/test/` (`MockEngine.ts`, `MockPlatform.ts`, `render.ts`,
`setup.ts`) and fixtures in `src/test/fixtures/`.

## Mocks and fixtures

- **Fixtures** are hand-written DTOs typed with the generated types, so a DTO
  change in core breaks `pnpm typecheck`. Small builders compute ranges from
  the fixture text so they stay consistent: `jose.ts` (a JSON scanner that
  builds the JOSE view-object tree with `~e` decoded levels and segment
  ranges per core TEST-PLAN §5), `cose.ts` (hex rows and nodes from a row
  table). Fixtures: a JWT, an SD-JWT (two disclosures, one undisclosed
  digest), an SD-JWT+KB, a CWT (tag 18, RFC 8392-like), an SD-CWT, a JSON and
  an EDN claim set, detection candidates (including an ambiguous input with
  two candidates and a key input), key cards (issuer P-256, holder Ed25519,
  public-only verifier), a validation report, date/time forms, registry
  annotations, and live-edit results.
- **MockEngine** implements `Engine` with `vi.fn()` methods returning those
  fixtures (overridable per test). **MockPlatform** records clipboard, file,
  and fetch calls, has a fixed clock (`1_800_000_000`) and deterministic
  `randomBytes`.
- `renderWithApp(Component, props, overrides)` builds fresh `Settings`,
  `KeyStore`, and `Workspace` around the mocks and passes them through Svelte
  context.

## UI contract the tests rely on

| Element | Contract |
|---|---|
| Key panel | `<aside aria-label="Keys">`; each card `role="article"` named by its label; buttons *Create key*, *Import key*, *Fetch from URL* |
| Tabs | `role="tablist"` (`Credentials`), `role="tab"` per tab with `aria-selected`, ArrowLeft/Right/Home/End; *Split view* button shows two `role="tabpanel"` |
| Tab header | `data-testid="detected-type"`; *Detected as…* button → `role="menu"` of `menuitemradio`; `nav[aria-label="Unwrapping layers"]` and `nav[aria-label="Provenance"]`; `data-testid="validation-badge"`; `role="switch"` *Live edit* |
| Actions | `role="toolbar"` (`Actions`) with buttons Issue, Redact, Disclose, Present, Validate, Re-sign, Tamper, Re-encode, Edit disclosures. Disabled ones have `aria-disabled="true"` (still focusable) and a `title` naming what is missing |
| Stale state | `role="status"` containing "modified – signature stale" with *Re-sign* and *Keep original signature* buttons |
| Main / raw panes | each `role="tree"` (`Main pane` / `Raw pane`); lines/rows are `treeitem`s with `data-node-id`, `aria-level`, `aria-expanded` (foldable), `aria-selected`; hex blocks carry `data-line` |
| Validation report | `role="list"` (`Validation report`); items carry `data-status`; node links are buttons that select the node |
| Date/time chit | `role="dialog"` (`Date/time`); labelled inputs *Epoch seconds*, *Milliseconds*, *RFC 3339 (UTC)*, *RFC 3339 (local)*; `data-testid="relative"`; *Insert*, *Use as clock* |
| URL fetch | a `role="alertdialog"` confirmation showing the URL and the IP-disclosure note before any `Platform.fetchUrl`; on a CORS failure, an explanation and a *Paste instead* fallback |
| About | `role="dialog"` (`About`) with the §9 notes and the SD-CWT revision from `engine.info()` |

## Areas and test files

| Area | File | Tests |
|---|---|---|
| Tree sync: collapse/expand and selection keyed by NodeId; state survives re-render and edit | `components/treeSync.test.ts`, `unit/lines.test.ts` | 8 + 6 |
| Raw-row ↔ main-line alignment from DTO ranges (hex), segment highlight (JOSE) | `unit/lines.test.ts`, `components/rawPane.test.ts` | (in lines) + 4 |
| Action enablement and "what's missing" tooltips, incl. Re-encode's three CBOR serializations | `unit/actions.test.ts`, `components/actions.test.ts` | 13 + 5 |
| Actions open derived tabs with a provenance breadcrumb | `unit/workspace.test.ts`, `components/provenance.test.ts` | 9 + 3 |
| *Detected as…* switcher, unwrapping-layer breadcrumb, key inputs routed to the panel | `components/detect.test.ts` | 5 |
| Live edit → "modified – signature stale", Re-sign / Keep original signature | `components/liveEdit.test.ts` | 5 |
| Key panel: create (alg list, seeded), import paste/file/clipboard, export with explicit private choice and labelled clipboard copy, JWK/CWK side by side, thumbprints, auto kid, roles | `unit/keyStore.test.ts`, `components/keyPanel.test.ts` | 9 + 10 |
| Validation checklist rendering with NodeId links, fetch hints | `components/validation.test.ts` | 5 |
| Date/time chit: synced fields, pre-fill, Insert in live edit, Use as clock | `components/dateTimeChit.test.ts` | 5 |
| URL fetch always confirmed; CORS explanation and paste fallback | `components/fetch.test.ts`, `unit/fetch.test.ts` | 4 + 3 |
| Hover text uses the registry's display text; inline time hints | `unit/hover.test.ts`, `components/annotations.test.ts` | 3 + 3 |
| Never persist: storage APIs spied during full flows; static scan; registry cache is IndexedDB | `unit/neverPersist.test.ts` | 4 |
| Accessibility: ARIA roles, keyboard navigation of trees and tabs | `components/a11y.test.ts` | 6 |
| Settings and clock | `unit/settings.test.ts` | 3 |
| About box with §9 notes | `components/about.test.ts` | 2 |
| Scaffold: engine/platform selection, base64url helpers, EDN mode, CSP of the production build, no stray network calls | `scaffold/*.test.ts` | pass now |

All behaviour tests fail against the stubs (stub methods throw
`NotImplemented` or render placeholders); scaffold tests pass.

### Rules encoded in the tests

- **Action enablement** (`logic/actions.ts`): Issue needs a claim set and an
  issuer key with a private part; Redact also needs a marked claim (JSON SD
  marks, or tags 58/62 in EDN); Disclose needs an SD credential with
  disclosures and no key binding; Present needs an SD-JWT, SD-CWT, or plain
  CWT without key binding, and a holder key with a private part; Validate,
  Tamper, and Re-encode need a signed credential; Re-sign needs a signed
  credential and a private key; Edit disclosures needs an SD-JWT or SD-CWT.
  Re-encode offers *As received*, *Preferred-plus*, and *Deterministic* for
  COSE, and compact / flattened / general JSON for JOSE.
- **Derived tabs**: every credential-producing action (Issue, Redact,
  Disclose, Present, Re-sign, Tamper, Re-encode, Edit disclosures) opens a
  new tab with provenance `derived` and becomes active; the breadcrumb lists
  the ancestors from the root tab. Randomness (32 bytes) and `iat`/`now` come
  from `Platform`/`Settings`, never from the engine.
- **Live edit**: a successful `parseEdit` with `signature_stale` marks the
  tab stale; a failed parse keeps the last good document and shows the
  diagnostic; *Re-sign* opens a derived tab; *Keep original signature* keeps
  the stale bytes and labels the tab *tampered*.
- **Keys**: seeded creation sends `KeySeed.seed` with the UTF-8 seed, the
  well-known option sends `well_known`, random sends 32 platform bytes as
  `entropy`. Export defaults to public; private requires an explicit
  confirmation, and the clipboard copy is sent with `sensitive: true` and
  announced as a private key.
- **Fetch**: no `fetchUrl` before the user confirms; cancelling fetches
  nothing; a `FetchError` of kind `cors` on the web shows why and offers
  pasting the content (or the desktop app).
- **Never persist**: during open, edit, validate, key create/export, and
  settings changes, `localStorage`/`sessionStorage` `setItem` and
  `indexedDB.open` are never called; only `registryCache` may use IndexedDB.

## End-to-end (Playwright)

`e2e/` holds the main flows against the real WASM engine: paste a JWT,
SD-JWT, CWT, and SD-CWT from `testdata/tokens/` → Validate; Issue → Present
→ Validate (JOSE and COSE, with created keys); key create → convert (JWK and
CWK side by side) → export. They need `crates/tokenator-wasm/pkg` and run
only with `TOKENATOR_E2E=1` (the config then builds and previews the app);
otherwise every spec is skipped. **tauri-driver specs come later**, once
`app/src-tauri` exists; they will reuse these flows.

## CSP

`scaffold/csp.test.ts` builds the app with Vite into a temporary directory
and parses the built `index.html`: exactly one CSP `<meta>`, `script-src` is
`'self'` (plus `'wasm-unsafe-eval'`, which WebAssembly needs), no
`'unsafe-inline'`/`'unsafe-eval'` for scripts, `object-src 'none'`, and no
inline `<script>` without `src`.

## Decisions (issues filed)

See the GitHub issues labelled `ai-needs-clarification` referenced in the
final report; defaults are encoded in the tests.
