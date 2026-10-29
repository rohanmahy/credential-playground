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

Accessible names are matched exactly unless a regex is shown in the test.

| Element | Contract |
|---|---|
| Input area | textbox _Paste a credential or key_ with an _Open_ button; _From clipboard_ and _Open file…_ buttons (the only ones with those names outside dialogs) |
| Key panel | `<aside aria-label="Keys">` (complementary); each card `role="article"` named by its label, with a _Role_ select (`issuer`/`holder`/`verifier`), `data-testid="kid"`, private/public, provenance label, both thumbprints and a _Thumbprint hash_ select; card buttons _Export_, _Convert_, _Set kid_ (menu: _JWK thumbprint_, _COSE thumbprint_, text), _Derive public key_. Panel buttons _Create key_, _Import key_, _Fetch from URL_ |
| Key dialogs | _Create key_: _Algorithm_ select (`KEY_SPECS` labels in order), radios _Random_ / _Well-known test seed_ / _From a seed_ with a _Seed_ textbox, _Role_, _Create_. _Import key_: _Key_ textbox, _Import_, _From clipboard_, _From file…_; closes after a successful import. _Export key_: _Format_ select (JWK, JWK Set, COSE_Key, COSE_KeySet, PEM …), radios _Public_ (default) / _Private_, checkbox _I understand this exports the private key_ gating _Copy private key_ and _Save…_, a `role="status"` announcing the copy. _Convert_: regions _JWK_ and _COSE_Key_ side by side and a _Private_ switch |
| Tabs | `role="tablist"` (_Credentials_), `role="tab"` per tab (title `Tab N · <kind label>`) with `aria-selected`, roving focus with ArrowLeft/Right/Home/End (moving also activates); `role="tabpanel"` with `aria-labelledby`; _Split view_ shows two panels; only the active (or split) panels are rendered |
| Tab header | `data-testid="detected-type"` (`Kind::label()`); _Detected as…_ button → `role="menu"` of `menuitemradio` (current one `aria-checked`); `nav` _Unwrapping layers_ with one `listitem` per breadcrumb entry; `nav` _Provenance_ (root: `Pasted`, `Clipboard`, `File: name`, `URL: url`, `Generated`; derived: parent title as a button, then the action label); `data-testid="validation-badge"` (`Not validated`, the overall status, or `tampered`); `role="switch"` _Live edit_ |
| Actions | `role="toolbar"` (_Actions_) with exactly the buttons Issue, Redact, Disclose, Present, Validate, Re-sign, Tamper, Re-encode, Edit disclosures. Disabled ones have `aria-disabled="true"` (never the `disabled` attribute) and a `title` listing what is missing; clicks on them do nothing. Re-encode opens `role="menu"` (_Re-encode_) of `menuitem`s from `reencodeChoices` (_As received_, _Preferred-plus_, _Deterministic_ / _Compact_, _JSON (flattened)_, _JSON (general)_). Issue, Redact, and Present open dialogs named after the action: Issue has _Issuer key_ (defaults to the first issuer key), _Serialization_, _Holder key (cnf)_; Present has a checkbox per disclosure (labelled with its claim, all checked), _Holder key_, _Audience_, _Nonce_. Re-sign uses the only private key, or asks when there are several |
| SD marks | the context menu of a JSON claim line offers `menuitemcheckbox` _Selectively disclosable_; marked lines carry `data-sd-mark="true"` |
| Stale state | `role="status"` containing "modified – signature stale" with _Re-sign_ and _Keep original signature_; an edit that does not parse shows its diagnostic in `role="alert"` |
| Main pane | `role="tree"` (_Main pane_). Read-only: one element per visible line of `main.text`; lines where a node starts are `treeitem`s (`data-node-id` = outermost node starting there, `aria-level` = depth + 1, `aria-expanded` when foldable, `aria-selected` true/false, roving `tabIndex`); other lines are presentational. Folded lines are not rendered. Each line has a fold `button` (_Collapse_/_Expand_) when foldable. Annotated names carry `title` = `hoverText(annotation)`; time-valued nodes show `data-testid="time-hint"`. ArrowUp/Down move over visible treeitems, Left/Right fold/unfold, Enter selects, Home/End. Live edit: `data-testid="live-editor"` holding CodeMirror |
| Raw pane | `role="tree"` (_Raw pane_), absent for `RawView.none` and when the _Show raw pane_ checkbox is off. Hex: one block per visible main-pane line (`data-line`), rows are `treeitem`s with `data-row`, `data-node-id`, `aria-selected` (true for the rows of the selected node), `aria-expanded` on the first row of a foldable node, head and payload as lowercase hex, the description, and the comment. Segments: one `treeitem` per segment (`data-node-id`) with its label and text; the selected node's `raw` characters are wrapped in `<mark>` and the segment is `aria-selected` |
| SD view | `table` _Disclosures_ (header row, then one row per disclosure: claim, value, salt, digest, status, a _slot_ button); `list` _Undisclosed digests_ marked "decoy or withheld" |
| Validation report | `role="list"` (_Validation report_), headings per category present, `data-testid="report-overall"`; items carry `data-status`, show the message, signature key label and selection, `preferred_hex` for encoding findings, and one button per NodeId (selects it and unfolds its ancestors); fetch hints are buttons _Fetch key from <url>_ |
| Date/time chit | `role="dialog"` (_Date/time_); text inputs _Epoch seconds_, _Milliseconds_, _RFC 3339 (UTC)_, _RFC 3339 (local)_ applied on Enter or change; `data-testid="relative"`; one radio per CBOR form labelled with its EDN, showing its hex; _Insert_ (enabled only from a node in live edit), _Use as clock_ |
| URL fetch | _Fetch from URL_ → textbox _URL_ and _Fetch_ → `role="alertdialog"` with the URL, the IP-disclosure note, _Fetch_ and _Cancel_, before any `Platform.fetchUrl`; a CORS failure shows `role="alert"` mentioning CORS and the desktop app with _Paste instead_ (textbox _Paste the content_, _Import_) |
| About | toolbar button _About_ → `role="dialog"` (_About_) with the §9 notes, the SD-CWT revision, and registry dates from `engine.info()` |

## Areas and test files

| Area | Files | Tests |
|---|---|---|
| Tree sync: collapse/expand and selection keyed by NodeId; state survives re-render and edit | `components/treeSync`, `unit/lines`, `unit/tree` | 8 + 10 + 2 |
| Raw-row ↔ main-line alignment (hex) and segment highlight (JOSE) | `unit/lines` (above), `components/rawPane` | 5 |
| Action enablement, "what's missing" tooltips, Re-encode's three CBOR serializations | `unit/actions`, `components/actions` | 13 + 6 |
| Actions open derived tabs with a provenance breadcrumb; SD marks and Issue | `unit/workspace`, `components/provenance`, `components/issue` | 17 + 3 + 2 |
| _Detected as…_, unwrapping breadcrumb, paste/clipboard input, keys routed to the panel | `components/detect` | 5 |
| Live edit → "modified – signature stale", Re-sign / Keep original signature | `components/liveEdit` | 5 |
| Key panel: create (alg list, seeded), import paste/file/clipboard, export with explicit private choice and labelled copy, JWK/CWK side by side, thumbprints, auto kid, roles | `unit/keyStore`, `components/keyPanel` | 12 + 12 |
| Validation checklist with NodeId links; SD view | `components/validation`, `components/disclosures` | 6 + 2 |
| Date/time chit: synced fields, pre-fill, Insert in live edit, Use as clock | `components/dateTimeChit` | 5 |
| URL fetch always confirmed; CORS explanation and paste fallback | `unit/fetch`, `components/fetch` | 4 + 4 |
| Hover text from the registry display text; inline time hints | `unit/hover`, `components/annotations` | 4 + 3 |
| Never persist: storage spied during full flows; static scans; registry cache in IndexedDB | `unit/neverPersist` | 4 (2 pass now) |
| Accessibility: ARIA roles, keyboard navigation of trees and tabs, split, dialogs | `components/a11y` | 6 |
| Settings and clock | `unit/settings` | 3 (1 passes now) |
| About box with §9 notes | `components/about` | 2 (1 passes now) |
| Scaffold: engine/platform selection, base64url, defaults, EDN mode, fixture consistency, production CSP | `scaffold/*` | 21 (pass now) |

Total: 164 tests; 25 pass against the scaffold, 139 fail until implemented.

Behaviour tests fail against the stubs (stub methods throw
`NotImplemented`, stub components render placeholders); scaffold tests pass.

### Rules encoded in the tests

- **Action enablement** (`logic/actions.ts`): Issue needs a claim set and an
  issuer key with a private part; Redact also needs a marked claim (JSON SD
  marks, or tags 58/62 in EDN); Disclose needs an SD credential with
  disclosures and no key binding; Present needs an SD-JWT, SD-CWT, or plain
  CWT without key binding, and a holder key with a private part; Validate,
  Tamper, and Re-encode need a signed credential; Re-sign needs a signed
  credential and a private key; Edit disclosures needs an SD-JWT or SD-CWT.
  Re-encode offers _As received_, _Preferred-plus_, and _Deterministic_ for
  COSE, and compact / flattened / general JSON for JOSE.
- **Derived tabs**: every credential-producing action (Issue, Redact,
  Disclose, Present, Re-sign, Tamper, Re-encode, Edit disclosures) opens a
  new tab with provenance `derived` and becomes active; the breadcrumb lists
  the ancestors from the root tab. Randomness (32 bytes) and `iat`/`now` come
  from `Platform`/`Settings`, never from the engine.
- **Live edit**: a successful `parseEdit` with `signature_stale` marks the
  tab stale; a failed parse keeps the last good document and shows the
  diagnostic; _Re-sign_ opens a derived tab; _Keep original signature_ keeps
  the stale bytes and labels the tab _tampered_.
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

- #33: UI defaults: CSP, the read-only main pane as a line tree, hex
  alignment by EDN line, action enablement rules, live-edit outcomes, the
  labelled private-key copy, keys routed from the input area, TypeScript 6.
- #34: core TS export: `#[serde(default)]` fields are required `T | null`
  in TypeScript (the app uses `lib/engine/defaults.ts`), and how raw
  `detect`/`open` input crosses the boundary.
