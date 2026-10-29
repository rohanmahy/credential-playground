# macOS desktop smoke test checklist

A manual click-through of the packaged desktop app. Automated WebDriver
tests can't drive WKWebView on macOS, so this covers what CI can't: the
real `.app`, native dialogs, the system clipboard, and real network fetches.
Linux CI runs the automated equivalent through `tauri-driver`
(`app/e2e-desktop`, also `scripts/desktop-e2e-docker.sh` on a Mac). Sections
marked _Also automated on Linux_ have WebDriver counterparts there, as noted;
keep doing them by hand here, since WKWebView and macOS differ.

Takes about 15 minutes. Run it before tagging a release.

## Setup

- [ ] Build: `cd app && pnpm tauri build --bundles app`, or download the
      `.app` zip from the GitHub release you're testing.
- [ ] Open `target/release/bundle/macos/The Tokenator.app`. The app is
      unsigned, so the first launch needs right-click → **Open** → **Open**.
- [ ] Note the version in **About**, and the date, at the bottom of this file.

Fixtures are in `testdata/`. To get one onto the clipboard, run
`pbcopy < testdata/tokens/<file>`. For a binary file, use **Open file…**.

## 1. Launch and About

_Also automated on Linux:_ the window contents and About (`launch.e2e.ts`). Not appearance.

- [ ] The window opens with the input box, the **Keys** panel, and an empty
      tab area. No error dialogs appear.
- [ ] **About** shows the §9 security notes, the SD-CWT revision
      (`draft-ietf-spice-sd-cwt-08`), and the registry dates.
- [ ] Light/dark: switch macOS appearance (System Settings → Appearance).
      The app follows it without a restart.

## 2. Input paths (native clipboard and file dialog)

_Also automated on Linux:_ the same fixtures through the input box, plus the
Bearer layer (`paste-validate.e2e.ts`). Not **From clipboard** or **Open file…**.

- [ ] `pbcopy < testdata/tokens/rfc7515-a3-jws-es256.txt`, then click
      **From clipboard**. A tab opens with the detected type **JWT/JWS** and
      the provenance **Clipboard**.
- [ ] **Open file…** → pick `testdata/tokens/rfc8392-a3-signed-cwt.cbor`
      (binary). It opens as a CWT with the provenance **File: rfc8392-a3-signed-cwt.cbor**.
      The unwrapping breadcrumb shows the CBOR tag layer.
- [ ] Paste `testdata/tokens/rfc8392-a3-signed-cwt.hex` into the input box
      and click **Open**. The breadcrumb shows a **Hex** layer, and the tree
      matches the binary version.
- [ ] Paste the same JWT prefixed with `Bearer `. The breadcrumb shows
      **Bearer prefix**.

## 3. Synced panes (CBOR)

_Also automated on Linux:_ fold and selection sync, and the raw pane toggle
(`tree-sync.e2e.ts`). Not hover text or time hints.

With the CWT tab open:

- [ ] The main pane shows EDN, with registry annotations (e.g. `/ iss /`).
      Hovering over an annotated name shows its description, with no draft
      revision numbers in the reference.
- [ ] The raw pane shows annotated hex rows, lined up with the EDN lines.
- [ ] Collapsing the payload in one pane collapses it in the other.
- [ ] Clicking a claim in the main pane highlights its hex rows, and vice versa.
- [ ] Time claims (`exp`, `iat`) show an inline human-readable date.
- [ ] Turn off **Show raw pane**, then turn it back on. The collapse state
      is kept.

## 4. Keys (native dialogs and clipboard)

_Also automated on Linux:_ create with the seed, kid, Convert, the private
export gate, a public JWK copied to the clipboard and imported back, and
Derive public key (`keys.e2e.ts`). Not **Save…** or **From file…**.

- [ ] **Create key** → ES256, **Well-known test seed**, role **Issuer** →
      **Create**. A card appears with kid `(none)`, the provenance
      **Generated**, and both thumbprints.
- [ ] **Set kid** → **JWK thumbprint**. The kid updates.
- [ ] **Convert** shows JWK and COSE_Key side by side. Private material
      stays hidden until you turn on **Private**.
- [ ] **Export** → JWK, **Public** → copy. `pbpaste` prints a public JWK
      with no `d`.
- [ ] **Export** → PEM, **Private**: **Copy private key** stays disabled
      until you tick **I understand this exports the private key**. After
      copying, the status says "Private key copied to clipboard".
- [ ] **Export** → COSE_Key → **Save…** opens the native macOS save dialog.
      The saved file re-imports through **Import key** → **From file…**.
- [ ] **Import key** → **From file…** →
      `testdata/keys/sd-cwt-08-c1-holder-private.pem`. Set its role to
      **Holder**.
- [ ] **Derive public key** on that card adds a public-only card linked to it.

## 5. JOSE flow: validate, issue, present

_Also automated on Linux:_ mark SD → Issue with `cnf` → Present with audience
and nonce → key binding PASS (`issue-present.e2e.ts`), and the RFC 9901
signature with its key (`paste-validate.e2e.ts`).

- [ ] Paste `testdata/tokens/rfc9901-s5.1-sd-jwt.txt` and click **Open**.
      The Disclosures table shows 10 rows, all **matched**.
- [ ] Import `testdata/keys/rfc9901-a5-ec-p256-public.jwk.json`, then
      **Validate**. The signature is PASS with ES256. Note the overall status
      (see #31).
- [ ] Paste `testdata/tokens/rfc9901-s5.1-input-claims.json` (opens as an
      unsigned claim set). Right-click a claim line → **Selectively
      disclosable** on two claims.
- [ ] **Issue** with the ES256 issuer key and the holder key as **Holder key
      (cnf)**. A new SD-JWT tab opens, and its provenance breadcrumb points
      back to the claims tab.
- [ ] **Present** from the new tab: untick one disclosure, choose the holder
      key, and enter an audience and a nonce. A new tab with a KB-JWT opens.
- [ ] **Validate** the presentation, with the audience and nonce filled in.
      Key binding is PASS.

## 6. COSE flow: redact, present, re-encode

_Also automated on Linux:_ Redact → Present → SD-KBT → key binding PASS
(`issue-present.e2e.ts`). Not the `58(…)` edit or **Re-encode**.

- [ ] Paste `testdata/tokens/sd-cwt-08-fig4-claims.edn`, turn on **Live
      edit**, and wrap one claim key in `58(…)`. **Redact** is enabled.
- [ ] Create an ES256 issuer key if needed, then **Redact** / **Issue** an
      SD-CWT. The disclosures show in the SD view.
- [ ] **Present** with the holder key. An SD-KBT tab opens, with the SD-CWT
      nested under `kcwt`.
- [ ] **Validate** the SD-KBT. The signature and key binding are PASS.
- [ ] On the SD-CWT tab, **Re-encode** → **Deterministic** opens a new tab.
      **Re-encode** → **As received** reproduces the original bytes.

## 7. Live edit and tamper

_Also automated on Linux:_ edit → stale → **Keep original signature** → FAIL
→ **Re-sign** → PASS (`live-edit.e2e.ts`). Not **Split view** or **Tamper**.

- [ ] On a signed tab, turn on **Live edit** and change one claim value. The
      status shows "modified – signature stale", with **Re-sign** and
      **Keep original signature**.
- [ ] **Keep original signature** → **Validate**. The signature is FAIL, and
      the badge says **tampered**.
- [ ] **Re-sign** with the matching private key → **Validate**. The
      signature is PASS. Only the edited bytes changed (compare the raw panes
      with **Split view**).
- [ ] **Tamper** → swap `alg` to `none`. The new tab fails validation, and
      the lint flags `alg: none`.

## 8. Date/time chit

- [ ] Select an `exp` node, then open **Date/time**. The fields are pre-filled.
- [ ] Edit **RFC 3339 (UTC)**. Epoch, milliseconds, local time, and the CBOR
      forms update together, and the relative time changes.
- [ ] **Use as clock** sets the validation clock. Re-validating a token
      after its `exp` now shows the time claim as FAIL.

## 9. Network (real fetch through the desktop shell)

- [ ] **Fetch from URL** → enter an https JWKS URL you trust → **Fetch**. A
      confirmation dialog shows the URL and the IP-disclosure note before
      anything is fetched. **Cancel** fetches nothing.
- [ ] Confirm the fetch. The keys import with the provenance **URL: …**.
      There's no CORS error, because the desktop app doesn't have CORS.
- [ ] Enter an `http://` URL. It's refused (https only).
- [ ] **Settings** → **Update registries** → confirm. The registry dates in
      **About** change.

## 10. Never persist

_Also automated on Linux:_ restart with no keys or tabs, and no user data in
`~/.local/share/io.github.rohanmahy.tokenator/` (`never-persist.e2e.ts`).

- [ ] Quit the app (⌘Q) and reopen it. No keys or tabs come back.
- [ ] Only the registry cache exists on disk:
      `ls ~/Library/Application\ Support/io.github.rohanmahy.tokenator/`
      shows only the registry cache file (or nothing, if you skipped §9).
- [ ] `ls ~/Library/WebKit/io.github.rohanmahy.tokenator` either doesn't
      exist or contains no local storage or IndexedDB data.

## 11. Keyboard and accessibility

- [ ] In the main pane, use ArrowUp/Down to move, Left/Right to fold and
      unfold, and Enter to select.
- [ ] In the tab bar, ArrowLeft/Right switch tabs.
- [ ] VoiceOver (⌘F5) announces the tree items and the action buttons.
      Disabled actions read out what's missing.

## Result

| Date | Version / commit | Tester | Pass/fail | Notes and issues filed |
|---|---|---|---|---|
| | | | | |
