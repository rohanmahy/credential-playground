// Per-area input on the credential side (SPEC §3, §4, §4.1): no global
// input box; the app starts with one empty tab; "+" opens another; paste
// or drop into an EMPTY tab runs token detection (`engine.detect`) and the
// tab becomes the decoded view, still editable; a non-empty tab never
// re-detects; Clear empties the tab without touching the keys; drops are
// accepted only on an empty text area. Names: ../ui.ts.
import { screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import AppShell from '../../lib/components/AppShell.svelte';
import { b64uToText, utf8 } from '../../lib/engine/bytes';
import * as fx from '../fixtures';
import { parseAsKind } from '../MockEngine';
import { renderWithApp, seedKeys, setupApp, type TestApp } from '../render';
import {
  NAMES,
  activePanel,
  dropOnto,
  pasteInto,
  tabBox,
  tabButton,
  textOf,
  typeInto,
} from '../ui';

function shell(setup: (app: TestApp) => void = () => undefined): TestApp {
  const app = setupApp();
  app.engine.parseEdit.mockImplementation(parseAsKind);
  setup(app);
  renderWithApp(AppShell, {}, app);
  return app;
}

const tabs = () => within(screen.getByRole('tablist', { name: 'Credentials' })).getAllByRole('tab');
const detectedType = () => within(activePanel()).getByTestId('detected-type');

/** Paste a JWT into the active (empty) tab and wait for the decoded view. */
async function pasteJwt(app: TestApp) {
  await pasteInto(tabBox(), fx.jwtToken);
  await waitFor(() => expect(app.engine.open).toHaveBeenCalled());
  await waitFor(() => expect(detectedType()).toHaveTextContent('JWT'));
}

describe('shell', () => {
  it('has no global input box; the header keeps Date/time, Settings, and About', () => {
    shell();
    expect(screen.queryByRole('textbox', { name: /paste a credential or key/i })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Open' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'New' })).toBeNull();
    expect(screen.queryByRole('button', { name: /New (JSON|EDN) draft/ })).toBeNull();
    const tools = screen.getByRole('navigation', { name: 'Tools' });
    for (const name of ['Date/time', 'Settings', 'About']) {
      expect(within(tools).getByRole('button', { name })).toBeInTheDocument();
    }
  });

  it('the web build has no menu bar', () => {
    shell();
    expect(screen.queryByRole('menubar')).toBeNull();
  });
});

describe('empty tabs', () => {
  it('on startup one empty tab is open, editable, with a type picker and the input buttons', () => {
    const app = shell();
    expect(tabs()).toHaveLength(1);
    expect(tabs()[0]).toHaveAttribute('aria-selected', 'true');
    const box = tabBox();
    expect(textOf(box)).toBe('');
    const type = within(activePanel()).getByRole('combobox', { name: NAMES.type });
    expect(type).toHaveDisplayValue(NAMES.jsonClaims);
    expect(within(type).getByRole('option', { name: NAMES.ednClaims })).toBeInTheDocument();
    expect(tabButton(NAMES.openFile)).toBeInTheDocument();
    expect(tabButton(NAMES.fromClipboard)).toBeInTheDocument();
    expect(app.engine.detect).not.toHaveBeenCalled();
    expect(app.workspace.tabs).toHaveLength(1);
  });

  it('the "+" button opens another empty tab and activates it', async () => {
    const app = shell();
    await userEvent.click(screen.getByRole('button', { name: NAMES.newTab }));
    expect(tabs()).toHaveLength(2);
    expect(tabs()[1]).toHaveAttribute('aria-selected', 'true');
    expect(textOf(tabBox())).toBe('');
    expect(within(activePanel()).getByRole('combobox', { name: NAMES.type })).toBeInTheDocument();
    expect(app.workspace.tabs.map((t) => t.empty)).toEqual([true, true]);
  });

  it('"+" works next to decoded tabs too, and each new tab is empty', async () => {
    const app = shell();
    await pasteJwt(app);
    await userEvent.click(screen.getByRole('button', { name: NAMES.newTab }));
    expect(tabs()).toHaveLength(2);
    expect(textOf(tabBox())).toBe('');
    expect(within(activePanel()).queryByTestId('detected-type')).toBeNull();
  });
});

describe('first fill of an empty tab', () => {
  it('paste runs token detection; the tab becomes the decoded view, in Live edit', async () => {
    const app = shell();
    await pasteJwt(app);
    expect(app.engine.detect).toHaveBeenCalledTimes(1);
    expect(app.engine.detect).toHaveBeenCalledWith(utf8(fx.jwtToken));
    expect(app.engine.open).toHaveBeenCalledWith(
      utf8(fx.jwtToken),
      fx.jwtCandidates[0],
      expect.anything(),
    );
    expect(app.engine.detectKey).not.toHaveBeenCalled();
    const panel = activePanel();
    expect(within(panel).getByRole('toolbar', { name: 'Actions' })).toBeInTheDocument();
    expect(within(panel).getByRole('tree', { name: 'Raw pane' })).toBeInTheDocument();
    expect(within(panel).getByRole('switch', { name: 'Live edit' })).toHaveAttribute(
      'aria-checked',
      'true',
    );
    expect(tabBox()).toBeInTheDocument();
    expect(within(panel).getByRole('navigation', { name: 'Provenance' })).toHaveTextContent(
      'Pasted',
    );
    expect(within(panel).queryByRole('combobox', { name: NAMES.type })).toBeNull();
    // the paste filled this tab; it did not open another
    expect(tabs()).toHaveLength(1);
    expect(tabs()[0]).toHaveTextContent('JWT');
    expect(app.workspace.tabs[0]?.empty).toBe(false);
  });

  it('a pasted compact SD-JWT is detected; the tab is the SD-JWT view with its disclosures', async () => {
    const sdJwtToken = b64uToText(fx.sdJwt.bytes);
    const app = shell((a) =>
      a.engine.detect.mockResolvedValueOnce([
        {
          kind: { type: 'sd_jwt', kb: false },
          confidence: 95,
          layers: [],
          payload_range: { start: 0, end: sdJwtToken.length },
          breadcrumb: ['SD-JWT'],
        },
      ]),
    );
    await pasteInto(tabBox(), sdJwtToken);
    await waitFor(() => expect(detectedType()).toHaveTextContent(/^SD-JWT$/));
    expect(app.engine.detect).toHaveBeenCalledWith(utf8(sdJwtToken));
    expect(app.engine.open).toHaveBeenCalledWith(
      utf8(sdJwtToken),
      expect.objectContaining({ kind: { type: 'sd_jwt', kb: false } }),
      expect.anything(),
    );
    const panel = activePanel();
    expect(within(panel).getByRole('table', { name: 'Disclosures' })).toBeInTheDocument();
    expect(within(panel).getByRole('switch', { name: 'Live edit' })).toHaveAttribute(
      'aria-checked',
      'true',
    );
    expect(tabs()).toHaveLength(1);
    expect(tabs()[0]).toHaveTextContent('SD-JWT');
  });

  it('a JWK pasted into a tab opens as a JSON claim set and adds no key', async () => {
    const app = shell((a) => a.engine.detect.mockResolvedValueOnce(fx.claimsCandidates));
    await pasteInto(tabBox(), fx.ISSUER_JWK);
    await waitFor(() => expect(detectedType()).toHaveTextContent('JSON claim set'));
    expect(app.engine.detect).toHaveBeenCalledWith(utf8(fx.ISSUER_JWK));
    expect(app.engine.detectKey).not.toHaveBeenCalled();
    expect(app.engine.keyImport).not.toHaveBeenCalled();
    expect(app.keys.forRole('issuer')).toBeNull();
    expect(app.keys.forRole('holder')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Add to key panel' })).toBeNull();
  });

  it('ambiguous input is resolved with "Detected as…" (JSON claim set → EDN claim set)', async () => {
    const app = shell((a) => a.engine.detect.mockResolvedValueOnce(fx.jsonOrEdnCandidates));
    await pasteInto(tabBox(), fx.DRAFT_JSON_TEXT);
    await waitFor(() => expect(detectedType()).toHaveTextContent('JSON claim set'));
    await userEvent.click(within(activePanel()).getByRole('button', { name: /detected as/i }));
    await userEvent.click(screen.getByRole('menuitemradio', { name: /^EDN claim set/ }));
    await waitFor(() => expect(detectedType()).toHaveTextContent('EDN claim set'));
    // choosing a reading is not a re-detection
    expect(app.engine.detect).toHaveBeenCalledTimes(1);
  });

  it('typing into an empty tab does not autodetect; it parses as the picked type', async () => {
    const app = shell();
    await typeInto(tabBox(), '{"iss":"x"}');
    await waitFor(() =>
      expect(app.engine.parseEdit).toHaveBeenLastCalledWith(
        expect.objectContaining({ kind: { type: 'json_claims' }, text: '{"iss":"x"}' }),
      ),
    );
    expect(app.engine.detect).not.toHaveBeenCalled();
    await waitFor(() => expect(detectedType()).toHaveTextContent('JSON claim set'));
  });

  it('the type picker applies to typed text (EDN claims)', async () => {
    const app = shell();
    await userEvent.selectOptions(
      within(activePanel()).getByRole('combobox', { name: NAMES.type }),
      NAMES.ednClaims,
    );
    await typeInto(tabBox(), '{1: "x"}');
    await waitFor(() =>
      expect(app.engine.parseEdit).toHaveBeenLastCalledWith(
        expect.objectContaining({ kind: { type: 'edn_claims' }, text: '{1: "x"}' }),
      ),
    );
    expect(app.engine.detect).not.toHaveBeenCalled();
    await waitFor(() => expect(detectedType()).toHaveTextContent('EDN claim set'));
  });

  it('From clipboard fills the empty tab and runs token detection', async () => {
    const app = shell((a) => (a.platform.clipboard = fx.jwtToken));
    await userEvent.click(tabButton(NAMES.fromClipboard));
    await waitFor(() => expect(app.engine.detect).toHaveBeenCalledWith(utf8(fx.jwtToken)));
    await waitFor(() => expect(detectedType()).toHaveTextContent('JWT'));
    expect(tabs()).toHaveLength(1);
    expect(within(activePanel()).getByRole('navigation', { name: 'Provenance' })).toHaveTextContent(
      'Clipboard',
    );
  });

  it('Open file… fills the empty tab and runs token detection', async () => {
    const app = shell((a) => {
      a.platform.files = [{ name: 'token.cwt', bytes: utf8('d28443a10126') }];
      a.engine.detect.mockResolvedValueOnce(fx.cwtHexCandidates);
    });
    await userEvent.click(tabButton(NAMES.openFile));
    await waitFor(() => expect(app.engine.detect).toHaveBeenCalledWith(utf8('d28443a10126')));
    await waitFor(() => expect(detectedType()).toHaveTextContent('CWT'));
    expect(tabs()).toHaveLength(1);
    expect(within(activePanel()).getByRole('navigation', { name: 'Provenance' })).toHaveTextContent(
      'File: token.cwt',
    );
  });

  it('nothing detected: the tab stays empty and says so', async () => {
    const app = shell((a) => a.engine.detect.mockResolvedValueOnce([]));
    await pasteInto(tabBox(), 'hello');
    await waitFor(() => expect(app.engine.detect).toHaveBeenCalled());
    expect(await within(activePanel()).findByRole('alert')).toHaveTextContent(/recogni/i);
    expect(app.engine.open).not.toHaveBeenCalled();
  });
});

describe('JWT and SD-JWT in the Type picker', () => {
  const sdJwtToken = b64uToText(fx.sdJwt.bytes);
  const typePicker = () => within(activePanel()).getByRole('combobox', { name: NAMES.type });

  it('the Type picker offers JWT and SD-JWT besides the claim and COSE types', () => {
    shell();
    const type = typePicker();
    for (const name of [NAMES.jsonClaims, NAMES.ednClaims, NAMES.jwt, NAMES.sdJwt]) {
      expect(within(type).getByRole('option', { name })).toBeInTheDocument();
    }
    expect(type).toHaveDisplayValue(NAMES.jsonClaims);
  });

  it('JWT: a typed compact JWT parses as a JWT, without detection', async () => {
    const app = shell();
    await userEvent.selectOptions(typePicker(), NAMES.jwt);
    await typeInto(tabBox(), fx.jwtToken);
    await waitFor(() =>
      expect(app.engine.parseEdit).toHaveBeenLastCalledWith(
        expect.objectContaining({ kind: { type: 'jwt' }, base: '', text: fx.jwtToken }),
      ),
    );
    expect(app.engine.detect).not.toHaveBeenCalled();
    await waitFor(() => expect(detectedType()).toHaveTextContent(/^JWT$/));
    expect(tabs()[0]).toHaveTextContent('JWT');
  });

  it('SD-JWT: a typed compact SD-JWT parses as an SD-JWT and lists its disclosures', async () => {
    const app = shell();
    await userEvent.selectOptions(typePicker(), NAMES.sdJwt);
    await typeInto(tabBox(), sdJwtToken);
    await waitFor(() =>
      expect(app.engine.parseEdit).toHaveBeenLastCalledWith(
        expect.objectContaining({
          kind: { type: 'sd_jwt', kb: false },
          base: '',
          text: sdJwtToken,
        }),
      ),
    );
    expect(app.engine.detect).not.toHaveBeenCalled();
    await waitFor(() => expect(detectedType()).toHaveTextContent(/^SD-JWT$/));
    expect(within(activePanel()).getByRole('table', { name: 'Disclosures' })).toBeInTheDocument();
  });

  it('a paste into the typed (non-empty) tab parses as the picked type, no detection', async () => {
    const app = shell();
    await userEvent.selectOptions(typePicker(), NAMES.sdJwt);
    // a space typed first makes the tab non-empty, so the paste is an edit
    await typeInto(tabBox(), ' ');
    await pasteInto(tabBox(), sdJwtToken);
    await waitFor(() =>
      expect(app.engine.parseEdit).toHaveBeenLastCalledWith(
        expect.objectContaining({
          kind: { type: 'sd_jwt', kb: false },
          text: expect.stringContaining(sdJwtToken),
        }),
      ),
    );
    await new Promise((r) => setTimeout(r, 300));
    expect(app.engine.detect).not.toHaveBeenCalled();
    expect(detectedType()).toHaveTextContent(/^SD-JWT$/);
  });
});

describe('a non-empty tab', () => {
  it('a paste never re-runs detection; the text re-parses as the tab type', async () => {
    const app = shell();
    await pasteJwt(app);
    app.engine.detect.mockResolvedValue(fx.cwtHexCandidates);
    await pasteInto(tabBox(), ' ');
    await waitFor(() =>
      expect(app.engine.parseEdit).toHaveBeenLastCalledWith(
        expect.objectContaining({ kind: { type: 'jwt' } }),
      ),
    );
    await new Promise((r) => setTimeout(r, 300));
    expect(app.engine.detect).toHaveBeenCalledTimes(1);
    expect(detectedType()).toHaveTextContent('JWT');
  });

  it('typing never re-runs detection either; the type sticks', async () => {
    const app = shell();
    await typeInto(tabBox(), '{"iss":"x"}');
    await waitFor(() => expect(detectedType()).toHaveTextContent('JSON claim set'));
    await typeInto(tabBox(), ' ');
    await new Promise((r) => setTimeout(r, 300));
    expect(app.engine.detect).not.toHaveBeenCalled();
    expect(app.engine.parseEdit).toHaveBeenLastCalledWith(
      expect.objectContaining({ kind: { type: 'json_claims' } }),
    );
  });

  it('refuses drops (dropEffect none) and ignores them', async () => {
    const app = shell();
    await pasteJwt(app);
    const before = textOf(tabBox());
    const outcome = await dropOnto(tabBox(), { text: fx.CWT_EDN });
    expect(outcome.accepted).toBe(false);
    expect(outcome.dropEffect).toBe('none');
    await new Promise((r) => setTimeout(r, 300));
    expect(app.engine.detect).toHaveBeenCalledTimes(1);
    expect(textOf(tabBox())).toBe(before);
    expect(detectedType()).toHaveTextContent('JWT');
  });
});

describe('Clear', () => {
  it('resets text, type, decoded view, and title to an empty tab; keys are untouched', async () => {
    const app = shell((a) => seedKeys(a, fx.issuerCard, fx.holderCard));
    await pasteJwt(app);
    const before = tabs()[0]?.textContent ?? '';
    expect(before).toContain('JWT');
    await userEvent.click(tabButton(NAMES.clear));
    await waitFor(() => expect(textOf(tabBox())).toBe(''));
    const panel = activePanel();
    expect(within(panel).queryByTestId('detected-type')).toBeNull();
    expect(within(panel).queryByRole('toolbar', { name: 'Actions' })).toBeNull();
    expect(within(panel).getByRole('combobox', { name: NAMES.type })).toHaveDisplayValue(
      NAMES.jsonClaims,
    );
    expect(tabs()).toHaveLength(1);
    expect(tabs()[0]).not.toHaveTextContent('JWT');
    expect(app.workspace.tabs[0]?.empty).toBe(true);
    expect(app.keys.forRole('issuer')?.info.jwk_thumbprint).toBe(fx.issuerInfo.jwk_thumbprint);
    expect(app.keys.forRole('holder')?.info.jwk_thumbprint).toBe(fx.holderInfo.jwk_thumbprint);
  });

  it('after Clear the next paste autodetects again', async () => {
    const app = shell();
    await pasteJwt(app);
    await userEvent.click(tabButton(NAMES.clear));
    await waitFor(() => expect(textOf(tabBox())).toBe(''));
    app.engine.detect.mockResolvedValueOnce(fx.cwtHexCandidates);
    await pasteInto(tabBox(), 'd28443a10126');
    await waitFor(() => expect(app.engine.detect).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(detectedType()).toHaveTextContent('CWT'));
  });

  it('Clear resets a type chosen in the picker back to the default', async () => {
    shell();
    const type = () => within(activePanel()).getByRole('combobox', { name: NAMES.type });
    await userEvent.selectOptions(type(), NAMES.ednClaims);
    await typeInto(tabBox(), '{1: "x"}');
    await waitFor(() => expect(detectedType()).toHaveTextContent('EDN claim set'));
    await userEvent.click(tabButton(NAMES.clear));
    await waitFor(() => expect(type()).toHaveDisplayValue(NAMES.jsonClaims));
  });
});

describe('drag and drop', () => {
  it('an empty tab accepts a dropped text and runs token detection', async () => {
    const app = shell();
    const outcome = await dropOnto(tabBox(), { text: fx.jwtToken });
    expect(outcome.accepted).toBe(true);
    await waitFor(() => expect(app.engine.detect).toHaveBeenCalledWith(utf8(fx.jwtToken)));
    await waitFor(() => expect(detectedType()).toHaveTextContent('JWT'));
    expect(tabs()).toHaveLength(1);
  });

  it('an empty tab accepts a dropped file (detected from its bytes, provenance named)', async () => {
    const app = shell();
    const file = new File([fx.jwtToken], 'token.jwt', { type: 'text/plain' });
    const outcome = await dropOnto(tabBox(), { file });
    expect(outcome.accepted).toBe(true);
    await waitFor(() => expect(app.engine.detect).toHaveBeenCalledWith(utf8(fx.jwtToken)));
    await waitFor(() =>
      expect(
        within(activePanel()).getByRole('navigation', { name: 'Provenance' }),
      ).toHaveTextContent('token.jwt'),
    );
  });

  it('drops anywhere else in the window are refused and ignored', async () => {
    // A window-level guard may cancel dragover with dropEffect "none" (so a
    // dropped file cannot navigate the webview); either way it is refused.
    const app = shell();
    for (const target of [
      screen.getByRole('navigation', { name: 'Tools' }),
      screen.getByRole('tablist', { name: 'Credentials' }),
      document.body,
    ]) {
      const outcome = await dropOnto(target, { text: fx.jwtToken });
      expect(outcome.accepted, target.tagName).toBe(false);
      if (outcome.prevented) expect(outcome.dropEffect, target.tagName).toBe('none');
    }
    await new Promise((r) => setTimeout(r, 300));
    expect(app.engine.detect).not.toHaveBeenCalled();
    expect(app.engine.detectKey).not.toHaveBeenCalled();
    expect(tabs()).toHaveLength(1);
    expect(textOf(tabBox())).toBe('');
  });
});
