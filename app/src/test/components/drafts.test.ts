// New drafts and explicit type in the UI (#43; app/TEST-PLAN.md UI
// contract: Input area, Empty state, Draft header).
import { screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { EditorView } from '@codemirror/view';
import { describe, expect, it } from 'vitest';
import AppShell from '../../lib/components/AppShell.svelte';
import { DRAFT_TEMPLATES } from '../../lib/logic/drafts';
import * as fx from '../fixtures';
import { renderWithApp, seedKeys, setupApp, type TestApp } from '../render';

function app(format: 'json' | 'edn' = 'json'): TestApp {
  const a = setupApp();
  a.engine.parseEdit.mockResolvedValue(
    fx.edited(format === 'json' ? fx.emptyJsonDraft : fx.emptyEdnDraft),
  );
  a.engine.detect.mockResolvedValue(
    format === 'json' ? fx.jsonClaimsDetected : fx.ednClaimsDetected,
  );
  return a;
}

function editor(): EditorView {
  const view = EditorView.findFromDOM(screen.getByTestId('live-editor'));
  if (!view) throw new Error('no CodeMirror view');
  return view;
}

function editTo(text: string) {
  const view = editor();
  view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: text } });
}

async function newDraft(a: TestApp, format: 'json' | 'edn' = 'json') {
  renderWithApp(AppShell, {}, a);
  await userEvent.click(screen.getByRole('button', { name: 'New' }));
  await screen.findByTestId('live-editor');
  if (format === 'edn') {
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Format' }), 'edn');
    await waitFor(() => expect(editor().state.doc.toString()).toBe(DRAFT_TEMPLATES.edn));
  }
}

describe('starting a draft', () => {
  it('New opens a tab in Live edit with the JSON template and provenance "New"', async () => {
    const a = app();
    await newDraft(a);
    expect(screen.getAllByRole('tab')).toHaveLength(1);
    expect(screen.getByRole('switch', { name: 'Live edit' })).toHaveAttribute(
      'aria-checked',
      'true',
    );
    expect(editor().state.doc.toString()).toBe(DRAFT_TEMPLATES.json);
    expect(screen.getByRole('combobox', { name: 'Format' })).toHaveValue('json');
    expect(screen.getByRole('navigation', { name: 'Provenance' })).toHaveTextContent('New');
    expect(screen.getByTestId('detected-type')).toHaveTextContent('JSON claim set');
  });

  it('the empty state offers New JSON draft and New EDN draft', async () => {
    const a = app('edn');
    renderWithApp(AppShell, {}, a);
    await userEvent.click(screen.getByRole('button', { name: 'New EDN draft' }));
    await screen.findByTestId('live-editor');
    expect(screen.getByRole('combobox', { name: 'Format' })).toHaveValue('edn');
    expect(a.engine.parseEdit).toHaveBeenCalledWith(
      expect.objectContaining({ kind: { type: 'edn_claims' }, text: DRAFT_TEMPLATES.edn }),
    );
    expect(screen.getByRole('button', { name: 'New JSON draft' })).toBeInTheDocument();
  });

  it('only draft tabs have a Format select', async () => {
    const a = app();
    renderWithApp(AppShell, {}, a);
    await userEvent.click(screen.getByRole('textbox', { name: /paste a credential or key/i }));
    await userEvent.paste(fx.jwtToken);
    a.engine.detect.mockResolvedValueOnce(fx.jwtCandidates);
    await userEvent.click(screen.getByRole('button', { name: 'Open' }));
    await waitFor(() => expect(screen.getAllByRole('tab')).toHaveLength(1));
    expect(screen.queryByRole('combobox', { name: 'Format' })).toBeNull();
  });
});

describe('type', () => {
  it('the header shows the type detected from the text as it is edited', async () => {
    const a = app('edn');
    await newDraft(a, 'edn');
    a.engine.detect.mockResolvedValue(fx.cwtEdnDetected);
    a.engine.parseEdit.mockResolvedValue(fx.cwtDraftEdit);
    editTo(fx.CWT_EDN);
    await waitFor(() => expect(screen.getByTestId('detected-type')).toHaveTextContent('CWT'));
    expect(screen.queryByText('modified – signature stale')).toBeNull();
    expect(
      within(screen.getByRole('toolbar', { name: 'Actions' })).getByRole('button', {
        name: 'Validate',
      }),
    ).toHaveAttribute('aria-disabled', 'false');
  });

  it('"Detected as…" sets the type explicitly, and the choice survives edits', async () => {
    const a = app('edn');
    await newDraft(a, 'edn');
    await userEvent.click(screen.getByRole('button', { name: /detected as/i }));
    const menu = screen.getByRole('menu');
    const items = within(menu).getAllByRole('menuitemradio');
    expect(items.map((i) => i.textContent?.replace(/\s*\(detected\)/, '').trim())).toEqual([
      'Auto-detect',
      'EDN claim set',
      'COSE_Sign1',
      'CWT',
      'SD-CWT',
      'SD-KBT',
      'COSE_Key',
      'COSE_KeySet',
    ]);
    expect(items[0]).toHaveAttribute('aria-checked', 'true');
    expect(within(menu).getByRole('menuitemradio', { name: /EDN claim set/ })).toHaveTextContent(
      '(detected)',
    );

    a.engine.parseEdit.mockResolvedValue(fx.edited(fx.coseKeyDraft));
    await userEvent.click(within(menu).getByRole('menuitemradio', { name: /COSE_Key$/ }));
    await waitFor(() => expect(screen.getByTestId('detected-type')).toHaveTextContent('COSE_Key'));
    expect(a.engine.parseEdit).toHaveBeenLastCalledWith(
      expect.objectContaining({ kind: { type: 'cose_key' } }),
    );

    editTo(fx.ISSUER_CWK_EDN);
    await waitFor(() =>
      expect(a.engine.parseEdit).toHaveBeenLastCalledWith(
        expect.objectContaining({ kind: { type: 'cose_key' }, text: fx.ISSUER_CWK_EDN }),
      ),
    );
    expect(screen.getByTestId('detected-type')).toHaveTextContent('COSE_Key');
    await userEvent.click(screen.getByRole('button', { name: /detected as/i }));
    expect(
      within(screen.getByRole('menu')).getByRole('menuitemradio', { name: /COSE_Key$/ }),
    ).toHaveAttribute('aria-checked', 'true');
  });

  it('key types offer "Add to key panel"', async () => {
    const a = app();
    await newDraft(a);
    a.engine.detect.mockResolvedValue(fx.jwkDetected);
    editTo(fx.VERIFIER_JWK);
    await waitFor(() => expect(screen.getByTestId('detected-type')).toHaveTextContent('JWK'));
    await userEvent.click(screen.getByRole('button', { name: 'Add to key panel' }));
    const keys = screen.getByRole('complementary', { name: 'Keys' });
    await waitFor(() => expect(within(keys).getAllByRole('article')).toHaveLength(1));
    expect(within(keys).getByRole('article')).toHaveTextContent('New');
  });

  it('a detected token that is not a draft type can be opened as such', async () => {
    const a = app();
    await newDraft(a);
    a.engine.detect.mockResolvedValue(fx.jwsJsonDetected);
    a.engine.parseEdit.mockResolvedValue(fx.edited(fx.jsonDraft));
    editTo('{"payload":"e30","protected":"e30","signature":""}');
    await userEvent.click(await screen.findByRole('button', { name: 'Open as JWS JSON' }));
    await waitFor(() => expect(screen.getAllByRole('tab')).toHaveLength(2));
    expect(a.engine.open).toHaveBeenCalled();
  });
});

describe('Format', () => {
  it('switching JSON → EDN converts the draft', async () => {
    const a = app();
    await newDraft(a);
    a.engine.parseEdit.mockResolvedValue(fx.edited(fx.jsonDraft));
    editTo(fx.DRAFT_JSON_TEXT);
    await waitFor(() =>
      expect(a.engine.parseEdit).toHaveBeenCalledWith(
        expect.objectContaining({ text: fx.DRAFT_JSON_TEXT }),
      ),
    );
    a.engine.parseEdit.mockResolvedValue(fx.edited(fx.convertedToEdn.document ?? fx.emptyEdnDraft));
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Format' }), 'edn');
    await waitFor(() => expect(editor().state.doc.toString()).toBe(fx.DRAFT_EDN_TEXT));
    expect(screen.queryByRole('alertdialog')).toBeNull();
    expect(screen.getByTestId('detected-type')).toHaveTextContent('EDN claim set');
  });

  it('EDN → JSON that has no JSON form asks before discarding', async () => {
    const a = app('edn');
    await newDraft(a, 'edn');
    editTo("{1: h'00'}");
    a.engine.convertClaims.mockResolvedValue(fx.notRepresentable);
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Format' }), 'json');
    const ask = await screen.findByRole('alertdialog');
    expect(ask).toHaveTextContent('a byte string has no JSON form');
    await userEvent.click(within(ask).getByRole('button', { name: 'Cancel' }));
    expect(screen.getByRole('combobox', { name: 'Format' })).toHaveValue('edn');
    expect(editor().state.doc.toString()).toBe("{1: h'00'}");

    a.engine.parseEdit.mockResolvedValue(fx.edited(fx.emptyJsonDraft));
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Format' }), 'json');
    await userEvent.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', {
        name: 'Discard and switch',
      }),
    );
    await waitFor(() =>
      expect(screen.getByRole('combobox', { name: 'Format' })).toHaveValue('json'),
    );
    expect(editor().state.doc.toString()).toBe(DRAFT_TEMPLATES.json);
  });
});

describe('actions', () => {
  it('a claim-set draft can be issued from the toolbar', async () => {
    const a = app();
    seedKeys(a, fx.issuerCard);
    await newDraft(a);
    a.engine.parseEdit.mockResolvedValue(fx.edited(fx.jsonDraft));
    editTo(fx.DRAFT_JSON_TEXT);
    const issue = within(screen.getByRole('toolbar', { name: 'Actions' })).getByRole('button', {
      name: 'Issue',
    });
    await waitFor(() => expect(issue).toHaveAttribute('aria-disabled', 'false'));
    await userEvent.click(issue);
    await userEvent.click(
      within(screen.getByRole('dialog', { name: 'Issue' })).getByRole('button', { name: 'Issue' }),
    );
    await waitFor(() => expect(a.engine.issue).toHaveBeenCalled());
    expect(a.engine.issue.mock.calls[0]?.[0].claims.bytes).toBe(fx.jsonDraft.bytes);
    await waitFor(() => expect(screen.getAllByRole('tab')).toHaveLength(2));
  });
});
