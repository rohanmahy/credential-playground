// Read-only / Live edit, "modified – signature stale", Re-sign, Keep
// original signature (SPEC §5 Live edit).
import { screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { EditorView } from '@codemirror/view';
import { describe, expect, it } from 'vitest';
import CredentialTab from '../../lib/components/CredentialTab.svelte';
import * as fx from '../fixtures';
import { renderWithApp, seedKeys, seedTab, setupApp } from '../render';

function mount() {
  const app = setupApp();
  seedKeys(app, fx.issuerCard);
  const tab = seedTab(app.workspace, fx.jwt);
  renderWithApp(CredentialTab, { tabId: tab.id }, app);
  return { app, tab };
}

async function editTo(text: string) {
  const view = EditorView.findFromDOM(screen.getByTestId('live-editor'));
  if (!view) throw new Error('no CodeMirror view');
  view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: text } });
}

describe('live edit', () => {
  it('switches the main pane to an editor with the document text', async () => {
    const { tab } = mount();
    const sw = screen.getByRole('switch', { name: 'Live edit' });
    expect(sw).toHaveAttribute('aria-checked', 'false');
    await userEvent.click(sw);
    expect(sw).toHaveAttribute('aria-checked', 'true');
    expect(tab.liveEdit).toBe(true);
    expect(screen.getByTestId('live-editor')).toHaveTextContent('"iss": "https://issuer.example"');
    expect(screen.queryByRole('tree', { name: 'Main pane' })).toBeNull();
  });

  it('an edit to signed content marks the tab "modified – signature stale"', async () => {
    const { app } = mount();
    await userEvent.click(screen.getByRole('switch', { name: 'Live edit' }));
    await editTo(fx.jwtEdited.main.text);
    await waitFor(() => expect(app.engine.parseEdit).toHaveBeenCalled());
    const status = await screen.findByRole('status');
    expect(status).toHaveTextContent('modified – signature stale');
    expect(within(status).getByRole('button', { name: 'Re-sign' })).toBeInTheDocument();
    expect(
      within(status).getByRole('button', { name: 'Keep original signature' }),
    ).toBeInTheDocument();
  });

  it('Re-sign signs the edited bytes into a derived tab', async () => {
    const { app, tab } = mount();
    await userEvent.click(screen.getByRole('switch', { name: 'Live edit' }));
    await editTo(fx.jwtEdited.main.text);
    const status = await screen.findByRole('status');
    await userEvent.click(within(status).getByRole('button', { name: 'Re-sign' }));
    await waitFor(() => expect(app.engine.resign).toHaveBeenCalled());
    const req = app.engine.resign.mock.calls[0]?.[0];
    expect(req?.doc.bytes).toBe(fx.jwtEdited.bytes);
    expect(req?.key.bytes).toBe(fx.issuerInfo.key.bytes);
    expect(app.workspace.tabs.at(-1)?.provenance).toEqual({
      type: 'derived',
      parent: tab.id,
      action: 'resign',
    });
  });

  it('Keep original signature labels the tab tampered without re-signing', async () => {
    const { app, tab } = mount();
    await userEvent.click(screen.getByRole('switch', { name: 'Live edit' }));
    await editTo(fx.jwtEdited.main.text);
    const status = await screen.findByRole('status');
    await userEvent.click(within(status).getByRole('button', { name: 'Keep original signature' }));
    expect(tab.tampered).toBe(true);
    expect(app.engine.resign).not.toHaveBeenCalled();
    expect(screen.getByTestId('validation-badge')).toHaveTextContent(/tampered/i);
  });

  it('a text that does not parse shows the diagnostic and keeps the last good document', async () => {
    const { app, tab } = mount();
    app.engine.parseEdit.mockResolvedValue(fx.editInvalid);
    await userEvent.click(screen.getByRole('switch', { name: 'Live edit' }));
    await editTo('{ "protected": ');
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'expected `,` or `}` after an object member',
    );
    expect(tab.doc).toEqual(fx.jwt);
    expect(screen.queryByText('modified – signature stale')).toBeNull();
  });
});
