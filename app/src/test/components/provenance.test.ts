// Derived tabs and the provenance breadcrumb (SPEC §4, §5).
import { screen, within, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import AppShell from '../../lib/components/AppShell.svelte';
import TabHeader from '../../lib/components/TabHeader.svelte';
import * as fx from '../fixtures';
import { renderWithApp, seedKeys, seedTab, setupApp } from '../render';

describe('provenance', () => {
  it('shows where a root tab came from', () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.jwt, { provenance: { type: 'file', name: 'token.txt' } });
    renderWithApp(TabHeader, { tabId: tab.id }, app);
    expect(screen.getByRole('navigation', { name: 'Provenance' })).toHaveTextContent(
      'File: token.txt',
    );
  });

  it('derived tabs link back to their parent', async () => {
    const app = setupApp();
    const parent = seedTab(app.workspace, fx.sdJwt);
    const child = seedTab(app.workspace, fx.sdJwtKb, {
      provenance: { type: 'derived', parent: parent.id, action: 'present' },
    });
    renderWithApp(TabHeader, { tabId: child.id }, app);
    const nav = screen.getByRole('navigation', { name: 'Provenance' });
    expect(nav).toHaveTextContent('Present');
    await userEvent.click(within(nav).getByRole('button', { name: parent.title }));
    expect(app.workspace.activeId).toBe(parent.id);
  });

  it('Present from the toolbar opens a derived tab with the chosen disclosures', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard, fx.holderCard);
    const parent = seedTab(app.workspace, fx.sdJwt);
    renderWithApp(AppShell, {}, app);
    await userEvent.click(screen.getByRole('button', { name: 'Present' }));
    const dialog = screen.getByRole('dialog', { name: 'Present' });
    await userEvent.click(within(dialog).getByRole('checkbox', { name: /given_name/ }));
    expect(within(dialog).getByRole('checkbox', { name: /email/ })).toBeChecked();
    await userEvent.selectOptions(
      within(dialog).getByRole('combobox', { name: 'Holder key' }),
      'Holder Ed25519',
    );
    await userEvent.type(
      within(dialog).getByRole('textbox', { name: 'Audience' }),
      'https://verifier.example',
    );
    await userEvent.type(within(dialog).getByRole('textbox', { name: 'Nonce' }), 'n-0S6');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Present' }));
    await waitFor(() => expect(app.engine.present).toHaveBeenCalled());
    expect(app.engine.present.mock.calls[0]?.[0]).toMatchObject({
      keep: [1],
      aud: 'https://verifier.example',
      nonce: { type: 'text', value: 'n-0S6' },
      iat: fx.NOW,
    });
    await waitFor(() => expect(app.workspace.tabs).toHaveLength(2));
    const nav = screen.getByRole('navigation', { name: 'Provenance' });
    expect(within(nav).getByRole('button', { name: parent.title })).toBeInTheDocument();
    expect(screen.getByRole('tab', { selected: true })).toHaveTextContent(/SD-JWT\+KB/);
  });
});
