// Marking claims selectively disclosable and the Issue dialog (SPEC §5).
import { screen, waitFor, within, fireEvent } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import CredentialTab from '../../lib/components/CredentialTab.svelte';
import * as fx from '../fixtures';
import { renderWithApp, seedKeys, seedTab, setupApp } from '../render';

function mount() {
  const app = setupApp();
  seedKeys(app, fx.issuerCard, fx.holderCard);
  const tab = seedTab(app.workspace, fx.jsonClaims);
  renderWithApp(CredentialTab, { tabId: tab.id }, app);
  return { app, tab };
}

describe('SD marks', () => {
  it('a claim is marked from its context menu, and the mark shows in the tree', async () => {
    const { tab } = mount();
    const main = screen.getByRole('tree', { name: 'Main pane' });
    const line = main.querySelector<HTMLElement>('[data-node-id="given_name"]');
    if (!line) throw new Error('line');
    await fireEvent.contextMenu(line);
    await userEvent.click(
      screen.getByRole('menuitemcheckbox', { name: /selectively disclosable/i }),
    );
    expect(tab.sdMarks.has('given_name')).toBe(true);
    expect(line).toHaveAttribute('data-sd-mark', 'true');
    expect(screen.getByRole('button', { name: 'Redact' })).toHaveAttribute(
      'aria-disabled',
      'false',
    );
  });
});

describe('Issue', () => {
  it('asks for the issuer key and header options, then opens the credential', async () => {
    const { app, tab } = mount();
    tab.sdMarks.add('given_name');
    await userEvent.click(screen.getByRole('button', { name: 'Issue' }));
    const dialog = screen.getByRole('dialog', { name: 'Issue' });
    expect(within(dialog).getByRole('combobox', { name: 'Issuer key' })).toHaveValue('key-1');
    await userEvent.selectOptions(
      within(dialog).getByRole('combobox', { name: 'Serialization' }),
      'json_flattened',
    );
    await userEvent.selectOptions(
      within(dialog).getByRole('combobox', { name: 'Holder key (cnf)' }),
      'key-2',
    );
    await userEvent.click(within(dialog).getByRole('button', { name: 'Issue' }));
    await waitFor(() => expect(app.engine.issue).toHaveBeenCalled());
    const req = app.engine.issue.mock.calls[0]?.[0];
    expect(req?.jose_serialization).toBe('json_flattened');
    expect(req?.sd.marks).toEqual(['given_name']);
    expect(req?.cnf).toEqual({
      type: 'key',
      key: expect.objectContaining({ bytes: fx.holderInfo.key.bytes }),
    });
    await waitFor(() => expect(app.workspace.tabs).toHaveLength(2));
  });
});
