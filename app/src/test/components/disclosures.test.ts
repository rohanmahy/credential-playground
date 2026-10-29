// SD views: disclosures, their match status and slots, undisclosed digests
// (SPEC §4.1).
import { screen, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import DisclosuresView from '../../lib/components/DisclosuresView.svelte';
import * as fx from '../fixtures';
import { renderWithApp, seedTab, setupApp } from '../render';

describe('DisclosuresView', () => {
  it('lists disclosures with digest, salt, claim, value, and status', () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.sdJwt);
    renderWithApp(DisclosuresView, { tabId: tab.id }, app);
    const rows = within(screen.getByRole('table', { name: 'Disclosures' }))
      .getAllByRole('row')
      .slice(1);
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent('given_name');
    expect(rows[0]).toHaveTextContent('"Alice"');
    expect(rows[0]).toHaveTextContent('salt-1');
    expect(rows[0]).toHaveTextContent('dig-given-name');
    expect(rows[0]).toHaveTextContent(/matched/i);
    const undisclosed = screen.getByRole('list', { name: /undisclosed/i });
    expect(undisclosed).toHaveTextContent('dig-decoy');
    expect(undisclosed).toHaveTextContent(/decoy or withheld/i);
  });

  it('links each disclosure to the slot it fills', async () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.sdJwt);
    renderWithApp(DisclosuresView, { tabId: tab.id }, app);
    const rows = within(screen.getByRole('table', { name: 'Disclosures' }))
      .getAllByRole('row')
      .slice(1);
    await userEvent.click(within(rows[1] as HTMLElement).getByRole('button', { name: /slot/i }));
    expect(tab.selected).toBe('payload/~e/_sd/1');
  });
});
