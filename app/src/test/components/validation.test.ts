// The validation checklist with links to NodeIds (SPEC §6).
import { screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import CredentialTab from '../../lib/components/CredentialTab.svelte';
import ValidationReport from '../../lib/components/ValidationReport.svelte';
import * as fx from '../fixtures';
import { renderWithApp, seedKeys, seedTab, setupApp } from '../render';

describe('ValidationReport', () => {
  it('renders every item with its status, grouped by category', () => {
    renderWithApp(ValidationReport, { report: fx.jwtReport, onSelectNode: vi.fn() });
    const list = screen.getByRole('list', { name: 'Validation report' });
    const items = within(list).getAllByRole('listitem');
    expect(items.map((i) => i.dataset['status'])).toEqual(['pass', 'fail', 'pass', 'warn', 'skip']);
    expect(items[1]).toHaveTextContent('Expired 2 d ago');
    for (const heading of ['Signature', 'Time', 'Key binding', 'Lint']) {
      expect(screen.getByRole('heading', { name: heading })).toBeInTheDocument();
    }
    expect(screen.getByTestId('report-overall')).toHaveTextContent(/fail/i);
  });

  it('links items to their nodes', async () => {
    const onSelectNode = vi.fn();
    renderWithApp(ValidationReport, { report: fx.jwtReport, onSelectNode });
    const exp = screen.getAllByRole('listitem')[1] as HTMLElement;
    await userEvent.click(within(exp).getByRole('button', { name: /payload\/~e\/exp|exp/ }));
    expect(onSelectNode).toHaveBeenCalledWith('payload/~e/exp');
  });

  it('names the verifying key and how it was selected', () => {
    renderWithApp(ValidationReport, { report: fx.jwtReport, onSelectNode: vi.fn() });
    const sig = screen.getAllByRole('listitem')[0];
    expect(sig).toHaveTextContent('Issuer P-256');
    expect(sig).toHaveTextContent(/kid/i);
  });

  it('shows the preferred encoding of lint findings', () => {
    renderWithApp(ValidationReport, { report: fx.cwtLintReport, onSelectNode: vi.fn() });
    expect(screen.getAllByRole('listitem')[0]).toHaveTextContent('1a5612aeb0');
  });

  it('offers fetch hints without fetching', async () => {
    const onFetch = vi.fn();
    const { app } = renderWithApp(ValidationReport, {
      report: fx.kidUrlReport,
      onSelectNode: vi.fn(),
      onFetch,
    });
    await userEvent.click(
      screen.getByRole('button', {
        name: /fetch key from https:\/\/issuer\.example\/keys\/1\.jwk/i,
      }),
    );
    expect(onFetch).toHaveBeenCalledWith(fx.kidUrlReport.fetchable[0]);
    expect(app.platform.fetchUrl).not.toHaveBeenCalled();
  });
});

describe('Validate in a tab', () => {
  it('runs validation, shows the badge, and selects linked nodes (expanding ancestors)', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard);
    const tab = seedTab(app.workspace, fx.jwt);
    tab.collapsed.add('payload');
    renderWithApp(CredentialTab, { tabId: tab.id }, app);
    await userEvent.click(screen.getByRole('button', { name: 'Validate' }));
    await waitFor(() => expect(app.engine.validate).toHaveBeenCalled());
    expect(await screen.findByRole('list', { name: 'Validation report' })).toBeInTheDocument();
    expect(screen.getByTestId('validation-badge')).toHaveTextContent(/fail/i);
    const exp = within(screen.getByRole('list', { name: 'Validation report' })).getAllByRole(
      'listitem',
    )[1] as HTMLElement;
    await userEvent.click(within(exp).getByRole('button', { name: /exp/ }));
    expect(tab.selected).toBe('payload/~e/exp');
    expect(tab.collapsed.has('payload')).toBe(false);
    const main = screen.getByRole('tree', { name: 'Main pane' });
    expect(main.querySelector('[data-node-id="payload/~e/exp"]')).toHaveAttribute(
      'aria-selected',
      'true',
    );
  });
});
