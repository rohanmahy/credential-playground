// The action toolbar: enablement, "what's missing" tooltips, Re-encode menu
// (SPEC §4.1, §5).
import { screen, within, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import ActionBar from '../../lib/components/ActionBar.svelte';
import * as fx from '../fixtures';
import { renderWithApp, seedKeys, seedTab, setupApp } from '../render';

const NAMES = [
  'Issue',
  'Redact',
  'Disclose',
  'Present',
  'Validate',
  'Re-sign',
  'Tamper',
  'Re-encode',
  'Edit disclosures',
];

function bar(doc = fx.jsonClaims, keys = true) {
  const app = setupApp();
  if (keys) seedKeys(app, fx.issuerCard, fx.holderCard);
  const tab = seedTab(app.workspace, doc);
  renderWithApp(ActionBar, { tabId: tab.id }, app);
  return { app, tab, toolbar: screen.getByRole('toolbar', { name: 'Actions' }) };
}

describe('ActionBar', () => {
  it('shows every action in order', () => {
    const { toolbar } = bar();
    expect(
      within(toolbar)
        .getAllByRole('button')
        .map((b) => b.textContent?.trim()),
    ).toEqual(NAMES);
  });

  it('disables with aria-disabled and explains what is missing', () => {
    const { toolbar } = bar(fx.jsonClaims, false);
    const issue = within(toolbar).getByRole('button', { name: 'Issue' });
    expect(issue).toHaveAttribute('aria-disabled', 'true');
    expect(issue).not.toBeDisabled(); // stays focusable for the tooltip
    expect(issue.getAttribute('title')).toMatch(/issuer key/i);
    const validate = within(toolbar).getByRole('button', { name: 'Validate' });
    expect(validate).toHaveAttribute('aria-disabled', 'true');
    expect(validate.getAttribute('title')).toMatch(/claim set|issue/i);
  });

  it('enables what the document and keys allow', () => {
    const { toolbar } = bar(fx.sdJwt);
    for (const name of [
      'Disclose',
      'Present',
      'Validate',
      'Re-sign',
      'Tamper',
      'Re-encode',
      'Edit disclosures',
    ]) {
      expect(within(toolbar).getByRole('button', { name }), name).toHaveAttribute(
        'aria-disabled',
        'false',
      );
    }
    expect(within(toolbar).getByRole('button', { name: 'Issue' })).toHaveAttribute(
      'aria-disabled',
      'true',
    );
  });

  it('ignores clicks on disabled actions', async () => {
    const { app, toolbar } = bar(fx.jsonClaims, false);
    await userEvent.click(within(toolbar).getByRole('button', { name: 'Issue' }));
    expect(app.engine.issue).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('Re-encode offers the three CBOR serializations for COSE and opens a derived tab', async () => {
    const { app, tab, toolbar } = bar(fx.cwt);
    await userEvent.click(within(toolbar).getByRole('button', { name: 'Re-encode' }));
    const menu = screen.getByRole('menu', { name: /re-encode/i });
    const items = within(menu)
      .getAllByRole('menuitem')
      .map((m) => m.textContent?.trim());
    expect(items).toEqual(
      expect.arrayContaining(['As received', 'Preferred-plus', 'Deterministic']),
    );
    expect(items).not.toContain('Compact');
    await userEvent.click(within(menu).getByRole('menuitem', { name: 'Deterministic' }));
    await waitFor(() => expect(app.engine.reencode).toHaveBeenCalled());
    expect(app.engine.reencode.mock.calls[0]?.[0].cbor).toBe('deterministic');
    await waitFor(() => expect(app.workspace.activeId).not.toBe(tab.id));
  });

  it('Re-encode offers JOSE serializations for JOSE', async () => {
    const { toolbar } = bar(fx.jwt);
    await userEvent.click(within(toolbar).getByRole('button', { name: 'Re-encode' }));
    const menu = screen.getByRole('menu', { name: /re-encode/i });
    const items = within(menu)
      .getAllByRole('menuitem')
      .map((m) => m.textContent?.trim());
    expect(items).toEqual(
      expect.arrayContaining(['Compact', 'JSON (flattened)', 'JSON (general)']),
    );
    expect(items).not.toContain('Deterministic');
  });
});
