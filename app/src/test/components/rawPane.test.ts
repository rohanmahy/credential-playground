// Raw pane rendering from RawView (SPEC §4.1).
import { screen, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import CredentialTab from '../../lib/components/CredentialTab.svelte';
import RawPane from '../../lib/components/RawPane.svelte';
import * as fx from '../fixtures';
import { renderWithApp, seedTab, setupApp } from '../render';

describe('hex view', () => {
  it('renders one block per main-pane line, with the rows aligned to it', () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.cwt);
    renderWithApp(RawPane, { tabId: tab.id }, app);
    const raw = screen.getByRole('tree', { name: 'Raw pane' });
    const blocks = [...raw.querySelectorAll<HTMLElement>('[data-line]')];
    expect(blocks.map((b) => Number(b.dataset['line']))).toEqual([...Array(14).keys()]);
    const rowsOf = (line: number) =>
      [...(blocks[line]?.querySelectorAll<HTMLElement>('[data-row]') ?? [])].map((r) =>
        Number(r.dataset['row']),
      );
    expect(rowsOf(5)).toEqual([7, 8]);
    expect(rowsOf(3)).toEqual([]);
    expect(rowsOf(12)).toEqual([17]);
  });

  it('shows head and payload bytes, the description, and the registry comment', () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.cwt);
    renderWithApp(RawPane, { tabId: tab.id }, app);
    const row12 = screen
      .getByRole('tree', { name: 'Raw pane' })
      .querySelector<HTMLElement>('[data-row="12"]');
    if (!row12) throw new Error('row');
    // head then payload bytes, lowercase hex (spacing is free)
    expect(row12.textContent?.replace(/\s/g, '')).toContain('75636f61703a2f2f'); // 75 "coap://"
    expect(row12).toHaveTextContent('text(21)');
    const row4 = screen
      .getByRole('tree', { name: 'Raw pane' })
      .querySelector<HTMLElement>('[data-row="4"]');
    expect(row4).toHaveTextContent('alg');
  });
});

describe('segment view', () => {
  it('lists the encoded segments with labels and separators', () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.sdJwtKb);
    renderWithApp(RawPane, { tabId: tab.id }, app);
    const raw = screen.getByRole('tree', { name: 'Raw pane' });
    if (fx.sdJwtKb.raw.type !== 'segments') throw new Error('fixture');
    for (const s of fx.sdJwtKb.raw.segments) {
      const el = raw.querySelector<HTMLElement>(`[data-node-id="${s.node_id}"]`);
      expect(el, s.node_id).not.toBeNull();
      expect(within(el as HTMLElement).getByText(s.label)).toBeInTheDocument();
      expect(el).toHaveTextContent(s.text);
    }
  });
});

describe('visibility', () => {
  it('is toggleable', async () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.jwt);
    renderWithApp(CredentialTab, { tabId: tab.id }, app);
    expect(screen.getByRole('tree', { name: 'Raw pane' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('checkbox', { name: /raw pane/i }));
    expect(app.settings.showRaw).toBe(false);
    expect(screen.queryByRole('tree', { name: 'Raw pane' })).toBeNull();
  });

  it('is absent for JSON claim sets (RawView none)', () => {
    const app = setupApp();
    const claims = seedTab(app.workspace, fx.jsonClaims);
    renderWithApp(CredentialTab, { tabId: claims.id }, app);
    expect(screen.getByRole('tree', { name: 'Main pane' })).toBeInTheDocument();
    expect(screen.queryByRole('tree', { name: 'Raw pane' })).toBeNull();
  });
});
