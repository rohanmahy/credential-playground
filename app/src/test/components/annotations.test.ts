// Registry annotations and time hints in the main pane (SPEC §4.1, §4.3).
import { screen, within } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import MainPane from '../../lib/components/MainPane.svelte';
import * as fx from '../fixtures';
import { renderWithApp, seedTab, setupApp } from '../render';

function line(nodeId: string): HTMLElement {
  const el = screen
    .getByRole('tree', { name: 'Main pane' })
    .querySelector<HTMLElement>(`[role="treeitem"][data-node-id="${CSS.escape(nodeId)}"]`);
  if (!el) throw new Error(nodeId);
  return el;
}

function mount(doc = fx.jwt) {
  const app = setupApp();
  const tab = seedTab(app.workspace, doc);
  renderWithApp(MainPane, { tabId: tab.id }, app);
}

describe('annotations', () => {
  it("hover text uses the registry's display text, not URLs", () => {
    mount();
    const iss = within(line('payload/~e/iss')).getByTitle(/Issuer/);
    expect(iss.title).toContain('RFC 7519, Section 4.1.1');
    expect(iss.title).not.toContain('https://');
  });

  it('COSE labels show the registered name and value name', () => {
    mount(fx.cwt);
    const alg = within(line('protected/~e/1')).getByTitle(/Cryptographic algorithm/);
    expect(alg.title).toContain('ES256');
    expect(line('protected/~e/1')).toHaveTextContent('/ alg / 1: -7 / ES256 /');
  });

  it('time claims show an inline human-readable date', () => {
    mount();
    const hint = within(line('payload/~e/exp')).getByTestId('time-hint');
    expect(hint).toHaveTextContent('2030-01-01T00:00:00Z');
    expect(hint).toHaveTextContent('in 1081 d 16 h');
    expect(within(line('payload/~e/sub')).queryByTestId('time-hint')).toBeNull();
  });
});
