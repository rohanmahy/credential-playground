// Synced collapse/expand and selection between the main and raw panes,
// keyed by NodeId; collapse state survives re-render and edit (SPEC §4.1).
import { screen, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { tick } from 'svelte';
import { describe, expect, it } from 'vitest';
import CredentialTab from '../../lib/components/CredentialTab.svelte';
import * as fx from '../fixtures';
import { renderWithApp, seedTab, setupApp } from '../render';

function panes() {
  return {
    main: screen.getByRole('tree', { name: 'Main pane' }),
    raw: screen.getByRole('tree', { name: 'Raw pane' }),
  };
}

function item(tree: HTMLElement, nodeId: string): HTMLElement {
  const el = tree.querySelector<HTMLElement>(
    `[role="treeitem"][data-node-id="${CSS.escape(nodeId)}"]`,
  );
  if (!el) throw new Error(`no treeitem ${nodeId}`);
  return el;
}

function toggle(el: HTMLElement): HTMLElement {
  return within(el).getByRole('button', { name: /collapse|expand/i });
}

function mount(doc = fx.cwt) {
  const app = setupApp();
  const tab = seedTab(app.workspace, doc);
  renderWithApp(CredentialTab, { tabId: tab.id }, app);
  return { app, tab };
}

describe('tree sync (COSE)', () => {
  it('renders both panes as trees', () => {
    mount();
    const { main, raw } = panes();
    expect(item(main, 'payload')).toHaveAttribute('aria-expanded', 'true');
    expect(item(raw, 'payload')).toHaveAttribute('aria-expanded', 'true');
  });

  it('collapsing in the main pane collapses the raw pane', async () => {
    const { app, tab } = mount();
    const { main, raw } = panes();
    await userEvent.click(toggle(item(main, 'payload')));
    expect(app.workspace.tab(tab.id)?.collapsed.has('payload')).toBe(true);
    expect(item(main, 'payload')).toHaveAttribute('aria-expanded', 'false');
    expect(item(raw, 'payload')).toHaveAttribute('aria-expanded', 'false');
    expect(within(main).queryByText(/coap:\/\/as\.example\.com/)).toBeNull();
    expect(raw.querySelector('[data-line="8"]')).toBeNull();
    expect(raw.querySelector('[data-line="11"]')).not.toBeNull();
  });

  it('expanding in the raw pane expands the main pane', async () => {
    const { tab } = mount();
    tab.collapsed.add('payload');
    await tick();
    const { main, raw } = panes();
    await userEvent.click(toggle(item(raw, 'payload')));
    expect(tab.collapsed.has('payload')).toBe(false);
    expect(item(main, 'payload')).toHaveAttribute('aria-expanded', 'true');
    expect(within(main).getByText(/coap:\/\/as\.example\.com/)).toBeInTheDocument();
  });

  it('selecting in the main pane highlights the counterpart rows', async () => {
    const { tab } = mount();
    const { main, raw } = panes();
    await userEvent.click(item(main, 'payload/~e/2'));
    expect(tab.selected).toBe('payload/~e/2');
    expect(item(main, 'payload/~e/2')).toHaveAttribute('aria-selected', 'true');
    expect(raw.querySelector('[data-row="14"]')).toHaveAttribute('aria-selected', 'true');
    expect(raw.querySelector('[data-row="12"]')).toHaveAttribute('aria-selected', 'false');
  });

  it('selecting in the raw pane highlights the main-pane line', async () => {
    const { tab } = mount();
    const { main, raw } = panes();
    const row = raw.querySelector<HTMLElement>('[data-row="12"]');
    if (!row) throw new Error('row 12');
    await userEvent.click(row);
    expect(tab.selected).toBe('payload/~e/1');
    expect(item(main, 'payload/~e/1')).toHaveAttribute('aria-selected', 'true');
  });

  it('collapse state survives a re-render and an edit (path-based NodeIds)', async () => {
    const { tab } = mount();
    tab.collapsed.add('payload');
    tab.selected = 'signature';
    tab.doc = structuredClone(fx.cwt); // re-render: new objects, same ids
    await tick();
    expect(item(panes().main, 'payload')).toHaveAttribute('aria-expanded', 'false');
    tab.doc = { ...structuredClone(fx.cwt), signature_stale: true }; // after an edit
    await tick();
    const { main, raw } = panes();
    expect(item(main, 'payload')).toHaveAttribute('aria-expanded', 'false');
    expect(item(raw, 'payload')).toHaveAttribute('aria-expanded', 'false');
    expect(item(main, 'signature')).toHaveAttribute('aria-selected', 'true');
  });
});

describe('tree sync (JOSE)', () => {
  it('collapsing a part collapses its segment', async () => {
    mount(fx.jwt);
    const { main, raw } = panes();
    await userEvent.click(toggle(item(main, 'payload')));
    expect(item(raw, 'payload')).toHaveAttribute('aria-expanded', 'false');
    expect(within(main).queryByText(/user-42/)).toBeNull();
  });

  it('selecting a claim highlights its characters in the payload segment', async () => {
    mount(fx.jwt);
    const { main, raw } = panes();
    await userEvent.click(item(main, 'payload/~e/iss'));
    const seg = item(raw, 'payload');
    const mark = seg.querySelector('mark');
    const node = fx.jwt.tree.children[1]?.children[0]?.children[0];
    const segment = fx.jwt.raw.type === 'segments' ? fx.jwt.raw.segments[1] : undefined;
    if (!node?.raw || !segment) throw new Error('fixture');
    expect(mark?.textContent).toBe(
      segment.text.slice(node.raw.start - segment.range.start, node.raw.end - segment.range.start),
    );
    expect(seg).toHaveAttribute('aria-selected', 'true');
  });
});
