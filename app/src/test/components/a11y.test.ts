// Accessibility basics: ARIA roles for trees and tabs, keyboard navigation.
import { screen, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import AppShell from '../../lib/components/AppShell.svelte';
import MainPane from '../../lib/components/MainPane.svelte';
import * as fx from '../fixtures';
import { renderWithApp, seedTab, setupApp } from '../render';
import { NAMES, keyArea, keyButton } from '../ui';

function mainTree(doc = fx.cwt) {
  const app = setupApp();
  const tab = seedTab(app.workspace, doc);
  renderWithApp(MainPane, { tabId: tab.id }, app);
  return { app, tab, tree: screen.getByRole('tree', { name: 'Main pane' }) };
}

const focusedId = () => (document.activeElement as HTMLElement | null)?.dataset['nodeId'];

describe('trees', () => {
  it('use tree/treeitem roles with levels and expanded state', () => {
    const { tree } = mainTree();
    const items = within(tree).getAllByRole('treeitem');
    expect(items.length).toBeGreaterThan(5);
    const payload = items.find((i) => i.dataset['nodeId'] === 'payload');
    expect(payload).toHaveAttribute('aria-level', '2');
    expect(payload).toHaveAttribute('aria-expanded', 'true');
    const sub = items.find((i) => i.dataset['nodeId'] === 'payload/~e/2');
    expect(sub).toHaveAttribute('aria-level', '4');
    expect(sub).not.toHaveAttribute('aria-expanded');
    // one roving tab stop
    expect(items.filter((i) => i.tabIndex === 0)).toHaveLength(1);
  });

  it('move with the arrow keys and fold with Left/Right', async () => {
    const { tab, tree } = mainTree();
    const payload = tree.querySelector<HTMLElement>('[data-node-id="payload"]');
    payload?.focus();
    await userEvent.keyboard('{ArrowLeft}');
    expect(tab.collapsed.has('payload')).toBe(true);
    await userEvent.keyboard('{ArrowDown}');
    expect(focusedId()).toBe('signature'); // folded lines are skipped
    await userEvent.keyboard('{ArrowUp}{ArrowRight}');
    expect(tab.collapsed.has('payload')).toBe(false);
    await userEvent.keyboard('{ArrowDown}');
    expect(focusedId()).toBe('payload/~e/1');
    await userEvent.keyboard('{Enter}');
    expect(tab.selected).toBe('payload/~e/1');
    await userEvent.keyboard('{Home}');
    expect(focusedId()).toBe('');
  });
});

describe('tabs', () => {
  it('use tablist/tab/tabpanel and move with the arrow keys', async () => {
    const app = setupApp();
    const a = seedTab(app.workspace, fx.jwt);
    const b = seedTab(app.workspace, fx.cwt);
    app.workspace.activeId = a.id;
    renderWithApp(AppShell, {}, app);
    const list = screen.getByRole('tablist', { name: 'Credentials' });
    const tabs = within(list).getAllByRole('tab');
    expect(tabs).toHaveLength(2);
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true');
    const panel = screen.getByRole('tabpanel');
    expect(panel).toHaveAttribute('aria-labelledby', tabs[0]?.id);
    tabs[0]?.focus();
    await userEvent.keyboard('{ArrowRight}');
    expect(app.workspace.activeId).toBe(b.id);
    expect(within(list).getAllByRole('tab')[1]).toHaveAttribute('aria-selected', 'true');
    expect(document.activeElement).toBe(within(list).getAllByRole('tab')[1]);
    await userEvent.keyboard('{Home}');
    expect(app.workspace.activeId).toBe(a.id);
  });

  it('the "+" button is reachable by keyboard and opens an empty tab', async () => {
    const app = setupApp();
    renderWithApp(AppShell, {}, app);
    const plus = screen.getByRole('button', { name: NAMES.newTab });
    plus.focus();
    await userEvent.keyboard('{Enter}');
    expect(screen.getAllByRole('tab')).toHaveLength(2);
    expect(app.workspace.tabs).toHaveLength(2);
  });

  it('two tabs can be shown side by side', async () => {
    const app = setupApp();
    seedTab(app.workspace, fx.jwt);
    seedTab(app.workspace, fx.cwt);
    renderWithApp(AppShell, {}, app);
    await userEvent.click(screen.getByRole('button', { name: 'Split view' }));
    expect(screen.getAllByRole('tabpanel')).toHaveLength(2);
    expect(app.workspace.split).not.toBeNull();
  });
});

describe('landmarks and dialogs', () => {
  it('the key areas are labelled regions and disabled actions stay focusable', () => {
    const app = setupApp();
    seedTab(app.workspace, fx.jsonClaims);
    renderWithApp(AppShell, {}, app);
    expect(keyArea('issuer')).toBeInTheDocument();
    expect(keyArea('holder')).toBeInTheDocument();
    const issue = screen.getByRole('button', { name: 'Issue' });
    issue.focus();
    expect(document.activeElement).toBe(issue);
  });

  it('dialogs take focus and close with Escape', async () => {
    const app = setupApp();
    renderWithApp(AppShell, {}, app);
    await userEvent.click(keyButton('issuer', NAMES.create));
    const dialog = screen.getByRole('dialog', { name: 'Create key' });
    expect(dialog.contains(document.activeElement)).toBe(true);
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('dialog', { name: 'Create key' })).toBeNull();
  });
});
