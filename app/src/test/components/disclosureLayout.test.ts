// SD view layout (SPEC §4.1): resizable Value / Salt / Digest columns, Value
// wraps, Salt and Digest truncate visually but keep their full text, and a
// resizable split between the panes and the SD view. jsdom has no layout,
// so these tests pin the ARIA contract, keyboard resizing, inline sizes,
// and the DOM text; the real layout (wrapping, ellipsis, the initial third
// of the window, dragging) is pinned in e2e/disclosures-layout.spec.ts.
import { screen, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import AppShell from '../../lib/components/AppShell.svelte';
import CredentialTab from '../../lib/components/CredentialTab.svelte';
import DisclosuresView from '../../lib/components/DisclosuresView.svelte';
import type { Document } from '../../lib/engine/types';
import * as fx from '../fixtures';
import { renderWithApp, seedTab, setupApp } from '../render';
import { NAMES, type ResizableColumn } from '../ui';

const COLUMNS: ResizableColumn[] = ['Value', 'Salt', 'Digest'];
const LONG_HEX = `h'${'00112233445566778899aabbccddeeff'.repeat(12)}'`;
const LONG_SALT = 'c2FsdC0'.repeat(10);
const LONG_DIGEST = 'ZGlnZXN0LW9mLWEtbG9uZy1kaXNjbG9zdXJl'.repeat(3);

/** An SD-CWT whose one disclosure has a long byte-string value, salt, and digest. */
function longSdCwt(): Document {
  const doc = structuredClone(fx.sdCwt);
  const d = doc.disclosures[0];
  if (!d) throw new Error('fixture');
  doc.disclosures = [{ ...d, value: LONG_HEX, salt: LONG_SALT, digest: LONG_DIGEST }];
  return doc;
}

function table() {
  return screen.getByRole('table', { name: NAMES.disclosures });
}

/** The header cell of a column. Its name may also include the handle's
 *  label, so it is matched by its leading text. */
function header(name: string) {
  return within(table()).getByRole('columnheader', { name: new RegExp(`^${name}\\b`) });
}

/** The body cells of a column, by the header's position. */
function cells(name: string): HTMLElement[] {
  const headers = within(table()).getAllByRole('columnheader');
  const index = headers.indexOf(header(name));
  return within(table())
    .getAllByRole('row')
    .slice(1)
    .map((row) => within(row).getAllByRole('cell')[index] as HTMLElement);
}

function handle(column: ResizableColumn) {
  return within(table()).getByRole('separator', { name: NAMES.resizeColumn[column] });
}

function splitter() {
  return screen.getByRole('separator', { name: NAMES.resizeDisclosures });
}

function sdRegion() {
  return screen.getByRole('region', { name: NAMES.sdRegion });
}

const num = (el: HTMLElement, attr: string) => Number(el.getAttribute(attr));

/** The full text a cell's tooltip shows: `title` on the cell or on the
 *  element inside it that holds the text. */
function tooltip(cell: HTMLElement): string | null {
  return cell.getAttribute('title') ?? cell.querySelector('[title]')?.getAttribute('title') ?? null;
}

describe('disclosure columns', () => {
  for (const [name, doc] of [
    ['SD-JWT', fx.sdJwt],
    ['SD-CWT', fx.sdCwt],
  ] as const) {
    it(`${name}: Value, Salt, and Digest have a focusable vertical resize handle; others none`, () => {
      const app = setupApp();
      const tab = seedTab(app.workspace, doc);
      renderWithApp(DisclosuresView, { tabId: tab.id }, app);
      const handles = within(table()).getAllByRole('separator');
      expect(handles).toHaveLength(3);
      for (const column of COLUMNS) {
        const h = handle(column);
        expect(header(column)).toContainElement(h);
        expect(h).toHaveAttribute('aria-orientation', 'vertical');
        expect(h).toHaveAttribute('tabindex', '0');
        expect(Number.isFinite(num(h, 'aria-valuenow'))).toBe(true);
        expect(num(h, 'aria-valuemin')).toBeGreaterThan(0);
        expect(num(h, 'aria-valuenow')).toBeGreaterThanOrEqual(num(h, 'aria-valuemin'));
      }
      // the other columns keep their natural width
      for (const other of ['Claim', 'Status', 'Slot']) {
        expect(within(header(other)).queryByRole('separator')).toBeNull();
        expect(header(other).style.width).toBe('');
      }
    });
  }

  for (const column of COLUMNS) {
    it(`ArrowRight / ArrowLeft resize the ${column} column (aria-valuenow and the header width)`, async () => {
      const app = setupApp();
      const tab = seedTab(app.workspace, fx.sdJwt);
      renderWithApp(DisclosuresView, { tabId: tab.id }, app);
      const others = COLUMNS.filter((c) => c !== column);
      const before = others.map((c) => handle(c).getAttribute('aria-valuenow'));
      const h = handle(column);
      h.focus();
      const start = num(h, 'aria-valuenow');
      await userEvent.keyboard('{ArrowRight}');
      const wider = num(handle(column), 'aria-valuenow');
      expect(wider).toBeGreaterThan(start);
      expect(header(column).style.width).toBe(`${wider}px`);
      await userEvent.keyboard('{ArrowLeft}{ArrowLeft}');
      const narrower = num(handle(column), 'aria-valuenow');
      expect(narrower).toBeLessThan(wider);
      expect(header(column).style.width).toBe(`${narrower}px`);
      // resizing one column leaves the others alone
      expect(others.map((c) => handle(c).getAttribute('aria-valuenow'))).toEqual(before);
    });
  }

  it('a column never gets narrower than its minimum', async () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.sdJwt);
    renderWithApp(DisclosuresView, { tabId: tab.id }, app);
    const h = handle('Salt');
    const min = num(h, 'aria-valuemin');
    expect(min).toBeGreaterThanOrEqual(32);
    h.focus();
    await userEvent.keyboard('{ArrowLeft>200/}');
    expect(num(handle('Salt'), 'aria-valuenow')).toBe(min);
    expect(header('Salt').style.width).toBe(`${min}px`);
  });
});

describe('disclosure cells', () => {
  it('Salt and Digest keep the full value in the DOM (no JS "…") with the full value as title', () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, longSdCwt());
    renderWithApp(DisclosuresView, { tabId: tab.id }, app);
    const [salt] = cells('Salt');
    const [digest] = cells('Digest');
    expect(salt?.textContent?.trim()).toBe(LONG_SALT);
    expect(digest?.textContent?.trim()).toBe(LONG_DIGEST);
    expect(salt?.textContent).not.toContain('…');
    expect(digest?.textContent).not.toContain('…');
    expect(tooltip(salt as HTMLElement)).toBe(LONG_SALT);
    expect(tooltip(digest as HTMLElement)).toBe(LONG_DIGEST);
  });

  it('Salt and Digest are titled in every row (SD-JWT)', () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.sdJwt);
    renderWithApp(DisclosuresView, { tabId: tab.id }, app);
    expect(cells('Salt').map(tooltip)).toEqual(['salt-1', 'salt-2']);
    expect(cells('Digest').map(tooltip)).toEqual(['dig-given-name', 'dig-email']);
  });

  it("Value is never truncated: a long h'' byte string is shown whole", () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, longSdCwt());
    renderWithApp(DisclosuresView, { tabId: tab.id }, app);
    const [value] = cells('Value');
    expect(value?.textContent?.trim()).toBe(LONG_HEX);
    expect(value?.textContent).not.toContain('…');
  });
});

describe('split between the panes and the SD view', () => {
  for (const [name, doc] of [
    ['SD-JWT', fx.sdJwt],
    ['SD-CWT', fx.sdCwt],
  ] as const) {
    it(`${name}: a focusable horizontal separator "Resize disclosures" above the SD view`, () => {
      const app = setupApp();
      const tab = seedTab(app.workspace, doc);
      renderWithApp(CredentialTab, { tabId: tab.id }, app);
      const s = splitter();
      expect(s).toHaveAttribute('aria-orientation', 'horizontal');
      expect(s).toHaveAttribute('tabindex', '0');
      expect(Number.isFinite(num(s, 'aria-valuenow'))).toBe(true);
      expect(num(s, 'aria-valuemin')).toBeGreaterThan(0);
      // it sits between the panes and the SD view
      const region = sdRegion();
      expect(s.compareDocumentPosition(region) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
      expect(region.contains(s)).toBe(false);
    });
  }

  it('no splitter without disclosures', () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.jwt);
    renderWithApp(CredentialTab, { tabId: tab.id }, app);
    expect(screen.queryByRole('separator', { name: NAMES.resizeDisclosures })).toBeNull();
  });

  it('before any resize the SD view is at most a third of the window high', () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.sdJwt);
    renderWithApp(CredentialTab, { tabId: tab.id }, app);
    const third = window.innerHeight / 3;
    expect(num(splitter(), 'aria-valuenow')).toBeLessThanOrEqual(third);
    const inline = sdRegion().style.height;
    if (inline) expect(parseFloat(inline)).toBeLessThanOrEqual(third);
  });

  it('ArrowUp grows the SD view and ArrowDown shrinks it (aria-valuenow and the inline height)', async () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.sdJwt);
    renderWithApp(CredentialTab, { tabId: tab.id }, app);
    splitter().focus();
    await userEvent.keyboard('{ArrowUp}{ArrowUp}{ArrowUp}');
    const taller = num(splitter(), 'aria-valuenow');
    expect(taller).toBeGreaterThan(0);
    expect(sdRegion().style.height).toBe(`${taller}px`);
    await userEvent.keyboard('{ArrowDown}');
    const shorter = num(splitter(), 'aria-valuenow');
    expect(shorter).toBeLessThan(taller);
    expect(sdRegion().style.height).toBe(`${shorter}px`);
  });

  it('the SD view never gets shorter than its minimum', async () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.sdJwt);
    renderWithApp(CredentialTab, { tabId: tab.id }, app);
    splitter().focus();
    await userEvent.keyboard('{ArrowUp}{ArrowUp}{ArrowDown>200/}');
    const min = num(splitter(), 'aria-valuemin');
    expect(min).toBeGreaterThanOrEqual(40);
    expect(num(splitter(), 'aria-valuenow')).toBe(min);
    expect(sdRegion().style.height).toBe(`${min}px`);
  });

  it("the user's size sticks to its tab while the app runs (tab switches)", async () => {
    const app = setupApp();
    const a = seedTab(app.workspace, fx.sdJwt);
    const b = seedTab(app.workspace, fx.sdCwt);
    app.workspace.activeId = a.id;
    renderWithApp(AppShell, {}, app);
    splitter().focus();
    await userEvent.keyboard('{ArrowUp}{ArrowUp}{ArrowUp}{ArrowUp}');
    const sized = sdRegion().style.height;
    expect(sized).toMatch(/^\d+(\.\d+)?px$/);

    const tabs = within(screen.getByRole('tablist', { name: 'Credentials' })).getAllByRole('tab');
    await userEvent.click(tabs[1] as HTMLElement);
    expect(app.workspace.activeId).toBe(b.id);
    // the other tab has its own (initial) size
    expect(sdRegion().style.height).not.toBe(sized);

    await userEvent.click(tabs[0] as HTMLElement);
    expect(app.workspace.activeId).toBe(a.id);
    expect(sdRegion().style.height).toBe(sized);
    expect(splitter()).toHaveAttribute('aria-valuenow', String(parseFloat(sized)));
  });
});

// SPEC §1: sizes live only while the app runs (unit/neverPersist.test.ts
// scans the sources statically as well).
describe('never persisted', () => {
  let setItem: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    setItem = vi.spyOn(Storage.prototype, 'setItem');
  });
  afterEach(() => setItem.mockRestore());

  it('column and split sizes are not written to storage', async () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.sdJwt);
    renderWithApp(CredentialTab, { tabId: tab.id }, app);
    splitter().focus();
    await userEvent.keyboard('{ArrowUp}{ArrowDown}');
    for (const column of COLUMNS) {
      handle(column).focus();
      await userEvent.keyboard('{ArrowRight}{ArrowLeft}{ArrowLeft}');
    }
    expect(setItem).not.toHaveBeenCalled();
    expect(document.cookie).toBe('');
  });
});
