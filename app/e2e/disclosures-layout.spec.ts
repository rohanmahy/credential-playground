// SD view layout (SPEC §4.1) with a real layout and the real WasmEngine:
// the SD view starts at most a third of the window high (less when its
// content is shorter), the splitter above it and the Value / Salt / Digest
// column handles drag, Salt and Digest truncate with an ellipsis but keep
// (and copy) their full text, and a long h'' value wraps inside its column.
import { expect, test, type Locator, type Page } from '@playwright/test';
import { ORIGIN } from '../playwright.config';
import {
  actions,
  activePanel,
  columnCell,
  columnHandle,
  columnHeader,
  createKey,
  disclosuresTable,
  dragBy,
  fixtureHex,
  fixtureText,
  mainPane,
  paste,
  sdRegion,
  sdSplitter,
} from './helpers';

const MANY = () => fixtureText('tokens/rfc9901-a3-sd-jwt.txt'); // 27 disclosures
const MANY_CWT = () => fixtureHex('tokens/sd-cwt-08-nested-issuer-sd-cwt.cbor'); // 15 disclosures
// 3 short disclosures and 2 undisclosed digests (A.3's KB presentation still
// lists many undisclosed digests, so it is not short).
const FEW = () => fixtureHex('tokens/sd-cwt-08-sd-kbt.cbor');
const SD_JWT = () => fixtureText('tokens/rfc9901-s5.1-sd-jwt.txt');
const SD_CWT = () => fixtureHex('tokens/sd-cwt-08-issuer-sd-cwt.cbor');

const TOLERANCE = 4;

test.beforeEach(async ({ page }) => {
  await page.goto('/');
});

async function height(el: Locator): Promise<number> {
  const box = await el.boundingBox();
  if (!box) throw new Error('not visible');
  return box.height;
}

async function width(el: Locator): Promise<number> {
  const box = await el.boundingBox();
  if (!box) throw new Error('not visible');
  return box.width;
}

const innerHeight = (page: Page) => page.evaluate(() => window.innerHeight);

/** The nearest element at or above `el` that scrolls vertically: its
 *  visible height and whether its content overflows. */
function scroller(el: Locator) {
  return el.evaluate((start) => {
    for (let e: Element | null = start; e; e = e.parentElement) {
      const oy = getComputedStyle(e).overflowY;
      if (oy === 'auto' || oy === 'scroll') {
        return {
          clientHeight: e.clientHeight,
          overflows: e.scrollHeight > e.clientHeight + 1,
          tag: e.tagName,
        };
      }
    }
    return null;
  });
}

/** Within the SD view (itself included), an element that scrolls
 *  vertically, and whether it overflows. */
function sdScroller(page: Page) {
  return sdRegion(page).evaluate((region) => {
    for (const e of [region, ...region.querySelectorAll('*')]) {
      const oy = getComputedStyle(e).overflowY;
      if ((oy === 'auto' || oy === 'scroll') && e.clientHeight > 0) {
        return { overflows: e.scrollHeight > e.clientHeight + 1 };
      }
    }
    return null;
  });
}

/** How a Salt / Digest cell renders: its full DOM text, its tooltip, and
 *  the text-overflow, white-space, and clipping of the element that renders
 *  the text (the cell, or the element inside it with the ellipsis). */
function truncation(cell: Locator) {
  return cell.evaluate((td) => {
    const full = (td.textContent ?? '').trim();
    const holder =
      [td, ...td.querySelectorAll('*')].find(
        (e) => getComputedStyle(e).textOverflow === 'ellipsis',
      ) ?? td;
    const cs = getComputedStyle(holder);
    return {
      full,
      textOverflow: cs.textOverflow,
      whiteSpace: cs.whiteSpace,
      clipped: holder.scrollWidth > holder.clientWidth,
      title: td.getAttribute('title') ?? td.querySelector('[title]')?.getAttribute('title'),
    };
  });
}

test.describe('initial size', () => {
  for (const [name, input, kind] of [
    ['SD-JWT with 27 disclosures (RFC 9901 A.3)', MANY, 'SD-JWT'],
    ['SD-CWT with 15 disclosures (draft -08 nested issuer token)', MANY_CWT, 'SD-CWT'],
  ] as const) {
    test(`${name}: the SD view starts at most a third of the window high`, async ({ page }) => {
      await paste(page, input());
      await expect(page.getByTestId('detected-type')).toHaveText(kind);
      await expect(sdSplitter(page)).toBeVisible();
      const third = (await innerHeight(page)) / 3;
      expect(await height(sdRegion(page))).toBeLessThanOrEqual(third + TOLERANCE);
    });
  }

  test('many disclosures fill the third and scroll on their own', async ({ page }) => {
    await paste(page, MANY());
    await expect(sdSplitter(page)).toBeVisible();
    const third = (await innerHeight(page)) / 3;
    const h = await height(sdRegion(page));
    expect(h).toBeGreaterThan(third * 0.8);
    expect(h).toBeLessThanOrEqual(third + TOLERANCE);
    // the SD view scrolls by itself, separately from the panes
    expect(await sdScroller(page)).toEqual({ overflows: true });
    const main = await scroller(mainPane(page));
    expect(main).not.toBeNull();
    const regionHoldsMain = await sdRegion(page).evaluate(
      (region, mainEl) => (mainEl ? region.contains(mainEl) : false),
      await mainPane(page).elementHandle(),
    );
    expect(regionHoldsMain).toBe(false);
  });

  test('a couple of disclosures: the SD view shrinks to fit them', async ({ page }) => {
    // a tall window, so that a third is clearly more than the short content
    await page.setViewportSize({ width: 1280, height: 1200 });
    await paste(page, MANY());
    await expect(sdSplitter(page)).toBeVisible();
    const many = await height(sdRegion(page));

    await page.getByRole('button', { name: 'New tab' }).click();
    await paste(page, FEW());
    await expect(page.getByTestId('detected-type')).toHaveText('SD-KBT');
    await expect(sdSplitter(page)).toBeVisible();
    const few = await height(sdRegion(page));
    expect(many).toBeGreaterThan(1200 / 3 - 40);
    expect(few).toBeLessThan(many - 40);
    expect(few).toBeLessThan((await innerHeight(page)) / 3);
    // shrunk to its content: nothing inside needs scrolling
    expect((await sdScroller(page))?.overflows ?? false).toBe(false);
  });
});

test.describe('splitter', () => {
  test('dragging it resizes the SD view; both sides keep a minimum', async ({ page }) => {
    await paste(page, MANY());
    const splitter = sdSplitter(page);
    await expect(splitter).toBeVisible();
    const start = await height(sdRegion(page));

    await dragBy(page, splitter, 0, -120);
    const taller = await height(sdRegion(page));
    expect(taller).toBeGreaterThan(start + 100);
    expect(taller).toBeLessThan(start + 140);
    expect(Number(await splitter.getAttribute('aria-valuenow'))).toBeCloseTo(taller, -1);

    await dragBy(page, splitter, 0, 200);
    const shorter = await height(sdRegion(page));
    expect(shorter).toBeLessThan(taller - 180);

    // all the way up: the panes keep their minimum and still scroll
    const top = (await splitter.boundingBox())?.y ?? 0;
    await dragBy(page, splitter, 0, 2 - top);
    const main = await scroller(mainPane(page));
    expect(main?.clientHeight ?? 0).toBeGreaterThanOrEqual(64);
    // all the way down: the SD view keeps its minimum
    const y = (await splitter.boundingBox())?.y ?? 0;
    await dragBy(page, splitter, 0, (await innerHeight(page)) - 2 - y);
    const min = Number(await splitter.getAttribute('aria-valuemin'));
    expect(min).toBeGreaterThanOrEqual(40);
    expect(await height(sdRegion(page))).toBeGreaterThanOrEqual(min - 1);
    await expect(sdRegion(page)).toBeInViewport();
  });

  test('ArrowUp / ArrowDown resize from the keyboard', async ({ page }) => {
    await paste(page, SD_JWT());
    const splitter = sdSplitter(page);
    await expect(splitter).toBeVisible();
    await splitter.focus();
    await expect(splitter).toBeFocused();
    const start = await height(sdRegion(page));
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('ArrowDown');
    const shorter = await height(sdRegion(page));
    expect(shorter).toBeLessThan(start);
    await page.keyboard.press('ArrowUp');
    expect(await height(sdRegion(page))).toBeGreaterThan(shorter);
  });

  test("the user's size sticks to its tab across tab switches", async ({ page }) => {
    await paste(page, MANY());
    await expect(sdSplitter(page)).toBeVisible();
    await dragBy(page, sdSplitter(page), 0, -100);
    const sized = await height(sdRegion(page));
    await page.getByRole('button', { name: 'New tab' }).click();
    await paste(page, SD_CWT());
    await expect(sdSplitter(page)).toBeVisible();
    const tabs = page.getByRole('tablist', { name: 'Credentials' }).getByRole('tab');
    await tabs.first().click();
    await expect(sdSplitter(page)).toBeVisible();
    expect(Math.abs((await height(sdRegion(page))) - sized)).toBeLessThanOrEqual(1);
  });
});

test.describe('columns', () => {
  test('Claim starts narrow and Status small, even in a wide window', async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1000 });
    await paste(page, SD_JWT());
    const claim = columnHeader(page, 'Claim');
    await expect(claim).toBeVisible();
    // No column soaks up the spare width.
    expect(await width(claim)).toBeLessThanOrEqual(130);
    expect(await width(columnHeader(page, 'Status'))).toBeLessThanOrEqual(96);

    const handle = columnHandle(page, 'Claim');
    const before = await width(claim);
    await dragBy(page, handle, 60, 0);
    expect(await width(claim)).toBeGreaterThan(before + 30);
  });

  for (const [name, input] of [
    ['SD-JWT', SD_JWT],
    ['SD-CWT', SD_CWT],
  ] as const) {
    test(`${name}: dragging the Value handle widens the column; keyboard too`, async ({ page }) => {
      await paste(page, input());
      const header = columnHeader(page, 'Value');
      const handle = columnHandle(page, 'Value');
      await expect(handle).toBeVisible();
      const before = await width(header);
      await dragBy(page, handle, 80, 0);
      const after = await width(header);
      expect(after).toBeGreaterThan(before + 40);
      expect(Number(await handle.getAttribute('aria-valuenow'))).toBeGreaterThan(before + 40);

      await handle.focus();
      await page.keyboard.press('ArrowLeft');
      await page.keyboard.press('ArrowLeft');
      expect(await width(header)).toBeLessThan(after);
    });

    test(`${name}: narrow Salt and Digest truncate with an ellipsis but keep the full text`, async ({
      page,
    }) => {
      await paste(page, input());
      await expect(columnHandle(page, 'Salt')).toBeVisible();
      await dragBy(page, columnHandle(page, 'Salt'), -600, 0);
      await columnHandle(page, 'Digest').focus();
      for (let i = 0; i < 60; i += 1) await page.keyboard.press('ArrowLeft');

      for (const column of ['Salt', 'Digest']) {
        const cell = await columnCell(page, column, 0);
        const state = await truncation(cell);
        expect(state.full.length).toBeGreaterThan(8);
        expect(state.full).not.toContain('…');
        expect(state.textOverflow).toBe('ellipsis');
        expect(state.whiteSpace).toMatch(/nowrap|pre/);
        expect(state.clipped).toBe(true);
        expect(state.title).toBe(state.full);
      }
    });
  }

  test('copying a selected, truncated Salt cell copies the whole salt', async ({
    page,
    context,
  }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: ORIGIN });
    await paste(page, SD_JWT());
    await expect(columnHandle(page, 'Salt')).toBeVisible();
    await dragBy(page, columnHandle(page, 'Salt'), -600, 0);
    const cell = await columnCell(page, 'Salt', 0);
    const full = ((await cell.textContent()) ?? '').trim();
    expect((await truncation(cell)).clipped).toBe(true);

    const selected = await cell.evaluate((td) => {
      const range = document.createRange();
      range.selectNodeContents(td);
      const sel = window.getSelection();
      sel?.removeAllRanges();
      sel?.addRange(range);
      return sel?.toString() ?? '';
    });
    expect(selected.trim()).toBe(full);
    await page.keyboard.press('ControlOrMeta+c');
    const copied = await page.evaluate(() => navigator.clipboard.readText());
    expect(copied.trim()).toBe(full);
    expect(copied).not.toContain('…');
  });
});

test.describe('Value wraps', () => {
  // 192 bytes: 384 hex digits with no spaces to break at.
  const HEX = '00112233445566778899aabbccddeeff'.repeat(12);

  test("a long h'' value wraps inside its column; the table does not overflow", async ({
    page,
  }) => {
    await createKey(page, 'EC P-256', 'issuer');
    await paste(page, `{1: "https://issuer.example", 58(503): h'${HEX}'}`);
    await expect(page.getByTestId('detected-type')).toHaveText('EDN claim set');
    await actions(page).getByRole('button', { name: 'Redact' }).click();
    const dialog = page.getByRole('dialog', { name: 'Redact' });
    await dialog.getByRole('button', { name: 'Redact' }).click();
    await expect(page.getByTestId('detected-type')).toHaveText('SD-CWT');
    await expect(disclosuresTable(page)).toBeVisible();

    const cell = await columnCell(page, 'Value', 0);
    const text = ((await cell.textContent()) ?? '').replace(/\s/g, '');
    expect(text).toContain(HEX);
    expect(text).not.toContain('…');

    const layout = await cell.evaluate((td) => {
      const range = document.createRange();
      range.selectNodeContents(td);
      const lines = new Set([...range.getClientRects()].map((r) => Math.round(r.top))).size;
      const table = td.closest('table') as HTMLTableElement;
      let box: HTMLElement | null = table.parentElement;
      while (box && box.clientWidth === 0) box = box.parentElement;
      return {
        lines,
        cellOverflow: td.scrollWidth - td.clientWidth,
        tableWidth: table.getBoundingClientRect().width,
        boxWidth: box?.clientWidth ?? 0,
        boxOverflow: box ? box.scrollWidth - box.clientWidth : 0,
      };
    });
    expect(layout.lines).toBeGreaterThan(1);
    expect(layout.cellOverflow).toBeLessThanOrEqual(1);
    expect(layout.tableWidth).toBeLessThanOrEqual(layout.boxWidth + 1);
    expect(layout.boxOverflow).toBeLessThanOrEqual(1);
    // the panel itself does not scroll sideways because of it
    expect(
      await activePanel(page).evaluate((p) => p.scrollWidth - p.clientWidth),
    ).toBeLessThanOrEqual(1);
  });
});
