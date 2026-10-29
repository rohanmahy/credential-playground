// Shared helpers for the e2e specs. They run against `vite preview` of the
// production build with the real WASM engine (playwright.config.ts).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, type BrowserContext, type Page } from '@playwright/test';
import { ORIGIN } from '../playwright.config';

const testdata = join(import.meta.dirname, '../../testdata');

export function fixtureText(path: string): string {
  return readFileSync(join(testdata, path), 'utf8').trim();
}

/** Binary fixtures are pasted as hex, which detection unwraps. */
export function fixtureHex(path: string): string {
  return readFileSync(join(testdata, path)).toString('hex');
}

export async function paste(page: Page, text: string): Promise<void> {
  const box = page.getByRole('textbox', { name: /paste a credential or key/i });
  await box.fill(text);
  await page.getByRole('button', { name: 'Open', exact: true }).click();
}

export function actions(page: Page) {
  return page.getByRole('toolbar', { name: 'Actions' });
}

export async function validate(page: Page) {
  await actions(page).getByRole('button', { name: 'Validate' }).click();
  const report = page.getByRole('list', { name: 'Validation report' });
  await expect(report).toBeVisible();
  return report;
}

export async function createKey(
  page: Page,
  algorithm: string,
  role: 'issuer' | 'holder' | 'verifier',
): Promise<void> {
  await page.getByRole('button', { name: 'Create key' }).click();
  const dialog = page.getByRole('dialog', { name: 'Create key' });
  await dialog.getByRole('combobox', { name: 'Algorithm' }).selectOption({ label: algorithm });
  await dialog.getByRole('radio', { name: /well-known test seed/i }).check();
  await dialog.getByRole('combobox', { name: 'Role' }).selectOption(role);
  await dialog.getByRole('button', { name: 'Create' }).click();
  await expect(dialog).toBeHidden();
}

/** Import Key dialog → paste → Import. */
export async function importKey(page: Page, text: string): Promise<void> {
  await page.getByRole('button', { name: 'Import key' }).click();
  const dialog = page.getByRole('dialog', { name: 'Import key' });
  await dialog.getByRole('textbox', { name: 'Key' }).fill(text);
  await dialog.getByRole('button', { name: 'Import' }).click();
  await expect(dialog).toBeHidden();
}

/**
 * Records every request the page makes. Requests to any origin other than
 * the app's own are aborted (and recorded), so nothing leaves the machine
 * even if the app misbehaves. A test that fulfils some URL itself (the
 * IANA registries) registers its own route afterwards, which takes
 * precedence.
 */
export async function guardNetwork(context: BrowserContext): Promise<{
  all: string[];
  foreign: string[];
}> {
  const log = { all: [] as string[], foreign: [] as string[] };
  await context.route('**/*', async (route) => {
    const url = route.request().url();
    log.all.push(url);
    if (new URL(url).origin === ORIGIN) return route.continue();
    log.foreign.push(url);
    return route.abort('blockedbyclient');
  });
  return log;
}

/** Collects `securitypolicyviolation` events from page load on. */
export async function watchCsp(page: Page): Promise<() => Promise<string[]>> {
  await page.addInitScript(() => {
    const seen: string[] = [];
    (window as unknown as { __csp: string[] }).__csp = seen;
    document.addEventListener('securitypolicyviolation', (e) =>
      seen.push(`${e.effectiveDirective} ${e.blockedURI}`),
    );
  });
  return () => page.evaluate(() => (window as unknown as { __csp: string[] }).__csp);
}
