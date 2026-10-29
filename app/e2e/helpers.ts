// Shared helpers for the e2e specs. They run against `vite preview` of the
// production build with the real WASM engine, so they are skipped unless
// TOKENATOR_E2E=1 (see playwright.config.ts and app/TEST-PLAN.md).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, test, type Page } from '@playwright/test';

export const enabled = process.env['TOKENATOR_E2E'] === '1';

export function skipUnlessEnabled(): void {
  test.skip(!enabled, 'needs the WASM engine build; set TOKENATOR_E2E=1');
}

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
  await page.getByRole('button', { name: 'Open' }).click();
}

export async function validate(page: Page) {
  await page
    .getByRole('toolbar', { name: 'Actions' })
    .getByRole('button', { name: 'Validate' })
    .click();
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
