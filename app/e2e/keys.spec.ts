// Key create → convert (JWK and CWK side by side) → export.
import { expect, test } from '@playwright/test';
import { createKey, skipUnlessEnabled } from './helpers';

skipUnlessEnabled();

test('create, convert, and export a key', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto('/');
  await createKey(page, 'EC P-256', 'issuer');
  const card = page.getByRole('complementary', { name: 'Keys' }).getByRole('article').first();
  await expect(card).toContainText('EC P-256');
  await expect(card).toContainText(/private/i);

  await card.getByRole('button', { name: 'Convert' }).click();
  await expect(page.getByRole('region', { name: 'JWK' })).toContainText('"kty":"EC"');
  await expect(page.getByRole('region', { name: 'COSE_Key' })).toContainText('/ kty / 1: 2');

  await card.getByRole('button', { name: 'Export' }).click();
  const dialog = page.getByRole('dialog', { name: 'Export key' });
  await dialog.getByRole('radio', { name: 'Private' }).check();
  await expect(dialog.getByRole('button', { name: 'Copy private key' })).toBeDisabled();
  await dialog
    .getByRole('checkbox', { name: /I understand this exports the private key/i })
    .check();
  await dialog.getByRole('button', { name: 'Copy private key' }).click();
  await expect(dialog.getByRole('status')).toHaveText(/private key copied/i);
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  expect(JSON.parse(copied)).toHaveProperty('d');
});

test('nothing is written to storage during a session', async ({ page }) => {
  await page.goto('/');
  await createKey(page, 'Ed25519', 'holder');
  // Runs in the page: checking storage is the point of this test.
  const stored = await page.evaluate(async () => ({
    local: window.localStorage.length,
    session: window.sessionStorage.length,
    dbs: (await indexedDB.databases()).map((d) => d.name),
  }));
  expect(stored.local).toBe(0);
  expect(stored.session).toBe(0);
  expect(stored.dbs.filter((n) => n !== 'tokenator-registry')).toEqual([]);
});
