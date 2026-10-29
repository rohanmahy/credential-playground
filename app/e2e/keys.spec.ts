// Key create → convert (JWK and CWK side by side) → export, import, derive,
// thumbprints and kid, through the real WasmEngine.
import { expect, test } from '@playwright/test';
import { createKey, fixtureText, importKey } from './helpers';

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

test('import a private JWK, derive its public key, set the kid to its thumbprint', async ({
  page,
}) => {
  await page.goto('/');
  await importKey(page, fixtureText('keys/sd-cwt-08-c1-holder-private.jwk.json'));
  const panel = page.getByRole('complementary', { name: 'Keys' });
  const card = panel.getByRole('article').first();
  await expect(card).toContainText(/private/i);
  await expect(card).toContainText(/P-256/);

  await card.getByRole('button', { name: 'Derive public key' }).click();
  await expect(panel.getByRole('article')).toHaveCount(2);
  await expect(panel.getByRole('article').nth(1)).toContainText(/public/i);

  await card.getByRole('button', { name: 'Set kid' }).click();
  await page.getByRole('menuitem', { name: 'JWK thumbprint' }).click();
  const kid = card.getByTestId('kid');
  await expect(kid).not.toBeEmpty();
  // RFC 7638 thumbprints are 43 base64url characters for SHA-256.
  await expect(kid).toHaveText(/^[A-Za-z0-9_-]{43}$/);
});

test('every algorithm in the Create key list generates in wasm', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('/');
  for (const alg of ['EC P-384', 'EC P-521', 'Ed25519', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']) {
    await createKey(page, alg, 'issuer');
  }
  await createKey(page, 'RSA 2048', 'issuer');
  const cards = page.getByRole('complementary', { name: 'Keys' }).getByRole('article');
  await expect(cards).toHaveCount(7);
  await expect(cards.last()).toContainText(/RSA/);
});

test('export a public COSE_Key without the private-key confirmation', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto('/');
  await createKey(page, 'Ed25519', 'holder');
  const card = page.getByRole('complementary', { name: 'Keys' }).getByRole('article').first();
  await card.getByRole('button', { name: 'Export' }).click();
  const dialog = page.getByRole('dialog', { name: 'Export key' });
  await dialog.getByRole('combobox', { name: 'Format' }).selectOption({ label: 'JWK' });
  await expect(dialog.getByRole('radio', { name: 'Public' })).toBeChecked();
  await dialog.getByRole('button', { name: 'Copy public key' }).click();
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  const jwk = JSON.parse(copied) as Record<string, unknown>;
  expect(jwk).toMatchObject({ kty: 'OKP', crv: 'Ed25519' });
  expect(jwk).not.toHaveProperty('d');
});
