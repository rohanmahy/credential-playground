// Local only (SPEC §1): during the main flows the page talks to nothing but
// its own origin. Every other request is aborted by the route guard and
// recorded. The IANA registry update is the one user-confirmed exception.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, test } from '@playwright/test';
import { ORIGIN } from '../playwright.config';
import {
  actions,
  createKey,
  fixtureHex,
  fixtureText,
  guardNetwork,
  importKey,
  paste,
  validate,
} from './helpers';

test('paste, validate, issue, present, and key flows stay on the app origin', async ({
  page,
  context,
}) => {
  test.setTimeout(120_000);
  const net = await guardNetwork(context);
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto('/');

  for (const input of [
    fixtureText('tokens/rfc9901-s5.2-sd-jwt-kb.txt'),
    fixtureHex('tokens/sd-cwt-08-sd-kbt.cbor'),
  ]) {
    await paste(page, input);
    await validate(page);
  }

  await createKey(page, 'EC P-256', 'issuer');
  await createKey(page, 'Ed25519', 'holder');
  await importKey(page, fixtureText('keys/rfc9901-a5-ec-p256-public.jwk.json'));
  await paste(page, fixtureText('tokens/rfc9901-a1-input-claims.json'));
  await actions(page).getByRole('button', { name: 'Issue' }).click();
  await page.getByRole('dialog', { name: 'Issue' }).getByRole('button', { name: 'Issue' }).click();
  await actions(page).getByRole('button', { name: 'Present' }).click();
  await page
    .getByRole('dialog', { name: 'Present' })
    .getByRole('button', { name: 'Present' })
    .click();
  await validate(page);

  const card = page.getByRole('complementary', { name: 'Keys' }).getByRole('article').first();
  await card.getByRole('button', { name: 'Convert' }).click();
  await expect(page.getByRole('region', { name: 'COSE_Key' })).toBeVisible();

  expect(net.foreign).toEqual([]);
  // The app did load its own assets, including the wasm module.
  expect(net.all.some((u) => u.endsWith('.wasm'))).toBe(true);
  for (const u of net.all) expect(new URL(u).origin).toBe(ORIGIN);
});

test('a key URL is fetched only after the user confirms it', async ({ page, context }) => {
  const net = await guardNetwork(context);
  await page.goto('/');
  await page.getByRole('button', { name: 'Fetch from URL' }).click();
  await page.getByRole('textbox', { name: 'URL' }).fill('https://issuer.example/jwks.json');
  await page.getByRole('button', { name: 'Fetch', exact: true }).click();
  const confirm = page.getByRole('alertdialog');
  await expect(confirm).toContainText('https://issuer.example/jwks.json');
  expect(net.foreign).toEqual([]);
  await confirm.getByRole('button', { name: 'Cancel' }).click();
  expect(net.foreign).toEqual([]);
});

test('Update registries fetches only www.iana.org, only after confirmation', async ({
  page,
  context,
}) => {
  const net = await guardNetwork(context);
  const iana: string[] = [];
  // Registered after the guard, so it takes precedence for these URLs.
  await context.route('https://www.iana.org/assignments/**', async (route) => {
    const url = route.request().url();
    iana.push(url);
    const which = /assignments\/(\w+)\//.exec(url)?.[1] ?? '';
    await route.fulfill({
      status: 200,
      contentType: 'application/xml',
      headers: { 'access-control-allow-origin': '*' },
      body: readFileSync(join(import.meta.dirname, `../../testdata/iana/${which}.xml`)),
    });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Settings' }).click();
  await page.getByRole('button', { name: 'Update registries' }).click();
  const confirm = page.getByRole('alertdialog', { name: 'Fetch the IANA registries?' });
  await expect(confirm).toBeVisible();
  expect(iana).toEqual([]);

  await confirm.getByRole('button', { name: 'Cancel' }).click();
  expect(iana).toEqual([]);

  await page.getByRole('button', { name: 'Update registries' }).click();
  await page
    .getByRole('alertdialog', { name: 'Fetch the IANA registries?' })
    .getByRole('button', { name: 'Fetch' })
    .click();
  await expect(page.getByText(/Registries updated/)).toBeVisible();
  expect(iana.sort()).toEqual([
    'https://www.iana.org/assignments/cose/cose.xml',
    'https://www.iana.org/assignments/cwt/cwt.xml',
    'https://www.iana.org/assignments/jose/jose.xml',
    'https://www.iana.org/assignments/jwt/jwt.xml',
  ]);
  expect(net.foreign).toEqual([]);
});
