// The Issuer key and Holder key areas (SPEC §4.2) through the real
// WasmEngine: paste with key detection, the JWK / COSE_Key toggle, the
// chooser for sets, errors for non-keys, create, export, Make public,
// Auto kid, and Clear.
import { expect, test } from '@playwright/test';
import {
  NAMES,
  createKey,
  fixtureHex,
  fixtureText,
  keyArea,
  keyBox,
  keyFormat,
  pasteKey,
  tabs,
  textOf,
} from './helpers';

test.beforeEach(async ({ page }) => {
  await page.goto('/');
});

test('a JWK pasted into the Issuer area is shown, and toggles to COSE_Key and back', async ({
  page,
}) => {
  await pasteKey(page, 'issuer', fixtureText('keys/rfc9901-a5-ec-p256-public.jwk.json'));
  const issuer = keyArea(page, 'issuer');
  await expect(issuer).toContainText('P-256');
  await expect(issuer).toContainText(/public/i);
  await expect(issuer).toContainText('Pasted');
  await expect(keyFormat(page, 'issuer', 'JWK')).toBeChecked();
  await expect.poll(() => textOf(keyBox(page, 'issuer'))).toContain('"kty"');

  await keyFormat(page, 'issuer', 'COSE_Key').check();
  await expect.poll(() => textOf(keyBox(page, 'issuer'))).toContain('/ kty / 1:');
  await expect.poll(() => textOf(keyBox(page, 'issuer'))).not.toContain('"kty"');

  await keyFormat(page, 'issuer', 'JWK').check();
  await expect.poll(() => textOf(keyBox(page, 'issuer'))).toContain('"kty"');
  // the Holder area is untouched
  expect(await textOf(keyBox(page, 'holder'))).toBe('');
  await expect(tabs(page)).toHaveCount(1);
});

test('a PEM key pasted into an area shows as JWK', async ({ page }) => {
  await pasteKey(page, 'holder', fixtureText('keys/sd-cwt-08-c1-holder-public.pem'));
  await expect(keyArea(page, 'holder')).toContainText('P-256');
  await expect(keyFormat(page, 'holder', 'JWK')).toBeChecked();
  await expect.poll(() => textOf(keyBox(page, 'holder'))).toContain('"kty"');
  expect(await textOf(keyBox(page, 'holder'))).not.toContain('BEGIN');
});

test('a COSE_Key pasted as hex: the toggle follows the detected format', async ({ page }) => {
  await pasteKey(page, 'issuer', fixtureHex('keys/sd-cwt-08-c2-issuer-private.cosekey.cbor'));
  await expect(keyArea(page, 'issuer')).toContainText(/private/i);
  await expect(keyFormat(page, 'issuer', 'COSE_Key')).toBeChecked();
  await expect.poll(() => textOf(keyBox(page, 'issuer'))).toContain('/ kty / 1:');
});

test('a token pasted into a key area: "Not a recognized key", and no key', async ({ page }) => {
  await pasteKey(page, 'issuer', fixtureText('tokens/rfc7515-a3-jws-es256.txt'));
  const issuer = keyArea(page, 'issuer');
  await expect(issuer.getByRole('alert')).toContainText(NAMES.notAKey);
  await expect(issuer.getByTestId('kid')).toHaveCount(0);
  await expect(tabs(page)).toHaveCount(1);
});

test('a JWK Set opens the chooser; the key picked fills the area', async ({ page }) => {
  await pasteKey(page, 'holder', fixtureText('keys/rfc7517-a1-public.jwks.json'));
  const chooser = page.getByRole('dialog', { name: NAMES.chooser });
  await expect(chooser).toBeVisible();
  const ec = chooser.getByRole('button', { name: /\b1\b.*EC|EC.*\b1\b/ });
  const rsa = chooser.getByRole('button', { name: /2011-04-29/ });
  await expect(ec).toBeVisible();
  await expect(rsa).toContainText('RS256');
  await expect(rsa).toContainText('RSA');
  await rsa.click();
  await expect(chooser).toBeHidden();
  await expect(keyArea(page, 'holder')).toContainText('RSA');
  await expect(keyArea(page, 'holder').getByTestId('kid')).toHaveText('2011-04-29');
  expect(await textOf(keyBox(page, 'issuer'))).toBe('');
});

test('a COSE_KeySet (hex) opens the chooser too', async ({ page }) => {
  await pasteKey(page, 'issuer', fixtureHex('keys/rfc8152-c7.1-public.cosekeyset.cbor'));
  const chooser = page.getByRole('dialog', { name: NAMES.chooser });
  await expect(chooser).toBeVisible();
  // key buttons name their kty (EC2 / OKP …); not the dialog's Close
  const keys = chooser.getByRole('button', { name: /\b(EC2?|OKP|RSA)\b/ });
  expect(await keys.count()).toBeGreaterThan(1);
  await keys.first().click();
  await expect(chooser).toBeHidden();
  await expect(keyArea(page, 'issuer').getByTestId('kid')).not.toBeEmpty();
});

test('typing a JWK into an empty area parses it without detection', async ({ page }) => {
  const box = keyBox(page, 'issuer');
  await box.click();
  await page.keyboard.insertText(fixtureText('keys/rfc9901-a5-ec-p256-public.jwk.json'));
  await expect(keyArea(page, 'issuer')).toContainText('P-256');
});

test('typed text that does not parse shows an error and leaves no key', async ({ page }) => {
  const box = keyBox(page, 'issuer');
  await box.click();
  await page.keyboard.insertText('{"kty": "EC", ');
  await expect(keyArea(page, 'issuer').getByRole('alert')).toBeVisible();
  await expect(keyArea(page, 'issuer').getByTestId('kid')).toHaveCount(0);
});

test('create, view as COSE_Key, and export the private key with confirmation', async ({
  page,
  context,
}) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await createKey(page, 'EC P-256', 'issuer');
  const issuer = keyArea(page, 'issuer');
  await expect(issuer).toContainText('EC P-256');
  await expect(issuer).toContainText(/private/i);
  await expect(issuer).toContainText('Generated');

  await keyFormat(page, 'issuer', 'COSE_Key').check();
  await expect.poll(() => textOf(keyBox(page, 'issuer'))).toContain('/ kty / 1: / EC2 / 2');

  await issuer.getByRole('button', { name: 'Export' }).click();
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

test('Make public replaces the key with its public part; Auto kid sets the thumbprint', async ({
  page,
}) => {
  await pasteKey(page, 'holder', fixtureText('keys/sd-cwt-08-c1-holder-private.jwk.json'));
  const holder = keyArea(page, 'holder');
  await expect(holder).toContainText(/private/i);
  await holder.getByRole('button', { name: 'Make public' }).click();
  await expect(holder).toContainText(/public/i);
  await expect.poll(() => textOf(keyBox(page, 'holder'))).not.toContain('"d"');

  await holder.getByRole('button', { name: 'Auto kid' }).click();
  await page.getByRole('menuitem', { name: 'JWK thumbprint' }).click();
  // RFC 7638 thumbprints are 43 base64url characters for SHA-256.
  await expect(holder.getByTestId('kid')).toHaveText(/^[A-Za-z0-9_-]{43}$/);
});

test('Clear empties the area, and the next paste autodetects again', async ({ page }) => {
  await createKey(page, 'Ed25519', 'holder');
  const holder = keyArea(page, 'holder');
  await holder.getByRole('button', { name: NAMES.clear }).click();
  await expect.poll(() => textOf(keyBox(page, 'holder'))).toBe('');
  await expect(holder.getByTestId('kid')).toHaveCount(0);
  await pasteKey(page, 'holder', fixtureText('keys/rfc7517-a1-public.jwks.json'));
  await expect(page.getByRole('dialog', { name: NAMES.chooser })).toBeVisible();
});

test('nothing is written to storage during a session', async ({ page }) => {
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

test('every algorithm in the Create key list generates in wasm', async ({ page }) => {
  test.setTimeout(180_000);
  for (const alg of [
    'EC P-384',
    'EC P-521',
    'Ed25519',
    'ML-DSA-44',
    'ML-DSA-65',
    'ML-DSA-87',
    'RSA 2048',
  ]) {
    await createKey(page, alg, 'issuer');
    await expect(keyArea(page, 'issuer')).toContainText(
      alg.replace(/^EC /, '').split(' ')[0] ?? alg,
    );
  }
});

test('export a public JWK without the private-key confirmation', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await createKey(page, 'Ed25519', 'holder');
  await keyArea(page, 'holder').getByRole('button', { name: 'Export' }).click();
  const dialog = page.getByRole('dialog', { name: 'Export key' });
  await dialog.getByRole('combobox', { name: 'Format' }).selectOption({ label: 'JWK' });
  await expect(dialog.getByRole('radio', { name: 'Public' })).toBeChecked();
  await dialog.getByRole('button', { name: 'Copy public key' }).click();
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  const jwk = JSON.parse(copied) as Record<string, unknown>;
  expect(jwk).toMatchObject({ kty: 'OKP', crv: 'Ed25519' });
  expect(jwk).not.toHaveProperty('d');
});
