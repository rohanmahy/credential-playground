// Checklist §4: key create (seeded) → kid → convert → export, through the
// native engine; the exported public JWK goes through the system clipboard
// (Rust clipboard plugin, X11 under Xvfb) and back in via Import key →
// From clipboard. Mirrors app/e2e/keys.spec.ts.
import { browser } from '@wdio/globals';
import {
  appReady,
  closeDialog,
  createKey,
  expectThat,
  fixtureText,
  importKey,
  keyCards,
  page,
} from '../helpers';

describe('keys', () => {
  beforeEach(async () => {
    await browser.refresh();
    await appReady();
  });

  it('create (well-known seed), set kid, convert, export the public JWK', async () => {
    await createKey('EC P-256', 'issuer');
    const card = keyCards().first();
    await expectThat(card).toContainText('EC P-256');
    await expectThat(card.locator('.badge')).toHaveText('Private');
    await expectThat(card).toContainText('Generated');

    await card.getByRole('button', 'Set kid').click();
    await page.getByRole('menuitem', 'JWK thumbprint').click();
    // RFC 7638 thumbprints are 43 base64url characters for SHA-256.
    await expectThat(card.getByTestId('kid')).toHaveText(/^[A-Za-z0-9_-]{43}$/);

    await card.getByRole('button', 'Convert').click();
    await expectThat(page.getByRole('region', 'JWK')).toContainText('"kty":"EC"');
    await expectThat(page.getByRole('region', 'COSE_Key')).toContainText('/ kty / 1: / EC2 / 2');
    await closeDialog('Convert key');

    await card.getByRole('button', 'Export').click();
    const dialog = page.getByRole('dialog', 'Export key');
    // The private export stays gated until the confirmation is ticked.
    await dialog.getByRole('radio', 'Private').check();
    await expectThat(dialog.getByRole('button', 'Copy private key')).toBeDisabled();
    await dialog.getByRole('checkbox', /I understand this exports the private key/i).check();
    await expectThat(dialog.getByRole('button', 'Copy private key')).toBeDisabled(false);

    await dialog.getByRole('radio', 'Public').check();
    await dialog.getByRole('combobox', 'Format').selectOption('JWK');
    await dialog.getByRole('button', 'Copy public key').click();
    await expectThat(dialog.getByRole('status')).toHaveText(/public key copied/i);
    await closeDialog('Export key');

    // Round trip through the system clipboard: the same key, public only.
    const print = await card.locator('.print').first().text();
    await page.getByRole('button', 'Import key').click();
    const imp = page.getByRole('dialog', 'Import key');
    await imp.getByRole('button', 'From clipboard').click();
    await expectThat(imp).toBeHidden();
    await expectThat(keyCards()).toHaveCount(2);
    const imported = keyCards().last();
    await expectThat(imported.locator('.badge')).toHaveText('Public');
    await expectThat(imported.locator('.print').first()).toHaveText(print);
  });

  it('import a private JWK and derive its public key', async () => {
    await importKey(fixtureText('keys/sd-cwt-08-c1-holder-private.jwk.json'));
    const card = keyCards().first();
    await expectThat(card).toContainText(/P-256/);
    await card.getByRole('button', 'Derive public key').click();
    await expectThat(keyCards()).toHaveCount(2);
    await expectThat(keyCards().nth(1).locator('.badge')).toHaveText('Public');
  });

  it('Ed25519 and ML-DSA-65 generate natively', async () => {
    await createKey('Ed25519', 'holder');
    await createKey('ML-DSA-65', 'issuer');
    await expectThat(keyCards()).toHaveCount(2);
    await expectThat(keyCards().last()).toContainText('ML-DSA-65');
  });
});
