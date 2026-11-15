// Checklist §4: the Issuer and Holder key areas on the native engine. Create
// (seeded) → Auto kid → COSE_Key view → export; the exported public JWK
// goes through the system clipboard (Rust clipboard plugin, X11 under
// Xvfb) and back into the Holder area via Import → From clipboard. Also a
// pasted JWK Set through the chooser, and Make public. Mirrors
// app/e2e/keys.spec.ts.
import { browser } from '@wdio/globals';
import {
  appReady,
  closeDialog,
  createKey,
  expectFieldText,
  expectThat,
  fixtureText,
  keyArea,
  keyBox,
  keyFormat,
  page,
  pasteKey,
} from '../helpers';

describe('key areas', () => {
  beforeEach(async () => {
    await browser.refresh();
    await appReady();
  });

  it('create (well-known seed), Auto kid, COSE_Key view, export the public JWK', async () => {
    await createKey('EC P-256', 'issuer');
    const issuer = keyArea('issuer');
    await expectThat(issuer).toContainText('EC P-256');
    await expectThat(issuer).toContainText('Private');
    await expectThat(issuer).toContainText('Generated');

    await issuer.getByRole('button', 'Auto kid').click();
    await page.getByRole('menuitem', 'JWK thumbprint').click();
    // RFC 7638 thumbprints are 43 base64url characters for SHA-256.
    await expectThat(issuer.getByTestId('kid')).toHaveText(/^[A-Za-z0-9_-]{43}$/);
    const kid = await issuer.getByTestId('kid').text();

    await keyFormat('issuer', 'COSE_Key').click();
    await expectFieldText(keyBox('issuer'), (t) => t.includes('/ kty / 1: / EC2 / 2'), 'is EDN');
    await keyFormat('issuer', 'JWK').click();
    await expectFieldText(keyBox('issuer'), (t) => t.includes('"kty"'), 'is JWK');

    await issuer.getByRole('button', 'Export').click();
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

    // Round trip through the system clipboard into the Holder area.
    await keyArea('holder').getByRole('button', 'Import').click();
    const imp = page.getByRole('dialog', 'Import key');
    await imp.getByRole('button', 'From clipboard').click();
    await expectThat(imp).toBeHidden();
    const holder = keyArea('holder');
    await expectThat(holder).toContainText('Public');
    await expectThat(holder.getByTestId('kid')).toHaveText(kid);
  });

  it('a pasted private JWK; Make public replaces it with its public part', async () => {
    await pasteKey('holder', fixtureText('keys/sd-cwt-08-c1-holder-private.jwk.json'));
    const holder = keyArea('holder');
    await expectThat(holder).toContainText(/P-256/);
    await expectThat(holder).toContainText('Private');
    await holder.getByRole('button', 'Make public').click();
    await expectThat(holder).toContainText('Public');
    await expectFieldText(keyBox('holder'), (t) => !t.includes('"d"'), 'has no "d"');
  });

  it('a pasted JWK Set goes through the chooser', async () => {
    await pasteKey('issuer', fixtureText('keys/rfc7517-a1-public.jwks.json'));
    const chooser = page.getByRole('dialog', 'Choose a key');
    await expectThat(chooser).toBeVisible();
    await chooser.getByRole('button', /2011-04-29/).click();
    await expectThat(chooser).toBeHidden();
    await expectThat(keyArea('issuer').getByTestId('kid')).toHaveText('2011-04-29');
  });

  it('Ed25519 and ML-DSA-65 generate natively, one per area', async () => {
    await createKey('Ed25519', 'holder');
    await createKey('ML-DSA-65', 'issuer');
    await expectThat(keyArea('holder')).toContainText('Ed25519');
    await expectThat(keyArea('issuer')).toContainText('ML-DSA-65');
  });

  it('Clear empties an area', async () => {
    await createKey('Ed25519', 'holder');
    await keyArea('holder').getByRole('button', 'Clear').click();
    await expectFieldText(keyBox('holder'), (t) => t === '', 'is empty');
    await expectThat(keyArea('holder').getByTestId('kid')).toHaveCount(0);
  });
});
