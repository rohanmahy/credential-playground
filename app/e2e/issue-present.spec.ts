// Issue → Present → Validate, JOSE and COSE, with created keys.
import { expect, test } from '@playwright/test';
import { createKey, fixtureText, paste, skipUnlessEnabled, validate } from './helpers';

skipUnlessEnabled();

test.beforeEach(async ({ page }) => {
  await page.goto('/');
  await createKey(page, 'EC P-256', 'issuer');
  await createKey(page, 'Ed25519', 'holder');
});

test('SD-JWT: issue with marked claims, present, validate', async ({ page }) => {
  await paste(page, fixtureText('tokens/rfc9901-a1-input-claims.json'));
  await expect(page.getByTestId('detected-type')).toHaveText('JSON claim set');
  const main = page.getByRole('tree', { name: 'Main pane' });
  await main.locator('[data-node-id="given_name"]').click({ button: 'right' });
  await page.getByRole('menuitemcheckbox', { name: /selectively disclosable/i }).click();
  await page.getByRole('button', { name: 'Issue' }).click();
  await page.getByRole('dialog', { name: 'Issue' }).getByRole('button', { name: 'Issue' }).click();
  await expect(page.getByTestId('detected-type')).toHaveText('SD-JWT');

  await page.getByRole('button', { name: 'Present' }).click();
  const present = page.getByRole('dialog', { name: 'Present' });
  await present.getByRole('textbox', { name: 'Audience' }).fill('https://verifier.example');
  await present.getByRole('textbox', { name: 'Nonce' }).fill('n-0S6');
  await present.getByRole('button', { name: 'Present' }).click();
  await expect(page.getByTestId('detected-type')).toHaveText('SD-JWT+KB');
  await expect(page.getByRole('navigation', { name: 'Provenance' })).toContainText('Present');

  const report = await validate(page);
  await expect(page.getByTestId('report-overall')).toHaveText(/pass/i);
  await expect(report).toContainText(/key binding/i);
});

test('SD-CWT: redact tagged EDN, present as SD-KBT, validate', async ({ page }) => {
  await paste(page, fixtureText('tokens/sd-cwt-08-fig4-claims.edn'));
  await expect(page.getByTestId('detected-type')).toHaveText('EDN claim set');
  await page.getByRole('button', { name: 'Redact' }).click();
  await page
    .getByRole('dialog', { name: 'Redact' })
    .getByRole('button', { name: 'Redact' })
    .click();
  await expect(page.getByTestId('detected-type')).toHaveText('SD-CWT');

  await page.getByRole('button', { name: 'Present' }).click();
  await page
    .getByRole('dialog', { name: 'Present' })
    .getByRole('button', { name: 'Present' })
    .click();
  await expect(page.getByTestId('detected-type')).toHaveText('SD-KBT');

  await validate(page);
  await expect(page.getByTestId('report-overall')).toHaveText(/pass|warn/i);
});
