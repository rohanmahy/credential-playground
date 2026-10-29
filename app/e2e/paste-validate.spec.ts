// Paste a JWT / SD-JWT / CWT / SD-CWT → Validate.
import { expect, test } from '@playwright/test';
import { fixtureHex, fixtureText, paste, skipUnlessEnabled, validate } from './helpers';

skipUnlessEnabled();

test.beforeEach(async ({ page }) => {
  await page.goto('/');
});

test('JWT (RFC 7515 A.3, ES256)', async ({ page }) => {
  await paste(page, fixtureText('tokens/rfc7515-a3-jws-es256.txt'));
  await expect(page.getByTestId('detected-type')).toHaveText(/JWS|JWT/);
  await expect(page.getByRole('tree', { name: 'Main pane' })).toContainText('"alg":"ES256"');
  const report = await validate(page);
  // no key in the panel: the signature check is skipped, not failed
  await expect(report.locator('[data-status]').first()).toHaveAttribute('data-status', 'skip');
});

test('SD-JWT+KB (RFC 9901 §5.2)', async ({ page }) => {
  await paste(page, fixtureText('tokens/rfc9901-s5.2-sd-jwt-kb.txt'));
  await expect(page.getByTestId('detected-type')).toHaveText('SD-JWT+KB');
  await expect(page.getByRole('table', { name: 'Disclosures' })).toContainText('given_name');
  const report = await validate(page);
  await expect(report).toContainText(/disclosure/i);
});

test('CWT (RFC 8392 A.3, hex)', async ({ page }) => {
  await paste(page, fixtureText('tokens/rfc8392-a3-signed-cwt.hex'));
  await expect(page.getByTestId('detected-type')).toHaveText('CWT');
  await expect(page.getByRole('navigation', { name: 'Unwrapping layers' })).toContainText('hex');
  await expect(page.getByRole('tree', { name: 'Raw pane' })).toBeVisible();
  await validate(page);
});

test('SD-CWT (draft-ietf-spice-sd-cwt-08)', async ({ page }) => {
  await paste(page, fixtureHex('tokens/sd-cwt-08-issuer-sd-cwt.cbor'));
  await expect(page.getByTestId('detected-type')).toHaveText('SD-CWT');
  const report = await validate(page);
  await expect(report).toContainText(/disclosure/i);
});
