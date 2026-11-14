// Issue → Present → Validate, JOSE and COSE, with keys created in the
// Issuer and Holder key areas, through the real WasmEngine. Issue signs
// with the Issuer area key, Present with the Holder area key, and
// validation uses both (SPEC §4.2, §5, §6).
import { expect, test, type Page } from '@playwright/test';
import {
  NAMES,
  actions,
  createKey,
  fixtureText,
  keyArea,
  mainPane,
  paste,
  readOnly,
  validate,
} from './helpers';

// Key binding validates against `cnf` (SPEC §6), so credentials that are
// presented later are issued with the holder key as `cnf`, and the
// presentation carries an audience and nonce.
async function issueWithHolder(page: Page, action: 'Issue' | 'Redact'): Promise<void> {
  const dialog = page.getByRole('dialog', { name: action });
  await dialog.getByRole('checkbox', { name: NAMES.cnf }).check();
  await dialog.getByRole('button', { name: action }).click();
}

async function presentTo(page: Page): Promise<void> {
  const present = page.getByRole('dialog', { name: 'Present' });
  await present.getByRole('textbox', { name: 'Audience' }).fill('https://verifier.example');
  await present.getByRole('textbox', { name: 'Nonce' }).fill('n-0S6');
  await present.getByRole('button', { name: 'Present' }).click();
}

// Redact needs EDN with to-be-redacted (58) tags (SPEC §5); the claims of
// SD-CWT Figure 4 are the issuer's input before tagging.
const TAGGED_EDN =
  '{1: "https://issuer.example", 2: "https://holder.example", 6: 1725244200, ' +
  '58(500): true, 501: "ABCD-123456", 502: [58(1549560720), 1612498440]}';

test.beforeEach(async ({ page }) => {
  await page.goto('/');
  await createKey(page, 'EC P-256', 'issuer');
  await createKey(page, 'Ed25519', 'holder');
});

test('SD-JWT: issue with marked claims, present, validate', async ({ page }) => {
  await paste(page, fixtureText('tokens/rfc9901-a1-input-claims.json'));
  await expect(page.getByTestId('detected-type')).toHaveText('JSON claim set');
  await readOnly(page);
  const main = page.getByRole('tree', { name: 'Main pane' });
  await main.locator('[data-node-id="given_name"]').click({ button: 'right' });
  await page.getByRole('menuitemcheckbox', { name: /selectively disclosable/i }).click();
  await actions(page).getByRole('button', { name: 'Issue' }).click();
  await issueWithHolder(page, 'Issue');
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
  await paste(page, TAGGED_EDN);
  await expect(page.getByTestId('detected-type')).toHaveText('EDN claim set');
  await actions(page).getByRole('button', { name: 'Redact' }).click();
  await issueWithHolder(page, 'Redact');
  await expect(page.getByTestId('detected-type')).toHaveText('SD-CWT');

  await actions(page).getByRole('button', { name: 'Present' }).click();
  await presentTo(page);
  await expect(page.getByTestId('detected-type')).toHaveText('SD-KBT');

  await validate(page);
  await expect(page.getByTestId('report-overall')).toHaveText(/pass|warn/i);
});

test('JWT: issue a plain JWT and validate it with the issuer key', async ({ page }) => {
  await paste(page, fixtureText('tokens/rfc9901-s5.1-input-claims.json'));
  await actions(page).getByRole('button', { name: 'Issue' }).click();
  await page.getByRole('dialog', { name: 'Issue' }).getByRole('button', { name: 'Issue' }).click();
  await expect(page.getByTestId('detected-type')).toHaveText('JWT');
  await expect(page.getByRole('navigation', { name: 'Provenance' })).toContainText('Issue');
  const report = await validate(page);
  await expect(report.locator('[data-status]').first()).toHaveAttribute('data-status', 'pass');
});

test('CWT: issue from EDN, present in an SD-KBT, validate', async ({ page }) => {
  await paste(page, '{1: "https://issuer.example", 2: "alice", 4: 1900000000}');
  await expect(page.getByTestId('detected-type')).toHaveText('EDN claim set');
  await actions(page).getByRole('button', { name: 'Issue' }).click();
  await issueWithHolder(page, 'Issue');
  await expect(page.getByTestId('detected-type')).toHaveText('CWT');
  await expect(page.getByRole('tree', { name: 'Raw pane' })).toBeVisible();

  await actions(page).getByRole('button', { name: 'Present' }).click();
  await presentTo(page);
  await expect(page.getByTestId('detected-type')).toHaveText('SD-KBT');
  const report = await validate(page);
  await expect(report.locator('[data-status]').first()).toHaveAttribute('data-status', 'pass');
  await expect(page.getByTestId('report-overall')).toHaveText(/pass|warn/i);
});

test('ML-DSA-87: issue a JWT and validate it (post-quantum in the browser)', async ({ page }) => {
  // Create replaces the Issuer area's P-256 key.
  await createKey(page, 'ML-DSA-87', 'issuer');
  await expect(keyArea(page, 'issuer')).toContainText('ML-DSA-87');
  await paste(page, fixtureText('tokens/rfc9901-s5.1-input-claims.json'));
  await actions(page).getByRole('button', { name: 'Issue' }).click();
  const dialog = page.getByRole('dialog', { name: 'Issue' });
  await dialog.getByRole('button', { name: 'Issue' }).click();
  await expect(page.getByTestId('detected-type')).toHaveText('JWT');
  await expect(mainPane(page)).toContainText('"ML-DSA-87"');
  const report = await validate(page);
  await expect(report.locator('[data-status]').first()).toHaveAttribute('data-status', 'pass');
});

test('Issue needs the Issuer area key and Present the Holder area key', async ({ page }) => {
  await paste(page, '{1: "https://issuer.example", 2: "alice", 4: 1900000000}');
  const issue = actions(page).getByRole('button', { name: 'Issue' });
  await expect(issue).toHaveAttribute('aria-disabled', 'false');
  await issue.click();
  await issueWithHolder(page, 'Issue');
  await expect(page.getByTestId('detected-type')).toHaveText('CWT');
  const present = actions(page).getByRole('button', { name: 'Present' });
  await expect(present).toHaveAttribute('aria-disabled', 'false');

  await keyArea(page, 'holder').getByRole('button', { name: NAMES.clear }).click();
  await expect(present).toHaveAttribute('aria-disabled', 'true');
  await expect(present).toHaveAttribute('title', /holder key/i);

  await page.getByRole('tablist', { name: 'Credentials' }).getByRole('tab').first().click();
  await keyArea(page, 'issuer').getByRole('button', { name: NAMES.clear }).click();
  await expect(actions(page).getByRole('button', { name: 'Issue' })).toHaveAttribute(
    'aria-disabled',
    'true',
  );
});
