// Writing a credential from scratch (#43 under SPEC §4.1), through the real
// WasmEngine: type into the empty tab with the Type picker's type, set the
// type explicitly with "Detected as…", and use the actions of that type.
import { expect, test, type Page } from '@playwright/test';
import { NAMES, activePanel, actions, createKey, paste, tabBox, validate } from './helpers';

/** Replaces the active tab's text by typing (never a paste). */
async function write(page: Page, text: string): Promise<void> {
  await tabBox(page).click();
  await page.keyboard.press('ControlOrMeta+A');
  await page.keyboard.insertText(text);
}

async function pickType(page: Page, label: 'JSON claims' | 'EDN claims'): Promise<void> {
  await activePanel(page).getByRole('combobox', { name: NAMES.type }).selectOption({ label });
}

async function setType(page: Page, label: string): Promise<void> {
  await page.getByRole('button', { name: /detected as/i }).click();
  // Exact label, optionally marked "(detected)".
  await page
    .getByRole('menuitemradio', { name: new RegExp(`^${label}( \\(detected\\))?$`) })
    .click();
  await expect(page.getByTestId('detected-type')).toHaveText(label);
}

test.beforeEach(async ({ page }) => {
  await page.goto('/');
});

test('a typed JSON claim set is issued as a JWT and validates', async ({ page }) => {
  await createKey(page, 'EC P-256', 'issuer');
  await write(page, '{"iss": "https://issuer.example", "sub": "user-42", "exp": 4102444800}');
  await expect(page.getByTestId('detected-type')).toHaveText('JSON claim set');
  await actions(page).getByRole('button', { name: 'Issue' }).click();
  await page.getByRole('dialog', { name: 'Issue' }).getByRole('button', { name: 'Issue' }).click();
  await expect(page.getByTestId('detected-type')).toHaveText('JWT');
  await validate(page);
  await expect(page.getByTestId('report-overall')).toHaveText(/pass/i);
});

test('a typed EDN claim set is issued as a CWT', async ({ page }) => {
  await createKey(page, 'EC P-256', 'issuer');
  await pickType(page, 'EDN claims');
  await write(page, '{1: "https://issuer.example", 2: "user-42", 4: 4102444800}');
  await expect(page.getByTestId('detected-type')).toHaveText('EDN claim set');
  await actions(page).getByRole('button', { name: 'Issue' }).click();
  await page.getByRole('dialog', { name: 'Issue' }).getByRole('button', { name: 'Issue' }).click();
  await expect(page.getByTestId('detected-type')).toHaveText('CWT');
  await validate(page);
});

const SIGN1 = `18([<< {1: -7} >>, {}, << {1: "issuer", 4: 4102444800} >>, h'00'])`;

test('a typed EDN COSE_Sign1 set to CWT explicitly stays a CWT across edits', async ({ page }) => {
  await pickType(page, 'EDN claims');
  await write(page, SIGN1);
  await setType(page, 'CWT');
  await expect(page.getByRole('status')).toHaveCount(0); // never "signature stale"
  await write(page, SIGN1.replace('"issuer"', '"another issuer"'));
  await expect(page.getByTestId('detected-type')).toHaveText('CWT');
  const report = await validate(page);
  await expect(report.locator('[data-status]').first()).not.toHaveAttribute('data-status', 'pass');
});

test('an EDN COSE_Sign1 pasted into an empty tab is detected as a CWT', async ({ page }) => {
  await paste(page, SIGN1);
  await expect(page.getByTestId('detected-type')).toHaveText('CWT');
});

test('typing never re-detects: a typed JWK stays a JSON claim set', async ({ page }) => {
  await write(
    page,
    '{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}',
  );
  await expect(page.getByTestId('detected-type')).toHaveText('JSON claim set');
  await expect(page.getByRole('button', { name: 'Add to key panel' })).toHaveCount(0);
});
