// New drafts and explicit type (#43), through the real WasmEngine: start
// from nothing in Live edit, pick JSON or EDN, let the type be detected or
// set it, and use the actions of that type.
import { expect, test, type Page } from '@playwright/test';
import { actions, createKey, validate } from './helpers';

/** Replaces the draft's text, as typing would. */
async function write(page: Page, text: string): Promise<void> {
  const content = page.getByTestId('live-editor').locator('.cm-content');
  await content.click();
  await page.keyboard.press('ControlOrMeta+A');
  await page.keyboard.insertText(text);
}

async function editorText(page: Page): Promise<string> {
  return page
    .getByTestId('live-editor')
    .locator('.cm-line')
    .evaluateAll((lines) => lines.map((l) => l.textContent ?? '').join('\n'));
}

async function newDraft(page: Page, format: 'JSON' | 'EDN'): Promise<void> {
  await page.getByRole('button', { name: `New ${format} draft` }).click();
  await expect(page.getByRole('switch', { name: 'Live edit' })).toHaveAttribute(
    'aria-checked',
    'true',
  );
  await expect(page.getByRole('combobox', { name: 'Format' })).toHaveValue(format.toLowerCase());
  await expect(page.getByRole('navigation', { name: 'Provenance' })).toContainText('New');
}

async function setType(page: Page, label: string): Promise<void> {
  await page.getByRole('button', { name: /detected as/i }).click();
  await page.getByRole('menuitemradio', { name: new RegExp(`^${label}`) }).click();
  await expect(page.getByTestId('detected-type')).toHaveText(label);
}

test.beforeEach(async ({ page }) => {
  await page.goto('/');
});

test('New from the toolbar opens a JSON draft with the template', async ({ page }) => {
  await page.getByRole('button', { name: 'New', exact: true }).click();
  await expect(page.getByRole('combobox', { name: 'Format' })).toHaveValue('json');
  expect(await editorText(page)).toBe('{}');
  await expect(page.getByTestId('detected-type')).toHaveText('JSON claim set');
});

test('a JSON claim-set draft is issued as a JWT and validates', async ({ page }) => {
  await createKey(page, 'EC P-256', 'issuer');
  await newDraft(page, 'JSON');
  await write(page, '{"iss": "https://issuer.example", "sub": "user-42", "exp": 4102444800}');
  await expect(page.getByTestId('detected-type')).toHaveText('JSON claim set');
  await actions(page).getByRole('button', { name: 'Issue' }).click();
  await page.getByRole('dialog', { name: 'Issue' }).getByRole('button', { name: 'Issue' }).click();
  await expect(page.getByTestId('detected-type')).toHaveText('JWT');
  await validate(page);
  await expect(page.getByTestId('report-overall')).toHaveText(/pass/i);
});

test('an EDN claim-set draft is issued as a CWT', async ({ page }) => {
  await createKey(page, 'EC P-256', 'issuer');
  await newDraft(page, 'EDN');
  await write(page, '{1: "https://issuer.example", 2: "user-42", 4: 4102444800}');
  await expect(page.getByTestId('detected-type')).toHaveText('EDN claim set');
  await actions(page).getByRole('button', { name: 'Issue' }).click();
  await page.getByRole('dialog', { name: 'Issue' }).getByRole('button', { name: 'Issue' }).click();
  await expect(page.getByTestId('detected-type')).toHaveText('CWT');
  await validate(page);
});

const SIGN1 = `18([<< {1: -7} >>, {}, << {1: "issuer", 4: 4102444800} >>, h'00'])`;

test('an EDN COSE_Sign1 draft can be set to CWT explicitly, and stays a CWT across edits', async ({
  page,
}) => {
  await newDraft(page, 'EDN');
  await write(page, SIGN1);
  await setType(page, 'CWT');
  await expect(page.getByRole('status')).toHaveCount(0); // a draft is never "signature stale"
  await write(page, SIGN1.replace('"issuer"', '"another issuer"'));
  await expect(page.getByTestId('detected-type')).toHaveText('CWT');
  const report = await validate(page);
  await expect(report.locator('[data-status]').first()).not.toHaveAttribute('data-status', 'pass');
});

test('an EDN COSE_Sign1 draft is detected as a CWT (needs core: EDN detection)', async ({
  page,
}) => {
  await newDraft(page, 'EDN');
  await write(page, SIGN1);
  await expect(page.getByTestId('detected-type')).toHaveText('CWT');
});

test('a COSE_Key draft goes to the key panel', async ({ page }) => {
  await newDraft(page, 'EDN');
  await write(
    page,
    "{1: 2, -1: 1, -2: h'58a9fe64819ebdcc06232cabcc5a1934175aabdfd3b2acc697dea8734096ba2b', -3: h'cbbeedf91bc01d1293b1219d21851fc1eb8ebf0aef0c3f90dc7bf92747d229b1'}",
  );
  await setType(page, 'COSE_Key');
  await page.getByRole('button', { name: 'Add to key panel' }).click();
  const card = page.getByRole('complementary', { name: 'Keys' }).getByRole('article').first();
  await expect(card).toContainText('EC P-256');
  await expect(card).toContainText('New');
});

test('a JWK draft is detected and goes to the key panel', async ({ page }) => {
  await newDraft(page, 'JSON');
  await write(
    page,
    '{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}',
  );
  await expect(page.getByTestId('detected-type')).toHaveText('JWK');
  await page.getByRole('button', { name: 'Add to key panel' }).click();
  await expect(page.getByRole('complementary', { name: 'Keys' }).getByRole('article')).toHaveCount(
    1,
  );
});

test('switching Format JSON → EDN converts the claim set (needs core: convert_claims)', async ({
  page,
}) => {
  await newDraft(page, 'JSON');
  await write(page, '{"iss": "https://issuer.example", "exp": 4102444800}');
  await page.getByRole('combobox', { name: 'Format' }).selectOption('edn');
  await expect(page.getByRole('alertdialog')).toHaveCount(0);
  await expect.poll(() => editorText(page)).toContain('"https://issuer.example"');
  expect(await editorText(page)).toMatch(/\b1\s*:/); // iss → CWT label 1
  await expect(page.getByTestId('detected-type')).toHaveText('EDN claim set');
});

test('switching Format EDN → JSON with a byte string asks before discarding', async ({ page }) => {
  await newDraft(page, 'EDN');
  await write(page, "{1: h'00'}");
  await page.getByRole('combobox', { name: 'Format' }).selectOption('json');
  const ask = page.getByRole('alertdialog');
  await expect(ask).toBeVisible();
  await ask.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByRole('combobox', { name: 'Format' })).toHaveValue('edn');
  expect(await editorText(page)).toBe("{1: h'00'}");
});
