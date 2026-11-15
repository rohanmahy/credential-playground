// Per-area input on the credential side (SPEC §3, §4, §4.1) through the real
// WasmEngine: no global input box; one empty tab at startup; paste into an
// empty tab detects and decodes, but later pastes and edits never
// re-detect; Clear; "+"; drops only on an empty text area.
import { expect, test, type Locator, type Page } from '@playwright/test';
import {
  NAMES,
  activePanel,
  createKey,
  fixtureText,
  keyArea,
  keyBox,
  paste,
  pasteInto,
  readOnly,
  tabBox,
  tabs,
  textOf,
} from './helpers';

const JWT = () => fixtureText('tokens/rfc7515-a3-jws-es256.txt');
const SD_JWT = () => fixtureText('tokens/rfc9901-s5.1-sd-jwt.txt');
const SD_JWT_KB = () => fixtureText('tokens/rfc9901-s5.2-sd-jwt-kb.txt');

test.beforeEach(async ({ page }) => {
  await page.goto('/');
});

interface DragOutcome {
  /** dragover was prevented (by the area, or by the window guard). */
  prevented: boolean;
  /** dataTransfer.dropEffect after dragover. Chromium does not let script
   *  set it on a synthetic DataTransfer (it reads back "none"), so
   *  acceptance is judged by `prevented` plus the outcome (the tab detects). */
  dropEffect: string;
}

/** Fires dragover + drop with a DataTransfer holding `text`. */
async function drop(page: Page, target: Locator, text: string): Promise<DragOutcome> {
  const data = await page.evaluateHandle((t) => {
    const dt = new DataTransfer();
    dt.setData('text/plain', t);
    return dt;
  }, text);
  const outcome = await target.evaluate((el, dt) => {
    const over = new DragEvent('dragover', { dataTransfer: dt, bubbles: true, cancelable: true });
    el.dispatchEvent(over);
    return { prevented: over.defaultPrevented, dropEffect: dt.dropEffect };
  }, data);
  await target.dispatchEvent('drop', { dataTransfer: data });
  return outcome;
}

/** Picks an empty tab's Type (failing fast if the option is missing). */
async function pickType(page: Page, label: string): Promise<void> {
  const type = activePanel(page).getByRole('combobox', { name: NAMES.type });
  await expect(type.getByRole('option', { name: label, exact: true })).toHaveCount(1);
  await type.selectOption({ label });
}

/** Refused: dragover not prevented, or prevented with dropEffect "none". */
const refused = (o: DragOutcome) => !o.prevented || o.dropEffect === 'none';

test('the shell: no global input, one empty tab with a type picker and input buttons', async ({
  page,
}) => {
  await expect(page.getByRole('textbox', { name: /paste a credential or key/i })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Open', exact: true })).toHaveCount(0);
  const tools = page.getByRole('navigation', { name: 'Tools' });
  for (const name of ['Date/time', 'Settings', 'About']) {
    await expect(tools.getByRole('button', { name })).toBeVisible();
  }
  await expect(tabs(page)).toHaveCount(1);
  const panel = activePanel(page);
  await expect(tabBox(page)).toBeVisible();
  expect(await textOf(tabBox(page))).toBe('');
  await expect(panel.getByRole('combobox', { name: NAMES.type })).toBeVisible();
  await expect(panel.getByRole('button', { name: NAMES.openFile })).toBeVisible();
  await expect(panel.getByRole('button', { name: NAMES.fromClipboard })).toBeVisible();
  await expect(page.getByRole('menubar')).toHaveCount(0);
});

test('paste a token into the startup tab: decoded, in Live edit, in the same tab', async ({
  page,
}) => {
  await paste(page, JWT());
  await expect(page.getByTestId('detected-type')).toHaveText('JWT');
  await expect(page.getByRole('tree', { name: 'Raw pane' })).toBeVisible();
  await expect(activePanel(page).getByRole('switch', { name: 'Live edit' })).toHaveAttribute(
    'aria-checked',
    'true',
  );
  await expect(page.getByTestId('live-editor')).toContainText('"alg":"ES256"');
  await expect(tabs(page)).toHaveCount(1);
  await expect(tabs(page).first()).toContainText('JWT');
  await expect(page.getByRole('navigation', { name: 'Provenance' })).toContainText('Pasted');
});

for (const [name, input, kind, disclosed] of [
  ['SD-JWT (RFC 9901 §5.1)', SD_JWT, 'SD-JWT', 'given_name'],
  ['SD-JWT+KB (RFC 9901 §5.2)', SD_JWT_KB, 'SD-JWT+KB', 'given_name'],
] as const) {
  test(`paste a compact ${name} into the startup tab: the SD-JWT view, in Live edit`, async ({
    page,
  }) => {
    await paste(page, input());
    await expect(page.getByTestId('detected-type')).toHaveText(kind);
    await expect(activePanel(page).getByRole('switch', { name: 'Live edit' })).toHaveAttribute(
      'aria-checked',
      'true',
    );
    await expect(page.getByRole('table', { name: 'Disclosures' })).toContainText(disclosed);
    await expect(tabs(page)).toHaveCount(1);
    await expect(tabs(page).first()).toContainText(kind);
  });
}

test('paste a line-wrapped compact SD-JWT (as RFC 9901 prints it): still detected', async ({
  page,
}) => {
  // Long compact tokens are usually copied with line breaks in them.
  const wrapped =
    SD_JWT()
      .match(/.{1,72}/g)
      ?.join('\n') ?? '';
  await paste(page, wrapped);
  await expect(page.getByTestId('detected-type')).toHaveText('SD-JWT');
  await expect(page.getByRole('table', { name: 'Disclosures' })).toContainText('given_name');
});

test('Type "JWT": a typed compact JWT decodes as a JWT, without detection', async ({ page }) => {
  await pickType(page, 'JWT');
  await tabBox(page).click();
  await page.keyboard.insertText(JWT());
  await expect(page.getByTestId('detected-type')).toHaveText('JWT');
  await expect(tabs(page).first()).toContainText('JWT');
  await readOnly(page);
  await expect(page.getByRole('tree', { name: 'Main pane' })).toContainText('"alg":"ES256"');
  await expect(page.getByRole('tree', { name: 'Raw pane' })).toBeVisible();
});

test('Type "SD-JWT": a typed compact SD-JWT decodes with its disclosures', async ({ page }) => {
  await pickType(page, 'SD-JWT');
  await tabBox(page).click();
  await page.keyboard.insertText(SD_JWT());
  await expect(page.getByTestId('detected-type')).toHaveText('SD-JWT');
  await expect(page.getByRole('table', { name: 'Disclosures' })).toContainText('given_name');
  await expect(tabs(page).first()).toContainText('SD-JWT');
});

test('Type "SD-JWT": a compact SD-JWT pasted into the typed tab parses as SD-JWT', async ({
  page,
}) => {
  await pickType(page, 'SD-JWT');
  await tabBox(page).click();
  // the typed space makes the tab non-empty: the paste is an edit, not a first fill
  await page.keyboard.insertText(' ');
  await pasteInto(tabBox(page), SD_JWT());
  await expect(page.getByTestId('detected-type')).toHaveText('SD-JWT');
  await expect(page.getByRole('table', { name: 'Disclosures' })).toContainText('given_name');
});

test('a paste into a non-empty tab never re-runs detection', async ({ page }) => {
  await paste(page, '{"iss": "https://issuer.example", "sub": "alice"}');
  await expect(page.getByTestId('detected-type')).toHaveText('JSON claim set');
  // a whole token pasted into the claim set's text does not turn it into a JWT
  await pasteInto(tabBox(page), JWT());
  await page.waitForTimeout(500);
  await expect(page.getByTestId('detected-type')).toHaveText('JSON claim set');
  await expect(tabs(page)).toHaveCount(1);
});

test('typing into an empty tab uses the type picker, not detection', async ({ page }) => {
  await pickType(page, 'EDN claims');
  await tabBox(page).click();
  await page.keyboard.insertText('{1: "https://issuer.example"}');
  await expect(page.getByTestId('detected-type')).toHaveText('EDN claim set');
});

test('ambiguous JSON can be read as EDN through "Detected as…"', async ({ page }) => {
  await paste(page, '{"1": "x"}');
  await expect(page.getByTestId('detected-type')).toHaveText('JSON claim set');
  await page.getByRole('button', { name: /detected as/i }).click();
  await page.getByRole('menuitemradio', { name: /^EDN claim set/ }).click();
  await expect(page.getByTestId('detected-type')).toHaveText('EDN claim set');
});

test('Clear resets the tab to empty and keeps the keys; the next paste detects again', async ({
  page,
}) => {
  await createKey(page, 'EC P-256', 'issuer');
  const key = await textOf(keyBox(page, 'issuer'));
  await paste(page, JWT());
  await expect(page.getByTestId('detected-type')).toHaveText('JWT');
  await activePanel(page).getByRole('button', { name: NAMES.clear }).click();
  await expect.poll(() => textOf(tabBox(page))).toBe('');
  await expect(page.getByTestId('detected-type')).toHaveCount(0);
  await expect(activePanel(page).getByRole('combobox', { name: NAMES.type })).toBeVisible();
  await expect(tabs(page).first()).not.toContainText('JWT');
  expect(await textOf(keyBox(page, 'issuer'))).toBe(key);
  await expect(keyArea(page, 'issuer')).toContainText('EC P-256');

  await paste(page, fixtureText('tokens/rfc8392-a3-signed-cwt.hex'));
  await expect(page.getByTestId('detected-type')).toHaveText('CWT');
});

test('"+" opens another empty tab', async ({ page }) => {
  await paste(page, JWT());
  await page.getByRole('button', { name: NAMES.newTab }).click();
  await expect(tabs(page)).toHaveCount(2);
  await expect(tabs(page).nth(1)).toHaveAttribute('aria-selected', 'true');
  expect(await textOf(tabBox(page))).toBe('');
  await paste(page, fixtureText('tokens/rfc8392-a3-signed-cwt.hex'));
  await expect(page.getByTestId('detected-type')).toHaveText('CWT');
  await tabs(page).first().click();
  await expect(page.getByTestId('detected-type')).toHaveText('JWT');
});

test('a drop is accepted on an empty tab only; elsewhere it is ignored', async ({ page }) => {
  // elsewhere in the window: refused (the window guard may prevent dragover
  // with dropEffect "none" so a file cannot navigate the page) and ignored
  expect(refused(await drop(page, page.getByRole('navigation', { name: 'Tools' }), JWT()))).toBe(
    true,
  );
  await page.waitForTimeout(300);
  expect(await textOf(tabBox(page))).toBe('');
  await expect(page.getByTestId('detected-type')).toHaveCount(0);

  // the empty tab: dragover prevented, and the drop is detected
  expect((await drop(page, tabBox(page), JWT())).prevented).toBe(true);
  await expect(page.getByTestId('detected-type')).toHaveText('JWT');

  // now non-empty: refused and ignored
  expect(
    refused(await drop(page, tabBox(page), fixtureText('tokens/rfc8392-a3-signed-cwt.hex'))),
  ).toBe(true);
  await page.waitForTimeout(300);
  await expect(page.getByTestId('detected-type')).toHaveText('JWT');
  await expect(tabs(page)).toHaveCount(1);
});
