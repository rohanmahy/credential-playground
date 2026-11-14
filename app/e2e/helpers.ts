// Shared helpers for the e2e specs. They run against `vite preview` of the
// production build with the real WASM engine (playwright.config.ts).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, type BrowserContext, type Locator, type Page } from '@playwright/test';
import { ORIGIN } from '../playwright.config';

const testdata = join(import.meta.dirname, '../../testdata');

export function fixtureText(path: string): string {
  return readFileSync(join(testdata, path), 'utf8').trim();
}

/** Binary fixtures are pasted as hex, which detection unwraps. */
export function fixtureHex(path: string): string {
  return readFileSync(join(testdata, path)).toString('hex');
}

// ---------------------------------------------------------------- UI names
// The accessible names these specs assume (src/test/ui.ts has the same for
// the component tests; SPEC §3, §4, §4.1, §4.2):
//   header     no global input box; nav "Tools": Date/time, Settings, About
//   key panel  region + textbox "Issuer key" / "Holder key"; per area the
//              buttons Create, Import, Fetch from URL, Clear, Export, Make
//              public, Auto kid; radiogroup "Key format" with radios JWK and
//              COSE_Key; key errors in role=alert inside the area
//   chooser    dialog "Choose a key", one button per key (kid, alg, kty)
//   tabs       tablist "Credentials", button "New tab" (the +); per tab
//              panel a textbox "Credential text" and a button "Clear"; an
//              empty tab also has a combobox "Type" (JSON claims, EDN
//              claims, …) and the buttons "Open file…" and "From clipboard"
//   Issue      dialog "Issue": checkbox "Holder key (cnf)", no key picker
//   Present    dialog "Present": no key picker (the Holder area's key)
export const NAMES = {
  areas: { issuer: 'Issuer key', holder: 'Holder key' },
  keyFormat: 'Key format',
  jwk: 'JWK',
  coseKey: 'COSE_Key',
  chooser: 'Choose a key',
  notAKey: 'Not a recognized key',
  newTab: 'New tab',
  credentialText: 'Credential text',
  type: 'Type',
  clear: 'Clear',
  openFile: 'Open file…',
  fromClipboard: 'From clipboard',
  cnf: 'Holder key (cnf)',
} as const;

export type AreaRole = 'issuer' | 'holder';

export function keyArea(page: Page, role: AreaRole): Locator {
  return page.getByRole('region', { name: NAMES.areas[role], exact: true });
}

export function keyBox(page: Page, role: AreaRole): Locator {
  return keyArea(page, role).getByRole('textbox', { name: NAMES.areas[role], exact: true });
}

export function keyFormat(page: Page, role: AreaRole, format: 'JWK' | 'COSE_Key'): Locator {
  return keyArea(page, role)
    .getByRole('radiogroup', { name: NAMES.keyFormat })
    .getByRole('radio', { name: format, exact: true });
}

/** The active tab's panel. */
export function activePanel(page: Page): Locator {
  return page.locator('[role="tabpanel"]:visible').first();
}

export function tabBox(page: Page): Locator {
  return activePanel(page).getByRole('textbox', { name: NAMES.credentialText });
}

export function tabs(page: Page): Locator {
  return page.getByRole('tablist', { name: 'Credentials' }).getByRole('tab');
}

/** The main pane: the read-only tree, or the Live edit editor. */
export function mainPane(page: Page): Locator {
  return page.getByRole('tree', { name: 'Main pane' }).or(page.getByTestId('live-editor'));
}

/** A textarea's value, or the text of a CodeMirror editor's lines. */
export async function textOf(field: Locator): Promise<string> {
  return field.evaluate((el) => {
    if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) return el.value;
    const lines = el.querySelectorAll('.cm-line');
    return lines.length > 0
      ? [...lines].map((l) => l.textContent ?? '').join('\n')
      : (el.textContent ?? '');
  });
}

/**
 * A paste as far as the page can tell: a `paste` event carrying text/plain
 * on the text area. If the app lets it through, the text is inserted as the
 * browser would (CodeMirror handles the event itself).
 */
export async function pasteInto(target: Locator, text: string): Promise<void> {
  await target.click();
  await target.evaluate((el, value) => {
    const data = new DataTransfer();
    data.setData('text/plain', value);
    const ev = new ClipboardEvent('paste', {
      clipboardData: data,
      bubbles: true,
      cancelable: true,
    });
    if (!el.dispatchEvent(ev)) return;
    if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) {
      el.setRangeText(value, el.selectionStart ?? 0, el.selectionEnd ?? 0, 'end');
      el.dispatchEvent(
        new InputEvent('input', { bubbles: true, inputType: 'insertFromPaste', data: value }),
      );
    } else {
      document.execCommand('insertText', false, value);
    }
  }, text);
}

/** Pastes into the active tab, which must be empty (runs token detection). */
export async function paste(page: Page, text: string): Promise<void> {
  const box = tabBox(page);
  await expect(box).toBeVisible();
  await pasteInto(box, text);
  await expect(activePanel(page).getByTestId('detected-type')).toBeVisible();
}

/** Opens a new empty tab with "+" and pastes into it. */
export async function pasteInNewTab(page: Page, text: string): Promise<void> {
  await page.getByRole('button', { name: NAMES.newTab }).click();
  await paste(page, text);
}

/** Switches the active tab to Read-only (the tree view) if it is in Live edit. */
export async function readOnly(page: Page): Promise<void> {
  const live = activePanel(page).getByRole('switch', { name: 'Live edit' });
  if ((await live.getAttribute('aria-checked')) === 'true') await live.click();
  await expect(live).toHaveAttribute('aria-checked', 'false');
  await expect(page.getByRole('tree', { name: 'Main pane' })).toBeVisible();
}

export function actions(page: Page) {
  return page.getByRole('toolbar', { name: 'Actions' });
}

export async function validate(page: Page) {
  await actions(page).getByRole('button', { name: 'Validate' }).click();
  const report = page.getByRole('list', { name: 'Validation report' });
  await expect(report).toBeVisible();
  return report;
}

/** The area's Create → algorithm, well-known test seed → Create. */
export async function createKey(page: Page, algorithm: string, role: AreaRole): Promise<void> {
  await keyArea(page, role).getByRole('button', { name: 'Create', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Create key' });
  await dialog.getByRole('combobox', { name: 'Algorithm' }).selectOption({ label: algorithm });
  await dialog.getByRole('radio', { name: /well-known test seed/i }).check();
  await dialog.getByRole('button', { name: 'Create' }).click();
  await expect(dialog).toBeHidden();
  await expect.poll(() => textOf(keyBox(page, role))).not.toBe('');
}

/** The area's Import → paste into the dialog → Import. */
export async function importKey(page: Page, text: string, role: AreaRole): Promise<void> {
  await keyArea(page, role).getByRole('button', { name: 'Import', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Import key' });
  await dialog.getByRole('textbox', { name: 'Key' }).fill(text);
  await dialog.getByRole('button', { name: 'Import' }).click();
  await expect(dialog).toBeHidden();
}

/** Pastes a key into an empty key area (runs key detection). */
export async function pasteKey(page: Page, role: AreaRole, text: string): Promise<void> {
  await pasteInto(keyBox(page, role), text);
}

/**
 * Records every request the page makes. Requests to any origin other than
 * the app's own are aborted (and recorded), so nothing leaves the machine
 * even if the app misbehaves. A test that fulfils some URL itself (the
 * IANA registries) registers its own route afterwards, which takes
 * precedence.
 */
export async function guardNetwork(context: BrowserContext): Promise<{
  all: string[];
  foreign: string[];
}> {
  const log = { all: [] as string[], foreign: [] as string[] };
  await context.route('**/*', async (route) => {
    const url = route.request().url();
    log.all.push(url);
    if (new URL(url).origin === ORIGIN) return route.continue();
    log.foreign.push(url);
    return route.abort('blockedbyclient');
  });
  return log;
}

/** Collects `securitypolicyviolation` events from page load on. */
export async function watchCsp(page: Page): Promise<() => Promise<string[]>> {
  await page.addInitScript(() => {
    const seen: string[] = [];
    (window as unknown as { __csp: string[] }).__csp = seen;
    document.addEventListener('securitypolicyviolation', (e) =>
      seen.push(`${e.effectiveDirective} ${e.blockedURI}`),
    );
  });
  return () => page.evaluate(() => (window as unknown as { __csp: string[] }).__csp);
}
