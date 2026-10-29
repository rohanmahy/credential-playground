// Locators and assertions for the desktop specs, by ARIA role and
// accessible name as in the UI contract (app/TEST-PLAN.md), so the specs
// read like the Playwright web specs (app/e2e) they mirror.
//
// WebDriver has no role locator, so a locator is a chain of steps that one
// injected script resolves in the page per attempt, and assertions retry
// until they hold. The script is plain JS text: functions passed to
// `browser.execute` would carry the TS transpiler's helpers into the page.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { $, browser } from '@wdio/globals';

const testdata = join(import.meta.dirname, '../../testdata');

export function fixtureText(path: string): string {
  return readFileSync(join(testdata, path), 'utf8').trim();
}

/** Binary fixtures are pasted as hex, which detection unwraps. */
export function fixtureHex(path: string): string {
  return readFileSync(join(testdata, path)).toString('hex');
}

type Name = string | RegExp;
type WireName = string | { re: string; flags: string };
type Step =
  { role: string; name?: WireName } | { css: string } | { nth: number } | { hasText: string };

interface Described {
  text: string;
  attrs: Record<string, string | null>;
  value: string | null;
  checked: boolean | null;
}

// Resolves `steps` from the document: arguments[0] = steps, arguments[1] =
// 'elements' (returns them) or a list of attribute names (returns their
// text, those attributes, value, and checked state).
const RESOLVE = String.raw`
const [steps, op] = arguments;
const ROLES = {
  button: 'button,[role=button]',
  textbox: 'textarea,input:not([type]),input[type=text],input[type=url],input[type=search],[role=textbox]',
  combobox: 'select,[role=combobox]',
  checkbox: 'input[type=checkbox],[role=checkbox]',
  radio: 'input[type=radio],[role=radio]',
  list: 'ul,ol,[role=list]',
  listitem: 'li,[role=listitem]',
  table: 'table,[role=table]',
  navigation: 'nav,[role=navigation]',
  complementary: 'aside,[role=complementary]',
  region: 'section[aria-label],section[aria-labelledby],[role=region]',
  article: 'article,[role=article]',
};
const norm = (s) => (s || '').replace(/\s+/g, ' ').trim();
const text = (el) => norm(el.textContent);
const hidden = (el) =>
  el.getClientRects().length === 0 ||
  getComputedStyle(el).visibility === 'hidden' ||
  !!el.closest('[aria-hidden="true"],[inert]');
const name = (el) => {
  const by = el.getAttribute('aria-labelledby');
  if (by) return norm(by.split(/\s+/).map((id) => { const t = document.getElementById(id); return t ? t.textContent : ''; }).join(' '));
  const label = el.getAttribute('aria-label');
  if (label) return norm(label);
  if (el.matches('input,select,textarea')) {
    const lab = (el.id && document.querySelector('label[for="' + CSS.escape(el.id) + '"]')) || el.closest('label');
    if (lab) {
      const copy = lab.cloneNode(true);
      copy.querySelectorAll('input,select,textarea').forEach((n) => n.remove());
      return text(copy);
    }
    return norm(el.getAttribute('title') || el.getAttribute('placeholder'));
  }
  if (el.matches('button,a,[role=button],[role=tab],[role=switch],[role^=menuitem],[role=treeitem],[role=option]')) {
    return text(el) || norm(el.getAttribute('title'));
  }
  return norm(el.getAttribute('title'));
};
const matches = (want, got) =>
  want === undefined || (typeof want === 'string' ? got === want : new RegExp(want.re, want.flags).test(got));
let found = [document.documentElement];
for (const step of steps) {
  if ('nth' in step) {
    const el = found.at(step.nth);
    found = el ? [el] : [];
  } else if ('hasText' in step) {
    found = found.filter((el) => text(el).includes(step.hasText));
  } else {
    const css = 'css' in step ? step.css : (ROLES[step.role] || '[role="' + step.role + '"]');
    const next = [];
    for (const root of found) {
      for (const el of root.querySelectorAll(css)) {
        if (next.includes(el)) continue;
        if ('role' in step) {
          const explicit = el.getAttribute('role');
          if (explicit && explicit !== step.role) continue;
          if (hidden(el) || !matches(step.name, name(el))) continue;
        }
        next.push(el);
      }
    }
    found = next;
  }
}
if (op === 'elements') return found;
return found.map((el) => ({
  text: text(el),
  attrs: Object.fromEntries(op.map((a) => [a, el.getAttribute(a)])),
  value: 'value' in el ? String(el.value) : null,
  checked: 'checked' in el ? !!el.checked : null,
}));
`;

// Sets a text field's value as a paste does: one `input` event, no keystrokes
// (typing a few kB of token into WebKitGTK one key at a time is slow).
const PASTE = String.raw`
const [el, value] = arguments;
el.focus();
const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, value);
el.dispatchEvent(new Event('input', { bubbles: true }));
el.dispatchEvent(new Event('change', { bubbles: true }));
`;

// Selects the first occurrence of arguments[1] inside arguments[0] (a
// contenteditable, e.g. CodeMirror's content) with the DOM selection, so
// the next keystrokes replace it.
const SELECT_TEXT = String.raw`
const [root, needle] = arguments;
root.focus();
const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
for (let node = walker.nextNode(); node; node = walker.nextNode()) {
  const at = node.data.indexOf(needle);
  if (at < 0) continue;
  const range = document.createRange();
  range.setStart(node, at);
  range.setEnd(node, at + needle.length);
  const sel = getSelection();
  sel.removeAllRanges();
  sel.addRange(range);
  return true;
}
return false;
`;

function wire(name: Name | undefined): WireName | undefined {
  return name instanceof RegExp ? { re: name.source, flags: name.flags } : name;
}

const TIMEOUT = 15_000;

/** Retries `check` until it returns true; fails with `describe()` of the last state. */
export async function eventually(
  what: string,
  check: () => Promise<boolean>,
  describe: () => Promise<string> = async () => '',
  timeout = TIMEOUT,
): Promise<void> {
  const deadline = Date.now() + timeout;
  let error: unknown;
  for (;;) {
    try {
      if (await check()) return;
      error = undefined;
    } catch (e) {
      error = e;
    }
    if (Date.now() > deadline) break;
    await browser.pause(100);
  }
  const last = await describe().catch(() => '');
  throw new Error(
    `timed out: ${what}${last ? `; last: ${last}` : ''}${error ? ` (${String(error)})` : ''}`,
  );
}

export class Locator {
  constructor(
    private readonly steps: Step[],
    private readonly label: string,
  ) {}

  private add(step: Step, label: string): Locator {
    return new Locator([...this.steps, step], `${this.label} > ${label}`);
  }

  getByRole(role: string, name?: Name): Locator {
    const w = wire(name);
    return this.add(
      w === undefined ? { role } : { role, name: w },
      `${role}${name ? ` "${String(name)}"` : ''}`,
    );
  }
  locator(css: string): Locator {
    return this.add({ css }, css);
  }
  getByTestId(id: string): Locator {
    return this.locator(`[data-testid="${id}"]`);
  }
  nth(i: number): Locator {
    return this.add({ nth: i }, `nth(${i})`);
  }
  first(): Locator {
    return this.nth(0);
  }
  last(): Locator {
    return this.nth(-1);
  }
  withText(text: string): Locator {
    return this.add({ hasText: text }, `hasText("${text}")`);
  }

  toString(): string {
    return this.label;
  }

  async describe(attrs: string[] = []): Promise<Described[]> {
    return (await browser.execute(RESOLVE, this.steps, attrs)) as Described[];
  }

  /** The single matching element, once there is exactly one. */
  async element(): Promise<WebdriverIO.Element> {
    let el: WebdriverIO.Element | undefined;
    let count = 0;
    await eventually(
      `exactly one ${this.label}`,
      async () => {
        const found = (await browser.execute(RESOLVE, this.steps, 'elements')) as unknown[];
        count = found.length;
        if (count !== 1) return false;
        el = await $(found[0] as WebdriverIO.Element);
        return true;
      },
      async () => `${count} found`,
    );
    return el as WebdriverIO.Element;
  }

  async click(): Promise<void> {
    await (await this.element()).click();
  }
  async rightClick(): Promise<void> {
    await (await this.element()).click({ button: 'right' });
  }
  /** Pastes `text` into a text field (see PASTE). */
  async fill(text: string): Promise<void> {
    await browser.execute(PASTE, await this.element(), text);
  }
  /** Replaces a text field's value by typing. */
  async type(text: string): Promise<void> {
    const el = await this.element();
    await el.clearValue();
    await el.addValue(text);
  }
  /**
   * Types `text` into the focused part of this element, e.g. over a
   * selection. Element Send Keys, not `browser.keys()`: WebKitWebDriver
   * drops the second of two equal keys in an action sequence ("ll" → "l").
   */
  async keys(text: string): Promise<void> {
    await (await this.element()).addValue(text);
  }
  async selectOption(label: string): Promise<void> {
    await (await this.element()).selectByVisibleText(label);
  }
  async check(): Promise<void> {
    const el = await this.element();
    if (!(await el.isSelected())) await el.click();
  }
  /** Selects `text` inside this contenteditable; the next keys replace it. */
  async selectText(text: string): Promise<void> {
    const ok = await browser.execute(SELECT_TEXT, await this.element(), text);
    if (!ok) throw new Error(`"${text}" not found in ${this.label}`);
  }
  async text(): Promise<string> {
    const [d] = await this.describe();
    if (!d) throw new Error(`no ${this.label}`);
    return d.text;
  }
  async attr(name: string): Promise<string | null> {
    const [d] = await this.describe([name]);
    if (!d) throw new Error(`no ${this.label}`);
    return d.attrs[name] ?? null;
  }
}

export const page = new Locator([], 'page');

function show(text: string): string {
  return JSON.stringify(text.length > 200 ? `${text.slice(0, 200)}…` : text);
}

function test(want: Name, got: string): boolean {
  return typeof want === 'string' ? got === want : want.test(got);
}

/** Retrying assertions, after Playwright's `expect(locator)`. */
export const expectThat = (loc: Locator) => ({
  async toHaveText(want: Name) {
    let got = '';
    await eventually(
      `${loc} has text ${String(want)}`,
      async () => {
        got = await loc.text();
        return test(want, got);
      },
      async () => show(got),
    );
  },
  async toContainText(want: Name) {
    let got = '';
    await eventually(
      `${loc} contains ${String(want)}`,
      async () => {
        got = await loc.text();
        return typeof want === 'string' ? got.includes(want) : want.test(got);
      },
      async () => show(got),
    );
  },
  async notToContainText(want: string) {
    let got = '';
    await eventually(
      `${loc} does not contain ${want}`,
      async () => {
        got = await loc.text();
        return !got.includes(want);
      },
      async () => show(got),
    );
  },
  async toHaveAttribute(name: string, want: Name) {
    let got: string | null = null;
    await eventually(
      `${loc} has ${name}=${String(want)}`,
      async () => {
        got = await loc.attr(name);
        return got !== null && test(want, got);
      },
      async () => String(got),
    );
  },
  async toHaveCount(n: number) {
    let got = -1;
    await eventually(
      `${n} × ${loc}`,
      async () => {
        got = (await loc.describe()).length;
        return got === n;
      },
      async () => String(got),
    );
  },
  async toBeVisible() {
    await expectThat(loc).toHaveCount(1);
  },
  async toBeHidden() {
    await expectThat(loc).toHaveCount(0);
  },
  async toBeDisabled(want = true) {
    let got: boolean | null = null;
    await eventually(
      `${loc} disabled=${want}`,
      async () => {
        const [d] = await loc.describe(['disabled']);
        got = d ? d.attrs['disabled'] !== null : null;
        return got === want;
      },
      async () => String(got),
    );
  },
  async toBeChecked(want = true) {
    let got: boolean | null = null;
    await eventually(
      `${loc} checked=${want}`,
      async () => {
        got = (await loc.describe())[0]?.checked ?? null;
        return got === want;
      },
      async () => String(got),
    );
  },
});

// The app's shared actions, as in app/e2e/helpers.ts.

export const actions = () => page.getByRole('toolbar', 'Actions');
export const mainPane = () => page.getByRole('tree', 'Main pane');
export const rawPane = () => page.getByRole('tree', 'Raw pane');
export const detectedType = () => page.getByTestId('detected-type');
export const keyCards = () => page.getByRole('complementary', 'Keys').getByRole('article');

/** Waits for the shell to load and the TauriEngine to answer. */
export async function appReady(): Promise<void> {
  await expectThat(page.getByRole('textbox', 'Paste a credential or key')).toBeVisible();
}

export async function paste(text: string): Promise<void> {
  await page.getByRole('textbox', 'Paste a credential or key').fill(text);
  await page.getByRole('button', 'Open').click();
}

export async function validate(): Promise<Locator> {
  await actions().getByRole('button', 'Validate').click();
  const report = page.getByRole('list', 'Validation report');
  await expectThat(report).toBeVisible();
  return report;
}

/** The first validation item: the issuer signature. */
export async function expectSignature(want: 'pass' | 'fail' | 'skip' | RegExp): Promise<void> {
  await expectThat(
    page.getByRole('list', 'Validation report').locator('[data-status]').first(),
  ).toHaveAttribute('data-status', want);
}

export async function createKey(
  algorithm: string,
  role: 'issuer' | 'holder' | 'verifier',
): Promise<void> {
  await page.getByRole('button', 'Create key').click();
  const dialog = page.getByRole('dialog', 'Create key');
  await dialog.getByRole('combobox', 'Algorithm').selectOption(algorithm);
  await dialog.getByRole('radio', /well-known test seed/i).check();
  await dialog.getByRole('combobox', 'Role').selectOption(role);
  await dialog.getByRole('button', 'Create').click();
  await expectThat(dialog).toBeHidden();
}

/** Import key dialog → paste → Import. */
export async function importKey(text: string): Promise<void> {
  await page.getByRole('button', 'Import key').click();
  const dialog = page.getByRole('dialog', 'Import key');
  await dialog.getByRole('textbox', 'Key').fill(text);
  await dialog.getByRole('button', 'Import').click();
  await expectThat(dialog).toBeHidden();
}

/** Clicks a dialog's Close button. */
export async function closeDialog(name: string): Promise<void> {
  const dialog = page.getByRole('dialog', name);
  await dialog.getByRole('button', 'Close').first().click();
  await expectThat(dialog).toBeHidden();
}
