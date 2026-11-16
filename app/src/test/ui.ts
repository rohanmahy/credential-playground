// The accessible names the component tests assume for the per-area input
// UI (SPEC §3, §4, §4.1, §4.2), in one place, and DOM helpers for
// pasting, typing, and dropping into a text area. app/e2e/helpers.ts
// repeats the names for Playwright.
//
// - Header: no global input; `nav` "Tools" with Date/time, Settings, About.
// - Key panel: `region` "Issuer key" and `region` "Holder key". Each has the
//   buttons Create, Import, Fetch from URL, Clear, Export, Make public,
//   Auto kid (a menu: JWK thumbprint, COSE thumbprint, Text…); a `textbox`
//   named like the area; a `radiogroup` "Key format" with radios JWK and
//   COSE_Key; key details (description, `data-testid="kid"`,
//   Private/Public, provenance label, both thumbprints, a "Thumbprint hash"
//   select); a parse or detection error in `role="alert"` inside the area.
// - Key chooser: `dialog` "Choose a key", one button per key whose text
//   holds its kid, alg, and kty.
// - Tabs: `tablist` "Credentials", button "New tab" (the +); each tab
//   panel has a `textbox` "Credential text" and a button "Clear"; an empty
//   tab also has a `combobox` "Type" (options "JSON claims", "EDN claims",
//   "JWT", "SD-JWT", …) and the buttons "Open file…" and "From clipboard".
// - SD view: `region` "Selective disclosure" holding `table` "Disclosures";
//   the Claim, Value, Salt, and Digest column headers each hold a
//   focusable `separator` (vertical) "Resize Claim column" / "Resize Value
//   column" / "Resize Salt column" / "Resize Digest column" (ArrowLeft/Right, aria-valuenow = the width in
//   px, mirrored as the header cell's inline `width`). Between the panes
//   and the SD view, a focusable `separator` (horizontal) "Resize
//   disclosures" (ArrowUp grows the SD view, ArrowDown shrinks it;
//   aria-valuenow = its height in px, mirrored as the region's inline
//   `height`).
import { act, screen, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { EditorView } from '@codemirror/view';
import { tick } from 'svelte';
import type { Role } from '../lib/engine/types';

export type AreaRole = Extract<Role, 'issuer' | 'holder'>;

export const NAMES = {
  areas: { issuer: 'Issuer key', holder: 'Holder key' },
  keyFormat: 'Key format',
  jwk: 'JWK',
  coseKey: 'COSE_Key',
  create: 'Create',
  import: 'Import',
  fetch: 'Fetch from URL',
  clear: 'Clear',
  export: 'Export',
  makePublic: 'Make public',
  autoKid: 'Auto kid',
  chooser: 'Choose a key',
  notAKey: 'Not a recognized key',
  newTab: 'New tab',
  credentialText: 'Credential text',
  type: 'Type',
  jsonClaims: 'JSON claims',
  ednClaims: 'EDN claims',
  jwt: 'JWT',
  sdJwt: 'SD-JWT',
  openFile: 'Open file…',
  fromClipboard: 'From clipboard',
  sdRegion: 'Selective disclosure',
  disclosures: 'Disclosures',
  resizeColumn: {
    Claim: 'Resize Claim column',
    Value: 'Resize Value column',
    Salt: 'Resize Salt column',
    Digest: 'Resize Digest column',
  },
  resizeDisclosures: 'Resize disclosures',
} as const;

export type ResizableColumn = keyof typeof NAMES.resizeColumn;

export function keyArea(role: AreaRole): HTMLElement {
  return screen.getByRole('region', { name: NAMES.areas[role] });
}

export function keyBox(role: AreaRole): HTMLElement {
  return within(keyArea(role)).getByRole('textbox', { name: NAMES.areas[role] });
}

export function keyButton(role: AreaRole, name: string | RegExp): HTMLElement {
  return within(keyArea(role)).getByRole('button', { name });
}

/** The active tab's panel (the only one unless split). */
export function activePanel(): HTMLElement {
  const panels = screen.getAllByRole('tabpanel');
  const tab = screen.getByRole('tab', { selected: true });
  const panel = panels.find((p) => p.getAttribute('aria-labelledby') === tab.id) ?? panels[0];
  if (!panel) throw new Error('no tab panel');
  return panel;
}

export function tabBox(panel: HTMLElement = activePanel()): HTMLElement {
  return within(panel).getByRole('textbox', { name: NAMES.credentialText });
}

export function tabButton(name: string | RegExp, panel: HTMLElement = activePanel()): HTMLElement {
  return within(panel).getByRole('button', { name });
}

function isField(el: Element): el is HTMLTextAreaElement | HTMLInputElement {
  return el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement;
}

/** A textarea's value, or a CodeMirror editor's document. */
export function textOf(el: HTMLElement): string {
  if (isField(el)) return el.value;
  const view = EditorView.findFromDOM(el);
  return view ? view.state.doc.toString() : (el.textContent ?? '');
}

/** What the browser does when a paste or drop is not prevented. */
function insertDefault(el: HTMLElement, text: string, inputType: string, userEvent: string) {
  if (isField(el)) {
    const start = el.selectionStart ?? el.value.length;
    const end = el.selectionEnd ?? el.value.length;
    el.value = el.value.slice(0, start) + text + el.value.slice(end);
    el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType, data: text }));
    return;
  }
  const view = EditorView.findFromDOM(el);
  if (!view) return;
  const { from, to } = view.state.selection.main;
  view.dispatch({ changes: { from, to, insert: text }, userEvent });
}

function clipboardData(text: string) {
  return {
    types: ['text/plain'],
    files: [] as File[],
    items: [],
    getData: (type: string) => (type === 'text/plain' || type === 'text' ? text : ''),
    setData: () => undefined,
    clearData: () => undefined,
  };
}

/** A paste: a `paste` event carrying `text/plain`; if the app does not
 *  prevent it, the text is inserted as the browser would
 *  (`inputType: insertFromPaste`, CodeMirror `input.paste`). */
export async function pasteInto(el: HTMLElement, text: string): Promise<void> {
  await act(async () => {
    el.focus();
    const ev = new Event('paste', { bubbles: true, cancelable: true });
    Object.defineProperty(ev, 'clipboardData', { value: clipboardData(text) });
    if (el.dispatchEvent(ev)) insertDefault(el, text, 'insertFromPaste', 'input.paste');
    await tick();
  });
}

/** Typing (not a paste): keystrokes into a textarea, or a CodeMirror
 *  `input.type` transaction at the end of the document. */
export async function typeInto(el: HTMLElement, text: string): Promise<void> {
  if (isField(el)) {
    await userEvent.type(
      el,
      text.replace(/[{[]/g, (c) => c + c),
    );
    return;
  }
  await act(async () => {
    const view = EditorView.findFromDOM(el);
    if (!view) throw new Error('typeInto: not a textarea or CodeMirror editor');
    const end = view.state.doc.length;
    view.dispatch({ changes: { from: end, insert: text }, userEvent: 'input.type' });
    await tick();
  });
}

export interface DropOutcome {
  /** dragover was prevented and did not set dropEffect to 'none'. A
   *  refusal is either an unprevented dragover or dropEffect 'none' (the
   *  window-level guard outside empty text areas). */
  accepted: boolean;
  /** dragover was prevented (by the area or by the window guard). */
  prevented: boolean;
  /** dataTransfer.dropEffect after dragover. */
  dropEffect: string;
}

/** dragenter + dragover + drop of `text` (or a file) onto `el`, with a
 *  writable fake DataTransfer (jsdom has none). */
export async function dropOnto(
  el: Element,
  payload: { text: string } | { file: File },
): Promise<DropOutcome> {
  const files = 'file' in payload ? [payload.file] : [];
  const dt = {
    types: 'file' in payload ? ['Files'] : ['text/plain'],
    files,
    items: files.map((f) => ({ kind: 'file', type: f.type, getAsFile: () => f })),
    dropEffect: 'copy',
    effectAllowed: 'all',
    getData: (type: string) =>
      'text' in payload && (type === 'text/plain' || type === 'text') ? payload.text : '',
    setData: () => undefined,
    clearData: () => undefined,
  };
  const fire = (type: string) => {
    const ev = new Event(type, { bubbles: true, cancelable: true });
    Object.defineProperty(ev, 'dataTransfer', { value: dt });
    return el.dispatchEvent(ev);
  };
  let outcome: DropOutcome = { accepted: false, prevented: false, dropEffect: '' };
  await act(async () => {
    fire('dragenter');
    const overNotPrevented = fire('dragover');
    outcome = {
      accepted: !overNotPrevented && dt.dropEffect !== 'none',
      prevented: !overNotPrevented,
      dropEffect: dt.dropEffect,
    };
    fire('drop');
    await tick();
  });
  return outcome;
}
