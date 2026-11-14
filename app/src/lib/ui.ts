// Small DOM helpers shared by components.
import type { Provenance } from './model';
import { utf8 } from './engine/bytes';

let counter = 0;

/** A document-unique id for aria-labelledby and friends. */
export function uid(prefix: string): string {
  counter += 1;
  return `${prefix}-${counter}`;
}

const FOCUSABLE =
  'input:not([disabled]), select:not([disabled]), textarea:not([disabled]), button:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function focusables(root: HTMLElement): HTMLElement[] {
  return [...root.querySelectorAll<HTMLElement>(FOCUSABLE)];
}

export function hex(bytes: Uint8Array, from = 0, to = bytes.length): string {
  let out = '';
  for (let i = from; i < to; i++) out += (bytes[i] ?? 0).toString(16).padStart(2, '0');
  return out;
}

export function errorMessage(e: unknown): string {
  if (e && typeof e === 'object' && 'message' in e && typeof e.message === 'string') {
    return e.message;
  }
  return String(e);
}

export interface MenuItem {
  label: string;
  role?: 'menuitem' | 'menuitemradio' | 'menuitemcheckbox';
  checked?: boolean;
  disabled?: boolean;
  action: () => void;
}

/** Input pasted or dropped into an empty text area. */
export interface AreaInput {
  bytes: Uint8Array;
  provenance: Provenance;
}

/** What a drop carries: the first file, else its text; null when empty. */
export async function droppedInput(dt: DataTransfer | null): Promise<AreaInput | null> {
  if (!dt) return null;
  const file = dt.files[0];
  if (file) {
    return {
      bytes: new Uint8Array(await file.arrayBuffer()),
      provenance: { type: 'dropped', name: file.name },
    };
  }
  const text = dt.getData('text/plain');
  return text.trim() ? { bytes: utf8(text), provenance: { type: 'dropped', name: null } } : null;
}

/** What a paste carries; null when it has no text. */
export function pastedInput(e: ClipboardEvent): AreaInput | null {
  const text = e.clipboardData?.getData('text/plain') ?? '';
  return text.trim() ? { bytes: utf8(text), provenance: { type: 'pasted' } } : null;
}

/** Drag and drop goes only into an empty text area (SPEC §4): a full one
 *  shows the no-drop cursor and ignores the drop. Call on dragover/drop. */
export function refuseDrop(e: DragEvent): void {
  e.preventDefault();
  e.stopPropagation();
  if (e.dataTransfer) e.dataTransfer.dropEffect = 'none';
}

/** Accepts a drag over an empty text area (dragover). */
export function acceptDrag(e: DragEvent): void {
  e.preventDefault();
  e.stopPropagation();
  if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
}
