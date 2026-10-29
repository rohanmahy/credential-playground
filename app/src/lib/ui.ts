// Small DOM helpers shared by components.

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
