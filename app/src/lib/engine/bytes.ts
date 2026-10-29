// Bytes cross the Engine boundary as unpadded base64url strings
// (core TEST-PLAN §2).
import type { Bytes } from './types';

export function toB64u(bytes: Uint8Array): Bytes {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromB64u(text: Bytes): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
    throw new Error('expected unpadded base64url');
  }
  const bin = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function fromUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function textToB64u(text: string): Bytes {
  return toB64u(utf8(text));
}

export function b64uToText(text: Bytes): string {
  return fromUtf8(fromB64u(text));
}
