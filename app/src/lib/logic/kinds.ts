// Display helpers for Kind (mirrors `Kind::label`/`family` in core).
import type { Family, Kind } from '../engine/types';
import { notImplemented } from '../notImplemented';

/** `JWT`, `SD-JWT+KB`, `CWT`, `JSON claim set`, … as `Kind::label()`. */
export function kindLabel(_kind: Kind): string {
  notImplemented('kindLabel');
}

export function kindFamily(_kind: Kind): Family | null {
  notImplemented('kindFamily');
}

export function isClaims(kind: Kind): boolean {
  return kind.type === 'json_claims' || kind.type === 'cbor_claims' || kind.type === 'edn_claims';
}

export function isKey(kind: Kind): boolean {
  return ['jwk', 'jwk_set', 'cose_key', 'cose_key_set', 'pem'].includes(kind.type);
}

export function isSigned(kind: Kind): boolean {
  return !isClaims(kind) && !isKey(kind);
}
