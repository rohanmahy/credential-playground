// Display helpers for Kind (mirrors `Kind::label`/`family` in core).
import type { Family, Kind } from '../engine/types';

/** `JWT`, `SD-JWT+KB`, `CWT`, `JSON claim set`, … as `Kind::label()`. */
export function kindLabel(kind: Kind): string {
  switch (kind.type) {
    case 'jwt':
      return 'JWT';
    case 'jws_compact':
      return 'JWS';
    case 'sd_jwt':
      return kind.kb ? 'SD-JWT+KB' : 'SD-JWT';
    case 'jws_json':
      return 'JWS JSON';
    case 'sd_jwt_json':
      return kind.kb ? 'SD-JWT+KB JSON' : 'SD-JWT JSON';
    case 'cose_sign1':
      return 'COSE_Sign1';
    case 'cwt':
      return 'CWT';
    case 'sd_cwt':
      return 'SD-CWT';
    case 'sd_kbt':
      return 'SD-KBT';
    case 'json_claims':
      return 'JSON claim set';
    case 'cbor_claims':
      return 'CBOR claim set';
    case 'edn_claims':
      return 'EDN claim set';
    case 'jwk':
      return 'JWK';
    case 'jwk_set':
      return 'JWK Set';
    case 'cose_key':
      return 'COSE_Key';
    case 'cose_key_set':
      return 'COSE_KeySet';
    case 'pem':
      return 'PEM';
  }
}

export function kindFamily(kind: Kind): Family | null {
  switch (kind.type) {
    case 'jwt':
    case 'jws_compact':
    case 'sd_jwt':
    case 'jws_json':
    case 'sd_jwt_json':
    case 'json_claims':
      return 'jose';
    case 'cose_sign1':
    case 'cwt':
    case 'sd_cwt':
    case 'sd_kbt':
    case 'cbor_claims':
    case 'edn_claims':
    case 'cose_key':
    case 'cose_key_set':
      return 'cose';
    default:
      return null;
  }
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

/** SD-JWT or SD-CWT, with or without key binding. */
export function isSd(kind: Kind): boolean {
  return kind.type === 'sd_jwt' || kind.type === 'sd_jwt_json' || kind.type === 'sd_cwt';
}

/** A presentation: SD-JWT+KB or SD-KBT. */
export function hasKeyBinding(kind: Kind): boolean {
  return (
    ((kind.type === 'sd_jwt' || kind.type === 'sd_jwt_json') && kind.kb) || kind.type === 'sd_kbt'
  );
}
