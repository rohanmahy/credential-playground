// `Engine::convert_claims` (#44): claim sets between JSON and EDN text,
// used when switching a draft's Format. The DTOs are generated from core;
// the method stays out of `Engine` (the Tauri test pins `Engine` to the
// original core methods), so callers check for it with `hasConvertClaims`.
// WasmEngine and TauriEngine both have it.
import type { ConvertClaimsRequest, ConvertClaimsResult } from './types';

export type { ConvertClaimsRequest, ConvertClaimsResult };

/** `convertClaims(req)`: `ok: false` when the text does not parse
 *  (`json.syntax` / `edn.syntax`) or EDN has no JSON form
 *  (`convert.not_representable`, with the node). JSON → EDN maps integer
 *  lexemes that fit CBOR to ints and other numbers to floats; with
 *  `map_claim_labels`, registered JWT names ↔ CWT labels at the top level. */
export interface ConvertClaims {
  convertClaims(req: ConvertClaimsRequest): Promise<ConvertClaimsResult>;
}

export function hasConvertClaims<E extends object>(engine: E): engine is E & ConvertClaims {
  return typeof (engine as Partial<ConvertClaims>).convertClaims === 'function';
}
