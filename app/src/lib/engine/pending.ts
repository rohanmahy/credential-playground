// Engine additions proposed for #43 that tokenator-core does not have yet
// (app/TEST-PLAN.md "Core additions needed"). The shapes follow the core
// wire conventions; replace them with the generated types once core
// exports them.
import type { Diagnostic, Document, Language, ViewOptions } from './types';

/** Proposed `Engine::convert_claims`: a claim set from JSON text to EDN or
 *  back. */
export interface ConvertClaimsRequest {
  text: string;
  from: Language;
  to: Language;
  /** Map registered JWT claim names to CWT labels (JSON → EDN) and back,
   *  through the registry (SPEC §7). */
  map_claim_labels: boolean;
  view: ViewOptions;
}

export interface ConvertClaimsResult {
  /** False when the input does not parse or cannot be represented in `to`
   *  (EDN → JSON with byte strings, non-text keys, tags, simple values,
   *  undefined, non-finite floats); see `diagnostics` (code
   *  `convert.not_representable`, with the node). */
  ok: boolean;
  text: string | null;
  /** The converted claim set (`json_claims` / `edn_claims`). */
  document: Document | null;
  diagnostics: Diagnostic[];
}

/** The proposed method, kept out of `Engine` until core has it (the
 *  Tauri test pins `Engine` to the core methods). The workspace uses it
 *  when the engine has it (`hasConvertClaims`); otherwise a Format switch
 *  asks before discarding the draft. */
export interface ConvertClaims {
  convertClaims(req: ConvertClaimsRequest): Promise<ConvertClaimsResult>;
}

export function hasConvertClaims<E extends object>(engine: E): engine is E & ConvertClaims {
  return typeof (engine as Partial<ConvertClaims>).convertClaims === 'function';
}
