// Drafts started from nothing (#43): the main pane opens in Live edit with
// a Format (JSON or EDN); the type is detected from the text, or set
// explicitly. Rules: app/TEST-PLAN.md "New drafts and explicit type".
import type { Kind } from '../engine/types';

export type DraftFormat = 'json' | 'edn';

export const DRAFT_FORMATS: readonly { format: DraftFormat; label: string }[] = [
  { format: 'json', label: 'JSON' },
  { format: 'edn', label: 'EDN' },
];

/** The starter text of a new draft. */
export const DRAFT_TEMPLATES: Readonly<Record<DraftFormat, string>> = {
  json: '{}',
  edn: '{}',
};

/** The types a draft can be set to, per format, in menu order. The first
 *  is the default when detection finds nothing that fits the format. */
export const DRAFT_KINDS: Readonly<Record<DraftFormat, readonly Kind[]>> = {
  json: [{ type: 'json_claims' }, { type: 'jwk' }, { type: 'jwk_set' }],
  edn: [
    { type: 'edn_claims' },
    { type: 'cose_sign1' },
    { type: 'cwt' },
    { type: 'sd_cwt' },
    { type: 'sd_kbt' },
    { type: 'cose_key' },
    { type: 'cose_key_set' },
  ],
};

function sameType(a: Kind, b: Kind): boolean {
  return a.type === b.type;
}

/** The draft's type: the explicit choice, else the detected kind when it is
 *  one of the format's DRAFT_KINDS, else the format's default. */
export function effectiveDraftKind(
  format: DraftFormat,
  detected: Kind | null,
  override: Kind | null,
): Kind {
  if (override) return override;
  const kinds = DRAFT_KINDS[format];
  if (detected && kinds.some((k) => sameType(k, detected))) return detected;
  return kinds[0] ?? { type: 'json_claims' };
}

/** The kind `parse_edit` is called with for a draft type: JWK and JWK Set
 *  drafts are parsed (and shown) as JSON claim sets; the rest as is. */
export function draftParseKind(kind: Kind): Kind {
  return kind.type === 'jwk' || kind.type === 'jwk_set' ? { type: 'json_claims' } : kind;
}

/** Whether `kind` is one of the format's draft types. */
export function isDraftKind(format: DraftFormat, kind: Kind): boolean {
  return DRAFT_KINDS[format].some((k) => sameType(k, kind));
}

/** Draft types that belong in the key panel ("Add to key panel"). */
export function isDraftKeyKind(kind: Kind): boolean {
  return ['jwk', 'jwk_set', 'cose_key', 'cose_key_set'].includes(kind.type);
}

/** A detected kind no draft format has (e.g. JWS JSON, a JWT): offered as
 *  "Open as …" in a regular tab. */
export function openableAs(detected: Kind | null): Kind | null {
  if (!detected) return null;
  return isDraftKind('json', detected) || isDraftKind('edn', detected) ? null : detected;
}

/** Why a Format switch would discard the draft (shown before asking). */
export interface DiscardReason {
  message: string;
  /** The node the engine pointed at, if any. */
  nodeId: string | null;
}
