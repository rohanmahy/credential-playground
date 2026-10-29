// Drafts started from nothing (#43): the main pane opens in Live edit with
// a Format (JSON or EDN); the type is detected from the text, or set
// explicitly. Rules: app/TEST-PLAN.md "New drafts and explicit type".
import type { Kind } from '../engine/types';
import { notImplemented } from '../notImplemented';

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

/** The draft's type: the explicit choice, else the detected kind when it is
 *  one of the format's DRAFT_KINDS, else the format's default. */
export function effectiveDraftKind(
  _format: DraftFormat,
  _detected: Kind | null,
  _override: Kind | null,
): Kind {
  notImplemented('effectiveDraftKind');
}

/** The kind `parse_edit` is called with for a draft type: JWK and JWK Set
 *  drafts are parsed (and shown) as JSON claim sets; the rest as is. */
export function draftParseKind(_kind: Kind): Kind {
  notImplemented('draftParseKind');
}
