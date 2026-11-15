// Tabs written from scratch (#43, SPEC §4.1): every tab starts empty, in
// Live edit, with a Type picker that applies when the user types. Once
// committed, the type sticks; edits never re-run detection. Rules:
// app/TEST-PLAN.md "New drafts and explicit type".
import type { Document, Kind } from '../engine/types';

export type DraftFormat = 'json' | 'edn';

export const DRAFT_FORMATS: readonly { format: DraftFormat; label: string }[] = [
  { format: 'json', label: 'JSON' },
  { format: 'edn', label: 'EDN' },
];

/** The types a draft can be set to, per format, in menu order. The first
 *  is the format's default. Keys are not credentials: they go into the
 *  key areas, never into a tab. JWT and SD-JWT drafts are typed as the
 *  compact serialization and shown as JSON, so they sit with JSON. */
export const DRAFT_KINDS: Readonly<Record<DraftFormat, readonly Kind[]>> = {
  json: [{ type: 'json_claims' }, { type: 'jwt' }, { type: 'sd_jwt', kb: false }],
  edn: [
    { type: 'edn_claims' },
    { type: 'cose_sign1' },
    { type: 'cwt' },
    { type: 'sd_cwt' },
    { type: 'sd_kbt' },
  ],
};

/** An empty tab's Type picker, in menu order (the first is the default).
 *  One SD-JWT entry: the parsed `kb` decides SD-JWT or SD-JWT+KB. */
export interface TabType {
  id: string;
  label: string;
  format: DraftFormat;
  kind: Kind;
}

export const TAB_TYPES: readonly TabType[] = [
  { id: 'json_claims', label: 'JSON claims', format: 'json', kind: { type: 'json_claims' } },
  { id: 'edn_claims', label: 'EDN claims', format: 'edn', kind: { type: 'edn_claims' } },
  { id: 'jwt', label: 'JWT', format: 'json', kind: { type: 'jwt' } },
  { id: 'sd_jwt', label: 'SD-JWT', format: 'json', kind: { type: 'sd_jwt', kb: false } },
  { id: 'cose_sign1', label: 'COSE_Sign1 (EDN)', format: 'edn', kind: { type: 'cose_sign1' } },
  { id: 'cwt', label: 'CWT (EDN)', format: 'edn', kind: { type: 'cwt' } },
  { id: 'sd_cwt', label: 'SD-CWT (EDN)', format: 'edn', kind: { type: 'sd_cwt' } },
  { id: 'sd_kbt', label: 'SD-KBT (EDN)', format: 'edn', kind: { type: 'sd_kbt' } },
];

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

/** Whether `kind` is one of the format's draft types. */
export function isDraftKind(format: DraftFormat, kind: Kind): boolean {
  return DRAFT_KINDS[format].some((k) => sameType(k, kind));
}

/** The Type picker entry for a format and kind (the format's default
 *  when the kind has none). */
export function tabTypeOf(format: DraftFormat, kind: Kind): TabType {
  return (
    TAB_TYPES.find((t) => t.format === format && sameType(t.kind, kind)) ??
    TAB_TYPES.find((t) => t.format === format) ??
    (TAB_TYPES[0] as TabType)
  );
}

/** Why a Format switch would discard the draft (shown before asking). */
export interface DiscardReason {
  message: string;
  /** The node the engine pointed at, if any. */
  nodeId: string | null;
}

/** The placeholder document of an empty tab: no text, no nodes. */
export function emptyDocument(kind: Kind, format: DraftFormat): Document {
  return {
    kind,
    layers: [],
    bytes: '',
    signed: false,
    signature_stale: false,
    tree: {
      id: '',
      kind: 'document',
      label: '',
      annotation: null,
      main: null,
      raw: null,
      key: null,
      time: null,
      sd: null,
      children: [],
    },
    main: { language: format, text: '', line_count: 1 },
    raw: { type: 'none' },
    disclosures: [],
    undisclosed: [],
    diagnostics: [],
  };
}
