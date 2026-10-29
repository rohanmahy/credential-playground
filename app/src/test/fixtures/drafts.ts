// Draft fixtures (#43): the documents parse_edit returns for new drafts,
// and results of the proposed convert_claims.
import type { Candidate, Document, EditResult, Kind } from '../../lib/engine/types';
import type { ConvertClaimsResult } from '../../lib/engine/pending';
import { textToB64u } from '../../lib/engine/bytes';
import { buildJsonClaims } from './jose';
import { cwt, ednClaims } from './documents';

export const DRAFT_JSON_TEXT = '{"iss": "https://issuer.example", "exp": 1893456000}';
export const DRAFT_EDN_TEXT = '{1: "https://issuer.example", 4: 1893456000}';

/** `{}` as a JSON claim set (what New gives). */
export const emptyJsonDraft: Document = buildJsonClaims('{}');

/** `{}` as an EDN claim set. */
export const emptyEdnDraft: Document = {
  ...structuredClone(ednClaims),
  bytes: textToB64u('{}'),
  main: { language: 'edn', text: '{}', line_count: 1 },
  tree: { ...structuredClone(ednClaims.tree), children: [] },
  raw: { type: 'hex', bytes: 'oA', rows: [] },
};

export const jsonDraft: Document = buildJsonClaims(DRAFT_JSON_TEXT);

export function edited(document: Document, stale = false): EditResult {
  return { ok: true, bytes: document.bytes, document, signature_stale: stale, diagnostics: [] };
}

/** A COSE_Sign1 written in an EDN draft and parsed as a CWT: parse_edit
 *  reports it stale (the base is empty), which drafts ignore. */
export const cwtDraftEdit: EditResult = edited(cwt, true);

/** A COSE_Key draft as parse_edit returns it. */
export const coseKeyDraft: Document = {
  ...structuredClone(cwt),
  kind: { type: 'cose_key' },
  signed: false,
};

function only(kind: Kind, confidence: number, label: string, length: number): Candidate[] {
  return [
    { kind, confidence, layers: [], payload_range: { start: 0, end: length }, breadcrumb: [label] },
  ];
}

export const jsonClaimsDetected = only({ type: 'json_claims' }, 60, 'JSON claim set', 2);
export const ednClaimsDetected = only({ type: 'edn_claims' }, 40, 'EDN claim set', 2);
/** What core should detect for EDN text of a COSE_Sign1 (gap: today it
 *  returns nothing, TEST-PLAN "Core additions needed"). */
export const cwtEdnDetected = only({ type: 'cwt' }, 80, 'CWT', 60);
export const jwkDetected: Candidate[] = [
  ...only({ type: 'jwk' }, 90, 'JWK', 80),
  ...only({ type: 'json_claims' }, 60, 'JSON claim set', 80),
];
export const jwsJsonDetected = only({ type: 'jws_json', general: false }, 90, 'JWS JSON', 120);

export const convertedToEdn: ConvertClaimsResult = {
  ok: true,
  text: DRAFT_EDN_TEXT,
  document: {
    ...structuredClone(emptyEdnDraft),
    bytes: textToB64u(DRAFT_EDN_TEXT),
    main: { language: 'edn', text: DRAFT_EDN_TEXT, line_count: 1 },
  },
  diagnostics: [],
};

export const convertedToJson: ConvertClaimsResult = {
  ok: true,
  text: DRAFT_JSON_TEXT,
  document: jsonDraft,
  diagnostics: [],
};

/** EDN with a byte string: no JSON form. */
export const notRepresentable: ConvertClaimsResult = {
  ok: false,
  text: null,
  document: null,
  diagnostics: [
    {
      severity: 'error',
      code: 'convert.not_representable',
      message: 'a byte string has no JSON form',
      node_id: '2',
      main: null,
      raw: null,
    },
  ],
};
