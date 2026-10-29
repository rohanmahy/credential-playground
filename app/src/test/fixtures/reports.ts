// Validation reports.
import type { ValidationReport } from '../../lib/engine/types';

export const jwtReport: ValidationReport = {
  overall: 'fail',
  items: [
    {
      id: 'signature',
      category: 'signature',
      status: 'pass',
      message: 'Signature verified with Issuer P-256 (kid match)',
      node_ids: ['signature', 'protected/~e/kid'],
      raw: null,
      detail: {
        type: 'signature',
        alg: 'ES256',
        key_index: 0,
        key_label: 'Issuer P-256',
        selection: 'panel_kid',
        untrusted: false,
      },
    },
    {
      id: 'time.exp',
      category: 'time',
      status: 'fail',
      message: 'Expired 2 d ago',
      node_ids: ['payload/~e/exp'],
      raw: null,
      detail: { type: 'time', claim: 'exp', value: 1799827200, now: 1800000000, skew: 60 },
    },
    {
      id: 'time.iat',
      category: 'time',
      status: 'pass',
      message: 'Issued in the past',
      node_ids: ['payload/~e/iat'],
      raw: null,
      detail: { type: 'time', claim: 'iat', value: 1767225600, now: 1800000000, skew: 60 },
    },
    {
      id: 'lint.typ',
      category: 'lint',
      status: 'warn',
      message: 'Unexpected typ "JWT" for this profile',
      node_ids: ['protected/~e/typ'],
      raw: null,
      detail: null,
    },
    {
      id: 'kb',
      category: 'key_binding',
      status: 'skip',
      message: 'No key binding',
      node_ids: [],
      raw: null,
      detail: null,
    },
  ],
  fetchable: [],
};

export const kidUrlReport: ValidationReport = {
  overall: 'skip',
  items: [
    {
      id: 'signature',
      category: 'signature',
      status: 'skip',
      message: 'No key to verify with',
      node_ids: ['signature'],
      raw: null,
      detail: {
        type: 'signature',
        alg: 'ES256',
        key_index: null,
        key_label: null,
        selection: 'none',
        untrusted: false,
      },
    },
  ],
  fetchable: [
    {
      kind: 'kid_url',
      url: 'https://issuer.example/keys/1.jwk',
      reason: 'The header kid is a URL',
    },
  ],
};

export const cwtLintReport: ValidationReport = {
  overall: 'warn',
  items: [
    {
      id: 'lint.encoding',
      category: 'lint',
      status: 'warn',
      message: 'Non-preferred argument: 1444064944 could be shorter',
      node_ids: ['payload/~e/4'],
      raw: { start: 41, end: 46 },
      detail: { type: 'encoding', finding: 'non_preferred_argument', preferred_hex: '1a5612aeb0' },
    },
  ],
  fetchable: [],
};
