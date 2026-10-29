// Document fixtures (hand-written, typed against the generated DTOs).
import type { DisclosureInfo, Document, EditResult, Kind } from '../../lib/engine/types';
import { b64uToText, textToB64u } from '../../lib/engine/bytes';
import { annotation, asciiHex } from './build';
import { buildCose } from './cose';
import { buildJose, buildJsonClaims } from './jose';

export const NOW = 1_800_000_000; // 2027-01-15T08:00:00Z, MockPlatform's clock

const ann = {
  iss: annotation(
    'iss',
    'Issuer',
    'RFC 7519, Section 4.1.1',
    'https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1',
  ),
  sub: annotation(
    'sub',
    'Subject',
    'RFC 7519, Section 4.1.2',
    'https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2',
  ),
  exp: annotation(
    'exp',
    'Expiration Time',
    'RFC 7519, Section 4.1.4',
    'https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4',
  ),
  alg: annotation(
    'alg',
    'Algorithm',
    'RFC 7515, Section 4.1.1',
    'https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1',
  ),
  cwtIss: annotation(
    'iss',
    'Issuer',
    'RFC 8392, Section 3.1.1',
    'https://www.rfc-editor.org/rfc/rfc8392#section-3.1.1',
  ),
  cwtSub: annotation(
    'sub',
    'Subject',
    'RFC 8392, Section 3.1.2',
    'https://www.rfc-editor.org/rfc/rfc8392#section-3.1.2',
  ),
  cwtExp: annotation(
    'exp',
    'Expiration Time',
    'RFC 8392, Section 3.1.4',
    'https://www.rfc-editor.org/rfc/rfc8392#section-3.1.4',
  ),
  coseAlg: annotation(
    'alg',
    'Cryptographic algorithm to use',
    'RFC 9052, Section 3.1',
    'https://www.rfc-editor.org/rfc/rfc9052#section-3.1',
    'ES256',
  ),
  coseKid: annotation(
    'kid',
    'Key identifier',
    'RFC 9052, Section 3.1',
    'https://www.rfc-editor.org/rfc/rfc9052#section-3.1',
  ),
};

export const ANNOTATIONS = ann;

// --- JWT ----------------------------------------------------------------------

const JWT_PAYLOAD = `{
    "iss": "https://issuer.example",
    "sub": "user-42",
    "iat": 1767225600,
    "exp": 1893456000
  }`;

export const jwt: Document = buildJose({
  kind: { type: 'jwt' },
  header: '{"alg":"ES256","kid":"issuer-1","typ":"JWT"}',
  payload: JWT_PAYLOAD,
  signature: 'c2lnbmF0dXJlLWJ5dGVz',
  extras: {
    'protected/~e/alg': { annotation: ann.alg },
    'payload/~e/iss': { annotation: ann.iss },
    'payload/~e/sub': { annotation: ann.sub },
    'payload/~e/iat': {
      time: { epoch: 1767225600, rfc3339: '2026-01-01T00:00:00Z', relative: '379 d 8 h ago' },
    },
    'payload/~e/exp': {
      annotation: ann.exp,
      time: { epoch: 1893456000, rfc3339: '2030-01-01T00:00:00Z', relative: 'in 1081 d 16 h' },
    },
  },
});

export const jwtToken = b64uToText(jwt.bytes);

/** The JWT after a live edit of `sub` (same NodeIds, stale signature). */
export const jwtEdited: Document = {
  ...buildJose({
    kind: { type: 'jwt' },
    header: '{"alg":"ES256","kid":"issuer-1","typ":"JWT"}',
    payload: JWT_PAYLOAD.replace('user-42', 'user-43'),
    signature: 'c2lnbmF0dXJlLWJ5dGVz',
  }),
  signature_stale: true,
};

// --- SD-JWT -------------------------------------------------------------------

const SD_HEADER = '{"alg":"ES256","typ":"example+sd-jwt"}';
const SD_PAYLOAD = `{
    "_sd": [
      "dig-given-name",
      "dig-email",
      "dig-decoy"
    ],
    "iss": "https://issuer.example",
    "_sd_alg": "sha-256",
    "cnf": {"jwk": {"kty":"OKP","crv":"Ed25519","x":"aG9sZGVy"}}
  }`;
const DISCLOSURES = ['["salt-1","given_name","Alice"]', '["salt-2","email","alice@example.com"]'];

const sdInfos: DisclosureInfo[] = [
  {
    index: 0,
    node_id: 'disclosures/0',
    digest: 'dig-given-name',
    salt: 'salt-1',
    claim: 'given_name',
    value: '"Alice"',
    decoy: false,
    status: 'matched',
    slot: 'payload/~e/_sd/0',
  },
  {
    index: 1,
    node_id: 'disclosures/1',
    digest: 'dig-email',
    salt: 'salt-2',
    claim: 'email',
    value: '"alice@example.com"',
    decoy: false,
    status: 'matched',
    slot: 'payload/~e/_sd/1',
  },
];

const sdExtras = {
  'payload/~e/iss': { annotation: ann.iss },
  'payload/~e/_sd': { sd: { type: 'digest_list' as const } },
  'payload/~e/_sd/0': { sd: { type: 'slot' as const, digest: 'dig-given-name', disclosure: 0 } },
  'payload/~e/_sd/1': { sd: { type: 'slot' as const, digest: 'dig-email', disclosure: 1 } },
  'payload/~e/_sd/2': { sd: { type: 'slot' as const, digest: 'dig-decoy', disclosure: null } },
  'disclosures/0': { sd: { type: 'disclosure' as const, index: 0 } },
  'disclosures/1': { sd: { type: 'disclosure' as const, index: 1 } },
};

export const sdJwt: Document = {
  ...buildJose({
    kind: { type: 'sd_jwt', kb: false },
    header: SD_HEADER,
    payload: SD_PAYLOAD,
    signature: 'c2Qtand0LXNpZw',
    disclosures: DISCLOSURES,
    extras: sdExtras,
  }),
  disclosures: sdInfos,
  undisclosed: [{ node_id: 'payload/~e/_sd/2', digest: 'dig-decoy', array_element: false }],
};

export const sdJwtKb: Document = {
  ...buildJose({
    kind: { type: 'sd_jwt', kb: true },
    header: SD_HEADER,
    payload: SD_PAYLOAD,
    signature: 'c2Qtand0LXNpZw',
    disclosures: DISCLOSURES,
    kb: {
      header: '{"alg":"EdDSA","typ":"kb+jwt"}',
      payload:
        '{"aud":"https://verifier.example","nonce":"n-0S6","iat":1800000000,"sd_hash":"aGFzaA"}',
      signature: 'a2Itc2ln',
    },
    extras: sdExtras,
  }),
  disclosures: sdInfos,
  undisclosed: [{ node_id: 'payload/~e/_sd/2', digest: 'dig-decoy', array_element: false }],
};

// --- CWT ----------------------------------------------------------------------

export const CWT_EDN = `18([
  / protected / << {
    / alg / 1: -7 / ES256 /
  } >>,
  / unprotected / {
    / kid / 4: h'4173796d6d65747269634543445341323536'
  },
  / payload / << {
    / iss / 1: "coap://as.example.com",
    / sub / 2: "erikw",
    / exp / 4: 1444064944
  } >>,
  / signature / h'5427c1ff28d23fba'
])`;

export const cwt: Document = buildCose({
  kind: { type: 'cwt' },
  signed: true,
  edn: CWT_EDN,
  rows: [
    ['', 0, 'd2', '', 'tag(18)', null],
    ['', 0, '84', '', 'array(4)', null],
    ['protected', 1, '43', '', 'bytes(3)', null],
    ['protected/~e', 2, 'a1', '', 'map(1)', null],
    ['protected/~e/1/~k', 3, '01', '', 'unsigned(1)', 'alg'],
    ['protected/~e/1', 3, '26', '', 'negative(-7)', 'ES256'],
    ['unprotected', 1, 'a1', '', 'map(1)', null],
    ['unprotected/4/~k', 2, '04', '', 'unsigned(4)', 'kid'],
    ['unprotected/4', 2, '52', '4173796d6d65747269634543445341323536', 'bytes(18)', null],
    ['payload', 1, '5825', '', 'bytes(37)', null],
    ['payload/~e', 2, 'a3', '', 'map(3)', null],
    ['payload/~e/1/~k', 3, '01', '', 'unsigned(1)', 'iss'],
    ['payload/~e/1', 3, '75', asciiHex('coap://as.example.com'), 'text(21)', null],
    ['payload/~e/2/~k', 3, '02', '', 'unsigned(2)', 'sub'],
    ['payload/~e/2', 3, '65', asciiHex('erikw'), 'text(5)', null],
    ['payload/~e/4/~k', 3, '04', '', 'unsigned(4)', 'exp'],
    ['payload/~e/4', 3, '1a5612aeb0', '', 'unsigned(1444064944)', null],
    ['signature', 1, '48', '5427c1ff28d23fba', 'bytes(8)', null],
  ],
  tree: {
    id: '',
    kind: 'array',
    label: '',
    main: [
      [0, '18(['],
      [13, '])'],
    ],
    rows: [0, 18],
    children: [
      {
        id: 'protected',
        kind: 'bytes',
        label: 'protected',
        main: [
          [1, '<<'],
          [3, '>>'],
        ],
        rows: [2, 6],
        children: [
          {
            id: 'protected/~e',
            kind: 'decoded',
            label: 'decoded',
            main: [
              [1, '{'],
              [3, '}'],
            ],
            rows: [3, 6],
            children: [
              {
                id: 'protected/~e/1',
                kind: 'integer',
                label: '1',
                main: [2, '-7'],
                rows: [5, 6],
                key: {
                  id: 'protected/~e/1/~k',
                  kind: 'integer',
                  label: '1',
                  main: [2, '1'],
                  rows: [4, 5],
                },
                extras: { annotation: ann.coseAlg },
              },
            ],
          },
        ],
      },
      {
        id: 'unprotected',
        kind: 'map',
        label: 'unprotected',
        main: [
          [4, '{'],
          [6, '}'],
        ],
        rows: [6, 9],
        children: [
          {
            id: 'unprotected/4',
            kind: 'bytes',
            label: '4',
            main: [5, "h'4173796d6d65747269634543445341323536'"],
            rows: [8, 9],
            key: {
              id: 'unprotected/4/~k',
              kind: 'integer',
              label: '4',
              main: [5, '4'],
              rows: [7, 8],
            },
            extras: { annotation: ann.coseKid },
          },
        ],
      },
      {
        id: 'payload',
        kind: 'bytes',
        label: 'payload',
        main: [
          [7, '<<'],
          [11, '>>'],
        ],
        rows: [9, 17],
        children: [
          {
            id: 'payload/~e',
            kind: 'decoded',
            label: 'decoded',
            main: [
              [7, '{'],
              [11, '}'],
            ],
            rows: [10, 17],
            children: [
              {
                id: 'payload/~e/1',
                kind: 'text',
                label: '1',
                main: [8, '"coap://as.example.com"'],
                rows: [12, 13],
                key: {
                  id: 'payload/~e/1/~k',
                  kind: 'integer',
                  label: '1',
                  main: [8, '1'],
                  rows: [11, 12],
                },
                extras: { annotation: ann.cwtIss },
              },
              {
                id: 'payload/~e/2',
                kind: 'text',
                label: '2',
                main: [9, '"erikw"'],
                rows: [14, 15],
                key: {
                  id: 'payload/~e/2/~k',
                  kind: 'integer',
                  label: '2',
                  main: [9, '2'],
                  rows: [13, 14],
                },
                extras: { annotation: ann.cwtSub },
              },
              {
                id: 'payload/~e/4',
                kind: 'integer',
                label: '4',
                main: [10, '1444064944'],
                rows: [16, 17],
                key: {
                  id: 'payload/~e/4/~k',
                  kind: 'integer',
                  label: '4',
                  main: [10, '4'],
                  rows: [15, 16],
                },
                extras: {
                  annotation: ann.cwtExp,
                  time: {
                    epoch: 1444064944,
                    rfc3339: '2015-10-05T17:09:04Z',
                    relative: '4119 d 14 h ago',
                  },
                },
              },
            ],
          },
        ],
      },
      {
        id: 'signature',
        kind: 'bytes',
        label: 'signature',
        main: [12, "h'5427c1ff28d23fba'"],
        rows: [17, 18],
      },
    ],
  },
});

/** Variants of the CWT that differ only in kind and SD lists (enough for
 *  action enablement; the trees are the CWT's). */
function variant(kind: Kind, extra: Partial<Document> = {}): Document {
  return { ...structuredClone(cwt), kind, ...extra };
}

export const sdCwt: Document = variant(
  { type: 'sd_cwt' },
  {
    disclosures: [
      {
        index: 0,
        node_id: 'unprotected/17/0',
        digest: 'a1b2',
        salt: '8d5c15fa86265d8ff77a0e92720ca837',
        claim: '"region"',
        value: '"ca"',
        decoy: false,
        status: 'matched',
        slot: 'payload/~e/simple(59)/0',
      },
    ],
  },
);

export const sdKbt: Document = variant({ type: 'sd_kbt' });

export const coseSign1: Document = variant({ type: 'cose_sign1' });

// --- claim sets -----------------------------------------------------------------

export const JSON_CLAIMS = `{
  "iss": "https://issuer.example",
  "given_name": "Alice",
  "address": {
    "street": "1 Main St",
    "country": "DE"
  }
}`;

export const jsonClaims: Document = buildJsonClaims(JSON_CLAIMS, {
  iss: { annotation: ann.iss },
});

export const EDN_CLAIMS = `{
  / iss / 1: "iss.example",
  58(2): "erikw"
}`;

export const ednClaims: Document = {
  ...buildCose({
    kind: { type: 'edn_claims' },
    signed: false,
    edn: EDN_CLAIMS,
    rows: [
      ['', 0, 'a2', '', 'map(2)', null],
      ['1/~k', 1, '01', '', 'unsigned(1)', 'iss'],
      ['1', 1, '6b', asciiHex('iss.example'), 'text(11)', null],
      ['58(2)/~k', 1, 'd83a', '', 'tag(58)', null],
      ['58(2)/~k/~t', 2, '02', '', 'unsigned(2)', null],
      ['58(2)', 1, '65', asciiHex('erikw'), 'text(5)', null],
    ],
    tree: {
      id: '',
      kind: 'map',
      label: '',
      main: [
        [0, '{'],
        [3, '}'],
      ],
      rows: [0, 6],
      children: [
        {
          id: '1',
          kind: 'text',
          label: '1',
          main: [1, '"iss.example"'],
          rows: [2, 3],
          key: { id: '1/~k', kind: 'integer', label: '1', main: [1, '1'], rows: [1, 2] },
          extras: { annotation: ann.cwtIss },
        },
        {
          id: '58(2)',
          kind: 'text',
          label: '58(2)',
          main: [2, '"erikw"'],
          rows: [5, 6],
          key: { id: '58(2)/~k', kind: 'tag', label: '58(2)', main: [2, '58(2)'], rows: [3, 5] },
        },
      ],
    },
  }),
  // EDN claim sets keep their text as the document bytes (core TEST-PLAN §3).
  bytes: textToB64u(EDN_CLAIMS),
};

/** An EDN claim set with nothing marked for redaction. */
export const ednClaimsUnmarked: Document = {
  ...structuredClone(ednClaims),
  main: { ...ednClaims.main, text: EDN_CLAIMS.replace('58(2)', '2') },
};

// --- live edit results ----------------------------------------------------------

export const editStale: EditResult = {
  ok: true,
  bytes: jwtEdited.bytes,
  document: jwtEdited,
  signature_stale: true,
  diagnostics: [],
};

export const editUnchanged: EditResult = {
  ok: true,
  bytes: jwt.bytes,
  document: jwt,
  signature_stale: false,
  diagnostics: [],
};

export const editInvalid: EditResult = {
  ok: false,
  bytes: null,
  document: null,
  signature_stale: false,
  diagnostics: [
    {
      severity: 'error',
      code: 'json.syntax',
      message: 'expected `,` or `}` after an object member',
      node_id: null,
      main: { start: 60, end: 61, line_start: 3, line_end: 4 },
      raw: null,
    },
  ],
};
