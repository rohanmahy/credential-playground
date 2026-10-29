// Detection candidates.
import type { Candidate, Kind, Layer } from '../../lib/engine/types';
import { jwtToken } from './documents';

function candidate(
  kind: Kind,
  confidence: number,
  breadcrumb: string[],
  layers: Layer[] = [],
  length = jwtToken.length,
): Candidate {
  return { kind, confidence, layers, payload_range: { start: 0, end: length }, breadcrumb };
}

export const jwtCandidates: Candidate[] = [candidate({ type: 'jwt' }, 95, ['JWT'])];

/** `Authorization: Bearer <jwt>` */
export const bearerCandidates: Candidate[] = [
  candidate(
    { type: 'jwt' },
    95,
    ['Authorization header', 'Bearer', 'JWT'],
    [
      { type: 'authorization_header', prefix: 'Authorization: ' },
      { type: 'bearer_prefix', prefix: 'Bearer ' },
    ],
  ),
];

/** `{"credential": "<jwt>", "id_token": "<sd-jwt>"}`: two token fields. */
export const containerCandidates: Candidate[] = [
  candidate(
    { type: 'jwt' },
    80,
    ['JSON field credential', 'JWT'],
    [{ type: 'json_field', path: ['credential'] }],
  ),
  candidate(
    { type: 'sd_jwt', kb: false },
    75,
    ['JSON field id_token', 'SD-JWT'],
    [{ type: 'json_field', path: ['id_token'] }],
  ),
];

export const cwtHexCandidates: Candidate[] = [
  candidate(
    { type: 'cwt' },
    90,
    ['hex', 'CWT'],
    [{ type: 'hex', upper: false, separator: null, wrap: null }],
  ),
  candidate({ type: 'json_claims' }, 10, ['JSON claim set']),
];

export const jwkCandidates: Candidate[] = [candidate({ type: 'jwk' }, 95, ['JWK'])];

export const claimsCandidates: Candidate[] = [
  candidate({ type: 'json_claims' }, 90, ['JSON claim set']),
];
