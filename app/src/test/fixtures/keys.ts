// Key cards and key DTOs.
import type { KeyExport, KeyInfo, Thumbprint } from '../../lib/engine/types';
import type { KeyCard } from '../../lib/model';
import { textToB64u } from '../../lib/engine/bytes';

export const ISSUER_JWK =
  '{"kty":"EC","crv":"P-256","kid":"issuer-1","x":"WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis","y":"y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE","d":"Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvEPqg"}';
export const HOLDER_JWK =
  '{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}';
export const VERIFIER_JWK =
  '{"kty":"EC","crv":"P-256","kid":"issuer-1","x":"WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis","y":"y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"}';

function info(jwk: string, overrides: Partial<KeyInfo>): KeyInfo {
  return {
    key: { bytes: textToB64u(jwk), format: { type: 'jwk' }, index: 0, role: null, label: null },
    kty: 'EC',
    crv: 'P-256',
    bits: null,
    param_set: null,
    description: 'EC P-256',
    private: true,
    kid: null,
    alg: null,
    algs: ['ES256'],
    role: null,
    jwk_thumbprint: 'oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U',
    jwk_thumbprint_uri:
      'urn:ietf:params:oauth:jwk-thumbprint:sha-256:oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U',
    cose_thumbprint: '496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec',
    cose_thumbprint_uri:
      'urn:ietf:params:oauth:ckt:sha-256:SWvYr63zB-WwjGSwQhv53AFSijRKQ72oj63RZp2iU-w',
    ...overrides,
  };
}

export const issuerInfo: KeyInfo = info(ISSUER_JWK, {
  kid: { type: 'text', value: 'issuer-1' },
  role: 'issuer',
});

export const holderInfo: KeyInfo = info(HOLDER_JWK, {
  kty: 'OKP',
  crv: 'Ed25519',
  description: 'Ed25519',
  algs: ['EdDSA', 'Ed25519'],
  role: 'holder',
  jwk_thumbprint: 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k',
  jwk_thumbprint_uri:
    'urn:ietf:params:oauth:jwk-thumbprint:sha-256:kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k',
  cose_thumbprint: 'ab6c3a4e1f3a4f7b8d0e2c1f9a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b',
  cose_thumbprint_uri:
    'urn:ietf:params:oauth:ckt:sha-256:q2w6Th86T3uNDiwfmntsXU4_KhsMnY5_alq0w9Lh8Kk',
});

export const verifierInfo: KeyInfo = info(VERIFIER_JWK, {
  private: false,
  kid: { type: 'text', value: 'issuer-1' },
  role: 'verifier',
});

/** A freshly generated ML-DSA-44 key (no kid). */
export const mlDsaInfo: KeyInfo = info(
  '{"kty":"AKP","alg":"ML-DSA-44","pub":"cHVi","priv":"cHJpdg"}',
  {
    kty: 'AKP',
    crv: null,
    param_set: 'ML-DSA-44',
    description: 'ML-DSA-44',
    alg: 'ML-DSA-44',
    algs: ['ML-DSA-44'],
  },
);

export const issuerCard: KeyCard = {
  id: 'key-1',
  label: 'Issuer P-256',
  role: 'issuer',
  info: issuerInfo,
  provenance: { type: 'generated' },
};

export const holderCard: KeyCard = {
  id: 'key-2',
  label: 'Holder Ed25519',
  role: 'holder',
  info: holderInfo,
  provenance: { type: 'file', name: 'holder.jwk.json' },
};

export const verifierCard: KeyCard = {
  id: 'key-3',
  label: 'Verifier P-256',
  role: 'verifier',
  info: verifierInfo,
  provenance: { type: 'pasted' },
};

/** An issuer-role card that only has the public key. */
export const publicIssuerCard: KeyCard = {
  ...verifierCard,
  id: 'key-4',
  label: 'Issuer (public only)',
  role: 'issuer',
};

export const publicExport: KeyExport = {
  bytes: textToB64u(VERIFIER_JWK),
  text: VERIFIER_JWK,
  private: false,
};
export const privateExport: KeyExport = {
  bytes: textToB64u(ISSUER_JWK),
  text: ISSUER_JWK,
  private: true,
};

export const jwkThumbprint: Thumbprint = {
  kind: 'jwk',
  hash: 'sha256',
  hex: 'a0a232c2f194a53553cb1310ddbc0821e414b9d7ebfc290b323084d7d1020fe5',
  base64url: 'oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U',
  uri: 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U',
};

export const coseThumbprint: Thumbprint = {
  kind: 'cose',
  hash: 'sha256',
  hex: '496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec',
  base64url: 'SWvYr63zB-WwjGSwQhv53AFSijRKQ72oj63RZp2iU-w',
  uri: 'urn:ietf:params:oauth:ckt:sha-256:SWvYr63zB-WwjGSwQhv53AFSijRKQ72oj63RZp2iU-w',
};

/** key_to_cwk of the issuer key: a COSE_Key document (EDN + hex). */
export const ISSUER_CWK_EDN = `{
  / kty / 1: 2 / EC2 /,
  / kid / 2: 'issuer-1',
  / crv / -1: 1 / P-256 /,
  / x / -2: h'58a9fe64819ebdcc06232cabcc5a1934175aabdfd3b2acc697dea8734096ba2b',
  / y / -3: h'cbbeedf91bc01d1293b1219d21851fc1eb8ebf0aef0c3f90dc7bf92747d229b1'
}`;
