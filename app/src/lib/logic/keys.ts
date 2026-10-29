// Key panel helpers.
import type { KeyFormat, KeySpec, KidValue } from '../engine/types';
import { fromB64u } from '../engine/bytes';

/** Every algorithm the panel can create, in menu order (SPEC §4.2). */
export const KEY_SPECS: readonly { spec: KeySpec; label: string }[] = [
  { spec: { type: 'p256' }, label: 'EC P-256' },
  { spec: { type: 'p384' }, label: 'EC P-384' },
  { spec: { type: 'p521' }, label: 'EC P-521' },
  { spec: { type: 'ed25519' }, label: 'Ed25519' },
  { spec: { type: 'rsa', bits: 2048 }, label: 'RSA 2048' },
  { spec: { type: 'rsa', bits: 3072 }, label: 'RSA 3072' },
  { spec: { type: 'rsa', bits: 4096 }, label: 'RSA 4096' },
  { spec: { type: 'ml_dsa44' }, label: 'ML-DSA-44' },
  { spec: { type: 'ml_dsa65' }, label: 'ML-DSA-65' },
  { spec: { type: 'ml_dsa87' }, label: 'ML-DSA-87' },
];

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** A kid for display: text as is, bytes as `h'…'`. */
export function kidText(kid: KidValue | null): string {
  if (!kid) return '';
  if (kid.type === 'text') return kid.value;
  try {
    return `h'${hex(fromB64u(kid.value))}'`;
  } catch {
    return kid.value;
  }
}

/** Export formats, in menu order. */
export const EXPORT_FORMATS: readonly { id: string; label: string; format: KeyFormat }[] = [
  { id: 'jwk', label: 'JWK', format: { type: 'jwk' } },
  { id: 'jwk_set', label: 'JWK Set', format: { type: 'jwk_set' } },
  { id: 'cose_key', label: 'COSE_Key', format: { type: 'cose_key' } },
  { id: 'cose_key_set', label: 'COSE_KeySet', format: { type: 'cose_key_set' } },
  { id: 'pem', label: 'PEM (SPKI / PKCS#8)', format: { type: 'pem', encoding: 'auto' } },
  {
    id: 'pem_sec1',
    label: 'PEM (SEC1, EC private keys)',
    format: { type: 'pem', encoding: 'sec1' },
  },
  { id: 'pem_pkcs1', label: 'PEM (PKCS#1, RSA)', format: { type: 'pem', encoding: 'pkcs1' } },
  {
    id: 'pem_ml_dsa_seed',
    label: 'PEM (ML-DSA seed)',
    format: { type: 'pem', encoding: 'pkcs8_ml_dsa_seed' },
  },
  {
    id: 'pem_ml_dsa_expanded',
    label: 'PEM (ML-DSA expanded)',
    format: { type: 'pem', encoding: 'pkcs8_ml_dsa_expanded' },
  },
  {
    id: 'pem_ml_dsa_both',
    label: 'PEM (ML-DSA seed and expanded)',
    format: { type: 'pem', encoding: 'pkcs8_ml_dsa_both' },
  },
];

/** A file name for an export: `<label>.<ext>`. */
export function exportFileName(label: string, format: KeyFormat, isPrivate: boolean): string {
  const base = label.replace(/[^\w.-]+/g, '-').replace(/^-+|-+$/g, '') || 'key';
  const suffix = isPrivate ? '.private' : '';
  switch (format.type) {
    case 'jwk':
      return `${base}${suffix}.jwk.json`;
    case 'jwk_set':
      return `${base}${suffix}.jwks.json`;
    case 'cose_key':
      return `${base}${suffix}.cose_key.cbor`;
    case 'cose_key_set':
      return `${base}${suffix}.cose_keyset.cbor`;
    case 'pem':
      return `${base}${suffix}.pem`;
  }
}
