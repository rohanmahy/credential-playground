// Key panel helpers.
import type { KeySpec, KidValue } from '../engine/types';
import { notImplemented } from '../notImplemented';

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

/** A kid for display: text as is, bytes as `h'…'`. */
export function kidText(_kid: KidValue | null): string {
  notImplemented('kidText');
}
