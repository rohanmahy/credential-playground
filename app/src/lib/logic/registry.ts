// "Update registries" (SPEC §7): user-confirmed fetches of the IANA XML,
// merged over the snapshot by the engine, then cached (the one persisted
// artifact). The engine picks the cached snapshot up at the next start.
import type { Engine } from '../engine/Engine';
import type { RegistryId, RegistryStats } from '../engine/types';
import type { Platform } from '../platform/Platform';
import { fromB64u, toB64u } from '../engine/bytes';
import { confirmedFetch, type Confirm } from './fetch';

export const IANA_REGISTRIES: readonly { which: RegistryId; url: string }[] = [
  { which: 'cwt', url: 'https://www.iana.org/assignments/cwt/cwt.xml' },
  { which: 'cose', url: 'https://www.iana.org/assignments/cose/cose.xml' },
  { which: 'jwt', url: 'https://www.iana.org/assignments/jwt/jwt.xml' },
  { which: 'jose', url: 'https://www.iana.org/assignments/jose/jose.xml' },
];

export type RegistryUpdate =
  | { type: 'updated'; stats: { which: RegistryId; stats: RegistryStats }[] }
  | { type: 'cancelled' }
  | { type: 'error'; explanation: string };

/** `confirm` is asked once with every URL (newline-separated); nothing is
 *  fetched unless it resolves true. */
export async function updateRegistries(
  engine: Engine,
  platform: Platform,
  confirm: Confirm,
): Promise<RegistryUpdate> {
  if (!(await confirm(IANA_REGISTRIES.map((r) => r.url).join('\n')))) return { type: 'cancelled' };
  const cached = await platform.registryCache.get().catch(() => null);
  let snapshot = cached ? toB64u(cached) : null;
  const stats: { which: RegistryId; stats: RegistryStats }[] = [];
  for (const { which, url } of IANA_REGISTRIES) {
    const outcome = await confirmedFetch(platform, url, async () => true);
    if (outcome.type === 'error') return { type: 'error', explanation: outcome.explanation };
    if (outcome.type !== 'ok') return { type: 'cancelled' };
    const merged = await engine.registryMerge({
      base_snapshot: snapshot,
      xml: toB64u(outcome.result.bytes),
      which,
    });
    snapshot = merged.snapshot;
    stats.push({ which, stats: merged.stats });
  }
  if (snapshot) await platform.registryCache.put(fromB64u(snapshot));
  return { type: 'updated', stats };
}
