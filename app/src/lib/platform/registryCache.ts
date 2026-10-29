// The registry cache in IndexedDB: the ONLY persistent storage the web app
// uses (SPEC §1). A static test fails if any other source file mentions
// browser storage APIs.
import type { RegistryCache } from './Platform';
import { notImplemented } from '../notImplemented';

export const REGISTRY_DB = 'tokenator-registry';
export const REGISTRY_STORE = 'snapshot';

/** IndexedDB database `tokenator-registry`, store `snapshot`, one key. */
export class IndexedDbRegistryCache implements RegistryCache {
  async get(): Promise<Uint8Array | null> {
    notImplemented('IndexedDbRegistryCache.get');
  }

  async put(_snapshot: Uint8Array): Promise<void> {
    notImplemented('IndexedDbRegistryCache.put');
  }

  async clear(): Promise<void> {
    notImplemented('IndexedDbRegistryCache.clear');
  }
}
