// The registry cache in IndexedDB: the ONLY persistent storage the web app
// uses (SPEC §1). A static test fails if any other source file mentions
// browser storage APIs.
import type { RegistryCache } from './Platform';

export const REGISTRY_DB = 'tokenator-registry';
export const REGISTRY_STORE = 'snapshot';
const KEY = 'current';

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB request failed'));
  });
}

/** IndexedDB database `tokenator-registry`, store `snapshot`, one key. */
export class IndexedDbRegistryCache implements RegistryCache {
  #db: Promise<IDBDatabase> | null = null;

  #open(): Promise<IDBDatabase> {
    this.#db ??= new Promise((resolve, reject) => {
      const req = indexedDB.open(REGISTRY_DB, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(REGISTRY_STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error ?? new Error('cannot open the registry cache'));
    });
    return this.#db;
  }

  async #store(mode: IDBTransactionMode): Promise<IDBObjectStore> {
    const db = await this.#open();
    return db.transaction(REGISTRY_STORE, mode).objectStore(REGISTRY_STORE);
  }

  async get(): Promise<Uint8Array | null> {
    const value: unknown = await request((await this.#store('readonly')).get(KEY));
    // Structured clones may come from another realm, so no `instanceof`.
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice();
    }
    return null;
  }

  async put(snapshot: Uint8Array): Promise<void> {
    await request((await this.#store('readwrite')).put(snapshot.slice(), KEY));
  }

  async clear(): Promise<void> {
    await request((await this.#store('readwrite')).delete(KEY));
  }
}
