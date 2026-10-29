// NEVER-PERSIST (SPEC §1): nothing but the registry cache is written to
// browser storage.
import 'fake-indexeddb/auto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { utf8 } from '../../lib/engine/bytes';
import { IndexedDbRegistryCache, REGISTRY_DB } from '../../lib/platform/registryCache';
import * as fx from '../fixtures';
import { seedKeys, setupApp } from '../render';

const srcDir = join(import.meta.dirname, '../..');

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return name === 'test' ? [] : sources(path);
    return /\.(ts|svelte)$/.test(name) ? [path] : [];
  });
}

describe('static scan', () => {
  it('only registryCache.ts mentions browser storage', () => {
    const offenders = sources(srcDir)
      .filter((f) => !f.endsWith('platform/registryCache.ts'))
      .filter((f) =>
        /localStorage|sessionStorage|indexedDB|document\.cookie|caches\.open/.test(
          readFileSync(f, 'utf8'),
        ),
      )
      .map((f) => relative(srcDir, f));
    expect(offenders).toEqual([]);
  });

  it('only WebPlatform calls fetch (no third-party network calls)', () => {
    const offenders = sources(srcDir)
      .filter((f) => !f.endsWith('platform/WebPlatform.ts'))
      .filter((f) =>
        /\bfetch\s*\(|XMLHttpRequest|WebSocket|sendBeacon|EventSource/.test(
          readFileSync(f, 'utf8'),
        ),
      )
      .map((f) => relative(srcDir, f));
    expect(offenders).toEqual([]);
  });
});

describe('runtime', () => {
  let spies: ReturnType<typeof vi.spyOn>[] = [];
  let idbOpen: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    spies = [vi.spyOn(Storage.prototype, 'setItem'), vi.spyOn(Storage.prototype, 'getItem')];
    idbOpen = vi.spyOn(indexedDB, 'open');
  });

  afterEach(() => {
    for (const s of spies) s.mockRestore();
    idbOpen.mockRestore();
  });

  it('writes nothing during open, edit, validate, key create/export, and settings changes', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard);
    const opened = await app.workspace.openInput(utf8(fx.jwtToken), { type: 'pasted' });
    if (opened.type !== 'tab') throw new Error(opened.type);
    app.workspace.setLiveEdit(opened.tabId, true);
    await app.workspace.applyEdit(opened.tabId, fx.jwtEdited.main.text);
    await app.workspace.validate(opened.tabId);
    const card = await app.keys.generate({ type: 'p256' }, { seed: { type: 'random' } });
    await app.keys.copyToClipboard(card.id, { type: 'jwk' }, 'private');
    app.settings.clockOverride = 1;
    app.settings.theme = 'dark';
    app.settings.skew = 5;
    expect(Storage.prototype.setItem).not.toHaveBeenCalled();
    expect(idbOpen).not.toHaveBeenCalled();
    expect(document.cookie).toBe('');
  });

  it('the registry cache is the one thing stored, in IndexedDB', async () => {
    const cache = new IndexedDbRegistryCache();
    const snapshot = Uint8Array.of(1, 2, 3);
    await cache.put(snapshot);
    expect(idbOpen).toHaveBeenCalledWith(REGISTRY_DB, expect.anything());
    expect([...((await cache.get()) ?? [])]).toEqual([1, 2, 3]);
    await cache.clear();
    expect(await cache.get()).toBeNull();
    expect(Storage.prototype.setItem).not.toHaveBeenCalled();
  });
});
