// Paths and the app environment, shared by wdio.conf.ts and the specs.
import { mkdirSync, readdirSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

const target = resolve(
  process.env['CARGO_TARGET_DIR'] ?? join(import.meta.dirname, '../../target'),
);

/** The binary the suite drives: built without incognito (build.mjs). */
export const application = resolve(
  process.env['TOKENATOR_BIN'] ?? join(target, 'desktop-e2e/tokenator'),
);

/** The binary with the shipped tauri.conf.json (build.mjs). */
export const shippedApplication = resolve(
  process.env['TOKENATOR_SHIPPED_BIN'] ?? join(target, 'release/tokenator'),
);

export const IDENTIFIER = 'io.github.rohanmahy.tokenator';

/** The app data dir (Tauri's and WebKitGTK's), relative to HOME. */
export const DATA_DIR = `.local/share/${IDENTIFIER}`;

/** The shell's one file (src-tauri/src/cache.rs). */
export const REGISTRY_CACHE = `${DATA_DIR}/registry-snapshot.bin`;

/** `env` with HOME and the XDG dirs moved into `home` (created). */
export function appEnv(home: string, env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const xdg = {
    HOME: home,
    XDG_DATA_HOME: join(home, '.local/share'),
    XDG_CONFIG_HOME: join(home, '.config'),
    XDG_CACHE_HOME: join(home, '.cache'),
  };
  for (const dir of Object.values(xdg)) mkdirSync(dir, { recursive: true });
  // No accessibility bus under Xvfb; without this GTK waits for one.
  return { ...env, ...xdg, NO_AT_BRIDGE: '1' };
}

/** Every file under `dir`, relative to it, sorted. */
export function filesUnder(dir: string): string[] {
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => !e.isDirectory())
    .map((e) => relative(dir, join(e.parentPath, e.name)))
    .sort();
}

/** Caches that GTK, fontconfig, and Mesa keep for any program. */
export function isSystemCache(file: string): boolean {
  return /^\.cache\/(dconf|fontconfig|mesa_shader_cache)\//.test(file);
}

/**
 * WebKitGTK's own bookkeeping in the app data dir, which it creates for
 * any web context (even with `incognito`; Tauri also makes a persistent
 * context): salts, the HSTS database, and a per-origin directory holding
 * just the origin's name. Local storage, IndexedDB, Cache API data,
 * cookies, or HTTP cache records would be other files.
 */
export function isWebKitBookkeeping(file: string): boolean {
  const rest = file.startsWith(`${DATA_DIR}/`) ? file.slice(DATA_DIR.length + 1) : null;
  return (
    rest !== null &&
    /^(hsts-storage\.sqlite|(CacheStorage|storage|mediakeys\/v1|WebKitCache\/Version \d+)\/salt|storage\/[\w-]+\/[\w-]+\/origin)$/.test(
      rest,
    )
  );
}
