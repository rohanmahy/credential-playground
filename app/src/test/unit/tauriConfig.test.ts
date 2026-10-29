// @vitest-environment node
// The desktop CSP (src-tauri/tauri.conf.json) is the web CSP
// (csp.config.ts) with only the differences native commands allow, and the
// TS side of the IPC logs nothing (private keys cross it).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { CSP_DIRECTIVES } from '../../../csp.config';

const appDir = join(import.meta.dirname, '../../..');

function tauriCsp(): Record<string, string[]> {
  const conf = JSON.parse(readFileSync(join(appDir, 'src-tauri/tauri.conf.json'), 'utf8'));
  return conf.app.security.csp;
}

describe('Tauri CSP', () => {
  it('equals the web CSP except script-src, connect-src, and frame-ancestors', () => {
    const expected: Record<string, readonly string[]> = {
      ...CSP_DIRECTIVES,
      // No WebAssembly on the desktop: the engine is native.
      'script-src': ["'self'"],
      // No fetch() from the webview: fetch_url runs in Rust. Only Tauri IPC.
      'connect-src': ['ipc:', 'http://ipc.localhost'],
      // Enforceable here (a real header, unlike the web's <meta> CSP).
      'frame-ancestors': ["'none'"],
    };
    expect(tauriCsp()).toEqual(expected);
  });

  it('has no network or eval sources', () => {
    for (const [name, values] of Object.entries(tauriCsp())) {
      for (const banned of ['https:', 'http:', '*', "'unsafe-eval'", "'wasm-unsafe-eval'"]) {
        expect(values, name).not.toContain(banned);
      }
    }
  });
});

describe('IPC wrappers', () => {
  it('TauriEngine and TauriPlatform never log', () => {
    for (const file of ['src/lib/engine/TauriEngine.ts', 'src/lib/platform/TauriPlatform.ts']) {
      const text = readFileSync(join(appDir, file), 'utf8');
      expect(text, file).not.toMatch(/\bconsole\./);
    }
  });

  it('use invoke from @tauri-apps/api/core only (no global __TAURI__)', () => {
    for (const file of ['src/lib/engine/TauriEngine.ts', 'src/lib/platform/TauriPlatform.ts']) {
      const text = readFileSync(join(appDir, file), 'utf8');
      expect(text, file).toMatch(/from '@tauri-apps\/api\/core'/);
      expect(text, file).not.toMatch(/window\.__TAURI__\b/);
      expect(text, file).not.toMatch(/@tauri-apps\/plugin-/);
    }
  });
});
