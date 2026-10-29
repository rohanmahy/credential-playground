// The production build bundles the real module (not the unit-test stand-in)
// as a same-origin asset, and the CSP still allows compiling it.
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { build } from 'vite';
import { WASM_FILE } from './helpers';

const appDir = join(import.meta.dirname, '../../..');
let outDir = '';

describe('vite build with the wasm package', () => {
  beforeAll(async () => {
    outDir = mkdtempSync(join(tmpdir(), 'tokenator-wasm-build-'));
    await build({
      root: appDir,
      configFile: join(appDir, 'vite.config.ts'),
      logLevel: 'silent',
      build: { outDir, emptyOutDir: true },
    });
  }, 180_000);

  afterAll(() => {
    if (outDir) rmSync(outDir, { recursive: true, force: true });
  });

  it('emits the release .wasm byte for byte as an asset', () => {
    const assets = readdirSync(join(outDir, 'assets'));
    const wasm = assets.filter((f) => f.endsWith('.wasm'));
    expect(wasm).toHaveLength(1);
    expect(
      readFileSync(join(outDir, 'assets', wasm[0] ?? '')).equals(readFileSync(WASM_FILE)),
    ).toBe(true);
  });

  it('does not bundle the unit-test stand-in, and the glue loads the asset', () => {
    const assets = readdirSync(join(outDir, 'assets'));
    const js = assets
      .filter((f) => f.endsWith('.js'))
      .map((f) => readFileSync(join(outDir, 'assets', f), 'utf8'))
      .join('\n');
    expect(js).not.toContain('tokenator-wasm is not built');
    const wasm = assets.find((f) => f.endsWith('.wasm'));
    expect(wasm, 'a .wasm asset').toBeDefined();
    expect(js).toContain(wasm);
  });

  it("keeps 'wasm-unsafe-eval' (not 'unsafe-eval') in script-src", () => {
    const html = readFileSync(join(outDir, 'index.html'), 'utf8').replace(/&#39;/g, "'");
    const csp = /http-equiv="Content-Security-Policy"\s+content="([^"]+)"/.exec(html)?.[1] ?? '';
    const scriptSrc = /script-src ([^;]+)/.exec(csp)?.[1]?.split(/\s+/) ?? [];
    expect(scriptSrc).toContain("'wasm-unsafe-eval'");
    expect(scriptSrc).not.toContain("'unsafe-eval'");
  });
});
