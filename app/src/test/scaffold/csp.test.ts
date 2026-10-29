// @vitest-environment node
// The production build's CSP restricts scripts to the app's own origin
// (SPEC §9). Builds into a temporary directory.
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { build } from 'vite';

const appDir = join(import.meta.dirname, '../../..');
let outDir = '';
let html = '';

function directives(policy: string): Map<string, string[]> {
  return new Map(
    policy
      .split(';')
      .map((d) => d.trim().split(/\s+/))
      .filter((d) => d[0])
      .map(([name, ...values]) => [name ?? '', values]),
  );
}

describe('production CSP', () => {
  beforeAll(async () => {
    outDir = mkdtempSync(join(tmpdir(), 'tokenator-csp-'));
    await build({
      root: appDir,
      configFile: join(appDir, 'vite.config.ts'),
      logLevel: 'silent',
      build: { outDir, emptyOutDir: true },
    });
    html = readFileSync(join(outDir, 'index.html'), 'utf8');
  }, 120_000);

  afterAll(() => {
    if (outDir) rmSync(outDir, { recursive: true, force: true });
  });

  it('has exactly one CSP meta, first in <head>', () => {
    const metas = html.match(/<meta[^>]+http-equiv="Content-Security-Policy"[^>]*>/g) ?? [];
    expect(metas).toHaveLength(1);
    expect(html.indexOf('Content-Security-Policy')).toBeLessThan(html.indexOf('<script'));
  });

  it("restricts script-src to 'self' (plus wasm compilation)", () => {
    const content =
      /http-equiv="Content-Security-Policy"\s+content="([^"]+)"/.exec(html)?.[1] ?? '';
    const policy = directives(content.replace(/&#39;/g, "'"));
    expect(policy.get('script-src')).toEqual(["'self'", "'wasm-unsafe-eval'"]);
    expect(policy.get('default-src')).toEqual(["'self'"]);
    expect(policy.get('object-src')).toEqual(["'none'"]);
    expect(policy.get('base-uri')).toEqual(["'none'"]);
    for (const [name, values] of policy) {
      if (name === 'style-src') continue;
      expect(values, name).not.toContain("'unsafe-inline'");
      expect(values, name).not.toContain("'unsafe-eval'");
      expect(values, name).not.toContain('*');
    }
  });

  it("limits connect-src to 'self' and https: (user-confirmed fetches)", () => {
    // https: is the SPEC §9 tradeoff: arbitrary key URLs (kid, jwt-vc-issuer
    // metadata) and https://www.iana.org for Update registries, all fetched
    // only after the user confirms. Nothing else: no http:, ws:, data:, blob:.
    const content =
      /http-equiv="Content-Security-Policy"\s+content="([^"]+)"/.exec(html)?.[1] ?? '';
    const policy = directives(content.replace(/&#39;/g, "'"));
    expect(policy.get('connect-src')).toEqual(["'self'", 'https:']);
    expect(policy.get('worker-src')).toEqual(["'self'"]);
  });

  it('has no inline scripts and loads scripts from its own origin', () => {
    const scripts = html.match(/<script\b[^>]*>/g) ?? [];
    expect(scripts.length).toBeGreaterThan(0);
    for (const s of scripts) expect(s).toMatch(/\ssrc="\.\/assets\//);
    expect(html).not.toMatch(/<script\b[^>]*>\s*[^<\s]/);
    expect(html).not.toMatch(/https?:\/\//);
  });
});
