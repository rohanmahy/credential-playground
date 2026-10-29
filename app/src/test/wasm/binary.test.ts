// Checks on the built module itself (crates/tokenator-wasm/TEST-PLAN.md §1):
// the binding surface, the stack size from build.rs (#27), no ambient
// randomness or clock, the size budget, and panics surfacing as errors.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { beforeAll, describe, expect, it } from 'vitest';
import { initSync, TokenatorEngine } from 'tokenator-wasm';
import { METHODS, PKG, REPO, wasmBytes } from './helpers';

/** Size budget of the release .wasm (measured ~2.9 MB raw, ~0.9 MB gzip). */
const MAX_RAW = 3.5 * 1024 * 1024;
const MAX_GZIP = 1.1 * 1024 * 1024;

const bytes = wasmBytes();

/** Initial values of the module's globals (the global section, id 6). */
function globals(wasm: Uint8Array): { mutable: boolean; value: number }[] {
  let p = 8;
  const u32 = (): number => {
    let r = 0;
    let s = 0;
    let b: number;
    do {
      b = wasm[p++] ?? 0;
      r |= (b & 0x7f) << s;
      s += 7;
    } while (b & 0x80);
    return r >>> 0;
  };
  const i32 = (): number => {
    let r = 0;
    let s = 0;
    let b: number;
    do {
      b = wasm[p++] ?? 0;
      r |= (b & 0x7f) << s;
      s += 7;
    } while (b & 0x80);
    return s < 32 && b & 0x40 ? r | (-1 << s) : r;
  };
  while (p < wasm.length) {
    const id = wasm[p++] ?? 0;
    const len = u32();
    const end = p + len;
    if (id === 6) {
      const out = [];
      for (let n = u32(); n > 0; n--) {
        p++; // value type
        const mutable = wasm[p++] === 1;
        const op = wasm[p++];
        out.push({ mutable, value: op === 0x41 ? i32() : NaN });
        while (wasm[p - 1] !== 0x0b) p++; // to the `end` of the init expression
      }
      return out;
    }
    p = end;
  }
  return [];
}

/** STACK_SIZE in build.rs, written as `N * 1024 * 1024`. */
function configuredStack(): number {
  const src = readFileSync(join(REPO, 'crates/tokenator-wasm/build.rs'), 'utf8');
  const m = /const STACK_SIZE: u32 = (\d+) \* 1024 \* 1024;/.exec(src);
  expect(m, 'STACK_SIZE in build.rs').not.toBeNull();
  return Number(m?.[1]) * 1024 * 1024;
}

describe('the release module', () => {
  beforeAll(() => {
    initSync({ module: bytes });
  });

  it('runs on the stack size set in build.rs (#27)', () => {
    const stack = configuredStack();
    expect(stack).toBeGreaterThanOrEqual(1024 * 1024);
    // rustc places the stack first: __stack_pointer (the first mutable
    // global) starts at the top of the stack region.
    const sp = globals(bytes).find((g) => g.mutable);
    expect(sp?.value).toBe(stack);
  });

  it('imports nothing but the wasm-bindgen glue: no randomness, clock, or network', () => {
    const imports = WebAssembly.Module.imports(new WebAssembly.Module(bytes));
    for (const i of imports) {
      expect(i.module).toBe('./tokenator_wasm_bg.js');
      expect(i.name).not.toMatch(/random|crypto|getrandom|date|now|performance|fetch|xmlhttp/i);
    }
    const glue = readFileSync(join(PKG, 'tokenator_wasm.js'), 'utf8');
    expect(glue).not.toMatch(/getRandomValues|randomFillSync|Date\.now|performance\.now/);
  });

  it('stays within the size budget', () => {
    const gz = gzipSync(bytes, { level: 9 }).length;
    console.info(`tokenator_wasm_bg.wasm: ${bytes.length} bytes, ${gz} gzipped`);
    expect(bytes.length).toBeLessThanOrEqual(MAX_RAW);
    expect(gz).toBeLessThanOrEqual(MAX_GZIP);
  });

  it('exports one TokenatorEngine method per Engine method, as declared in tokenator-wasm.d.ts', () => {
    const own = Object.getOwnPropertyNames(TokenatorEngine.prototype).filter(
      (n) =>
        n !== 'constructor' &&
        n !== 'free' &&
        n !== '__destroy_into_raw' &&
        !n.startsWith('Symbol'),
    );
    expect(own.sort()).toEqual([...METHODS, 'panic_for_tests'].sort());
    const declared = readFileSync(join(REPO, 'app/src/lib/engine/tokenator-wasm.d.ts'), 'utf8');
    const generated = readFileSync(join(PKG, 'tokenator_wasm.d.ts'), 'utf8');
    for (const m of [...METHODS, 'panic_for_tests']) {
      expect(declared, `tokenator-wasm.d.ts declares ${m}`).toMatch(new RegExp(`\\b${m}\\(`));
      expect(generated, `pkg declares ${m}`).toMatch(new RegExp(`\\b${m}\\(`));
    }
  });

  it('every method returns an envelope string', () => {
    const engine = new TokenatorEngine();
    const info = engine.info();
    expect(typeof info).toBe('string');
    expect(Object.keys(JSON.parse(info) as object)).toEqual(['ok']);
    const err = JSON.parse(engine.render('{not json')) as { err: { code: string } };
    expect(err.err.code).toBe('invalid_input');
    engine.free();
  });

  it('a bad snapshot makes the constructor throw the err envelope text', () => {
    let thrown: unknown;
    try {
      new TokenatorEngine(Uint8Array.of(1, 2, 3));
    } catch (e) {
      thrown = e;
    }
    expect(typeof thrown).toBe('string');
    expect((JSON.parse(thrown as string) as { err: { code: string } }).err.code).toBe('registry');
  });

  it('a panic surfaces as a thrown WebAssembly.RuntimeError, never a silent result', () => {
    const engine = new TokenatorEngine();
    expect(() => engine.panic_for_tests('boom')).toThrow(WebAssembly.RuntimeError);
    // The same object keeps working afterwards.
    expect(JSON.parse(engine.info())).toHaveProperty('ok');
  });
});
