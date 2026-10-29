// The wasm half of the parity suite (SPEC §11): every case in
// testdata/parity, run through the release wasm module's bindings, must
// return exactly the envelope text the native engine wrote (byte for
// byte, or the same SHA-256 and length for digest goldens). Cases tagged
// `stack` are the #27 stack audit: they must not trap under the stack
// size set in crates/tokenator-wasm/build.rs.
import { beforeAll, describe, expect, it } from 'vitest';
import { initSync, TokenatorEngine } from 'tokenator-wasm';
import { METHODS, bindingArgs, mismatch, readCorpus, wasmBytes, type CorpusEntry } from './helpers';

const corpus = readCorpus();
let engine: TokenatorEngine | undefined;

beforeAll(() => {
  initSync({ module: wasmBytes() });
});

function run(entry: CorpusEntry): void {
  // Built here, so a failing constructor fails every case, not the file.
  engine ??= new TokenatorEngine();
  const binding = (engine as unknown as Record<string, (...a: unknown[]) => unknown>)[
    entry.case.method
  ];
  expect(binding, `binding ${entry.case.method}`).toBeTypeOf('function');
  if (!binding) return expect.fail(`no binding ${entry.case.method}`);
  const out = binding.apply(engine, bindingArgs(entry.case));
  expect(out).toBeTypeOf('string');
  const why = mismatch(out as string, entry.golden);
  if (why) expect.fail(`${entry.id} (${entry.case.source}): ${why}`);
}

describe('corpus', () => {
  it('has cases for every Engine method, from testdata/parity', () => {
    expect(corpus.length).toBeGreaterThan(400);
    const methods = new Set(corpus.map((e) => e.case.method));
    expect([...methods].sort()).toEqual([...METHODS].sort());
    expect(corpus.filter((e) => e.case.stack).length).toBeGreaterThanOrEqual(16);
  });
});

describe('wasm output is byte-identical to the native goldens', () => {
  for (const entry of corpus.filter((e) => !e.case.stack)) {
    it(entry.id, () => run(entry));
  }
});

describe('stack audit (#27): deep and heavy cases run in the release build', () => {
  for (const entry of corpus.filter((e) => e.case.stack)) {
    it(entry.id, { timeout: 120_000 }, () => run(entry));
  }
});
