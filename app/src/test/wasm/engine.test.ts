// WasmEngine over the real release module, in Node (the module bytes are
// passed in, since Node cannot fetch the bundled asset URL). Pins the
// contract in crates/tokenator-wasm/TEST-PLAN.md §2: lazy loading, one
// binding per Engine method, DTOs in and out, EngineFailure for every
// failure, the registry snapshot, and panics.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { EngineFailure, isEngineFailure } from '../../lib/engine/Engine';
import { WasmEngine } from '../../lib/engine/WasmEngine';
import { fromB64u, textToB64u, utf8 } from '../../lib/engine/bytes';
import { defaultViewOptions } from '../../lib/engine/defaults';
import type { Candidate, Document, EngineError } from '../../lib/engine/types';
import {
  REPO,
  camel,
  engineArgs,
  envelope,
  readCorpus,
  wasmBytes,
  type CorpusEntry,
} from './helpers';

const corpus = readCorpus();
const wasm = wasmBytes();
const JWS = readFileSync(join(REPO, 'testdata/tokens/rfc7515-a3-jws-es256.txt'), 'utf8').trim();

function load(snapshot: Uint8Array | null = null): Promise<WasmEngine> {
  return WasmEngine.load(snapshot, { wasm });
}

async function failure(p: Promise<unknown>): Promise<EngineFailure> {
  try {
    await p;
  } catch (e) {
    expect(e, String(e)).toBeInstanceOf(EngineFailure);
    return e as EngineFailure;
  }
  return expect.fail('expected the call to reject');
}

function call(engine: WasmEngine, entry: CorpusEntry): Promise<unknown> {
  const fn = (engine as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>)[
    camel(entry.case.method)
  ];
  expect(fn, camel(entry.case.method)).toBeTypeOf('function');
  if (!fn) return expect.fail(`no method ${camel(entry.case.method)}`);
  return fn.apply(engine, engineArgs(entry.case));
}

describe('loading', () => {
  it('load() resolves without instantiating; the first call does', async () => {
    // Bytes that are not a wasm module: load() still succeeds…
    const engine = await WasmEngine.load(null, { wasm: Uint8Array.of(0, 1, 2, 3) });
    expect(engine).toBeInstanceOf(WasmEngine);
    // …and the first call reports the failure as an EngineFailure.
    const f = await failure(engine.info());
    expect(f.error.code as string).toBe('internal');
    expect(f.error.node_id).toBeNull();
  });

  it('concurrent first calls share one instance and all succeed', async () => {
    const engine = await load();
    const results = await Promise.all([
      engine.info(),
      engine.detect(utf8(JWS)),
      engine.registryLookup({ name: 'iss' }),
      engine.info(),
    ]);
    expect(results[0]).toEqual(results[3]);
    expect((results[1] as Candidate[])[0]?.kind).toEqual({ type: 'jwt' });
  });

  it('info() matches the bundled registry and the SD-CWT revision', async () => {
    const info = await (await load()).info();
    expect(info.sd_cwt_revision).toBe('draft-ietf-spice-sd-cwt-08');
    expect(Object.keys(info.registry_updated).sort()).toEqual(['cose', 'cwt', 'jose', 'jwt']);
  });
});

describe('every Engine method returns the native DTOs (parity corpus)', () => {
  let engine: WasmEngine;
  beforeAll(async () => {
    engine = await load();
  });

  for (const entry of corpus) {
    it(entry.id, { timeout: 120_000 }, async () => {
      if (!('text' in entry.golden)) {
        // Digest goldens are large successful outputs (byte identity is
        // checked in parity.test.ts).
        await expect(call(engine, entry)).resolves.toBeDefined();
        return;
      }
      const expected = envelope(entry.golden);
      if ('ok' in expected) {
        expect(await call(engine, entry)).toEqual(expected.ok);
      } else {
        const f = await failure(call(engine, entry));
        expect(f.error).toEqual(expected.err);
        expect(f.message).toBe((expected.err as EngineError).message);
        expect(isEngineFailure(f)).toBe(true);
      }
    });
  }
});

describe('requests and raw input', () => {
  let engine: WasmEngine;
  beforeAll(async () => {
    engine = await load();
  });

  it('detect and open read only the bytes of a Uint8Array view', async () => {
    const padded = utf8(`xxxx${JWS}yyyy`);
    const view = padded.subarray(4, padded.length - 4);
    const copy = utf8(JWS);
    const [a, b] = await Promise.all([engine.detect(view), engine.detect(copy)]);
    expect(a).toEqual(b);
    const top = a[0];
    if (!top) return expect.fail('nothing detected');
    const [da, db] = await Promise.all([
      engine.open(view, top, defaultViewOptions()),
      engine.open(copy, top, defaultViewOptions()),
    ]);
    expect(da).toEqual(db);
  });

  it('requests may omit defaulted fields', async () => {
    const top = (await engine.detect(utf8(JWS)))[0];
    if (!top) return expect.fail('nothing detected');
    const doc: Document = await engine.open(utf8(JWS), top, {});
    const report = await engine.validate({ doc: { kind: doc.kind, bytes: doc.bytes }, now: 0 });
    expect(report.items[0]?.id).toBe('signature');
  });

  it('a malformed request rejects with invalid_input', async () => {
    const bad = { doc: { kind: { type: 'nope' }, bytes: '' }, now: 0 };
    const f = await failure(engine.validate(bad as never));
    expect(f.error.code).toBe('invalid_input');
  });

  it('results are fresh objects', async () => {
    const a = await engine.info();
    const b = await engine.info();
    expect(a).toEqual(b);
    expect(a).not.toBe(b);
  });

  it('keyToJwk resolves to the JWK text, not a parsed object', async () => {
    const key = await engine.keyGenerate({ spec: { type: 'p256' }, seed: { type: 'well_known' } });
    const jwk = await engine.keyToJwk({ key: key.key, visibility: 'public' });
    expect(typeof jwk).toBe('string');
    expect(JSON.parse(jwk)).toMatchObject({ kty: 'EC', crv: 'P-256' });
  });
});

describe('registry snapshot', () => {
  it('load(snapshot) builds the engine from a registry_merge snapshot', async () => {
    const xml = readFileSync(join(REPO, 'testdata/iana/cwt.xml'), 'utf8').replace(
      '<updated>2026-07-20</updated>',
      '<updated>2027-01-02</updated>',
    );
    const merged = await (await load()).registryMerge({ xml: textToB64u(xml), which: 'cwt' });
    const engine = await load(fromB64u(merged.snapshot));
    expect((await engine.info()).registry_updated['cwt']).toBe('2027-01-02');
    expect((await (await load()).info()).registry_updated['cwt']).not.toBe('2027-01-02');
  });

  it('all four IANA registries merge in turn', async () => {
    const engine = await load();
    let snapshot: string | null = null;
    for (const which of ['cwt', 'cose', 'jwt', 'jose'] as const) {
      const xml = readFileSync(join(REPO, `testdata/iana/${which}.xml`));
      const r = await engine.registryMerge({
        base_snapshot: snapshot,
        xml: textToB64u(xml.toString('utf8')),
        which,
      });
      snapshot = r.snapshot;
    }
    const merged = await load(fromB64u(snapshot ?? ''));
    expect((await merged.registryLookup({ name: 'iss' })).length).toBeGreaterThan(0);
  });

  it('an unreadable snapshot rejects the first call with code registry', async () => {
    const engine = await load(utf8('not a snapshot'));
    const f = await failure(engine.info());
    expect(f.error.code).toBe('registry');
  });
});

describe('panics', () => {
  it('a panic rejects with EngineFailure (code internal) and the engine keeps answering', async () => {
    const engine = await load();
    const f = await failure(engine.panicForTests('boom'));
    expect(f.error.code as string).toBe('internal');
    expect(f.message).toMatch(/panic|unreachable/i);
    expect((await engine.info()).version).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('repeated panics do not exhaust the stack for later deep calls', async () => {
    const engine = await load();
    for (let i = 0; i < 20; i++) await failure(engine.panicForTests(`boom ${i}`));
    const deep = corpus.find((e) => e.id === 'render--stack--cbor-maps-max-depth');
    if (!deep) return expect.fail('missing stack case');
    await expect(call(engine, deep)).resolves.toBeDefined();
  });
});
