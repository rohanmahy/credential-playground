// What #43 (new drafts, explicit type) needs from the real engine. The
// first group pins what core already does; the second pins the core
// additions described in app/TEST-PLAN.md "Core additions needed" and
// fails until they land.
import { beforeAll, describe, expect, it } from 'vitest';
import { WasmEngine } from '../../lib/engine/WasmEngine';
import { utf8 } from '../../lib/engine/bytes';
import { defaultViewOptions } from '../../lib/engine/defaults';
import type { Kind } from '../../lib/engine/types';
import { wasmBytes } from './helpers';

const view = defaultViewOptions();
const SIGN1 = `18([<< {1: -7} >>, {}, << {1: "issuer", 4: 1893456000} >>, h'00'])`;
const COSE_KEY = `{1: 2, -1: 1, -2: h'58a9fe64819ebdcc06232cabcc5a1934175aabdfd3b2acc697dea8734096ba2b', -3: h'cbbeedf91bc01d1293b1219d21851fc1eb8ebf0aef0c3f90dc7bf92747d229b1'}`;

let engine: WasmEngine;

beforeAll(async () => {
  engine = await WasmEngine.load(null, { wasm: wasmBytes() });
});

const edit = (kind: Kind, text: string) => engine.parseEdit({ kind, base: '', text, view });

describe('drafts with the current core', () => {
  it('parse_edit opens the starter templates with an empty base', async () => {
    for (const kind of [{ type: 'json_claims' }, { type: 'edn_claims' }] as Kind[]) {
      const r = await edit(kind, '{}');
      expect(r.ok, kind.type).toBe(true);
      expect(r.document?.kind).toEqual(kind);
      expect(r.signature_stale).toBe(false);
    }
  });

  it('parse_edit with an explicit kind builds COSE documents from EDN text', async () => {
    for (const kind of [{ type: 'cwt' }, { type: 'cose_sign1' }] as Kind[]) {
      const r = await edit(kind, SIGN1);
      expect(r.ok, kind.type).toBe(true);
      expect(r.document?.kind).toEqual(kind);
    }
    const key = await edit({ type: 'cose_key' }, COSE_KEY);
    expect(key.document?.kind).toEqual({ type: 'cose_key' });
    const cards = await engine.keyImport({
      bytes: key.document?.bytes ?? '',
      format: { type: 'cose_key' },
    });
    expect(cards.map((c) => c.description)).toEqual(['EC P-256']);
  });

  it('a kind that does not fit the text is a diagnostic, not a failure', async () => {
    const r = await edit({ type: 'cwt' }, '{1: "x"}');
    expect(r.ok).toBe(false);
    expect(r.diagnostics[0]?.severity).toBe('error');
  });

  it('JSON drafts are detected (claim sets, JWKs); `{}` detects as JSON only', async () => {
    expect((await engine.detect(utf8('{"iss":"x"}')))[0]?.kind).toEqual({ type: 'json_claims' });
    const jwk = '{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}';
    expect((await engine.detect(utf8(jwk)))[0]?.kind).toEqual({ type: 'jwk' });
    expect((await engine.detect(utf8('{}'))).map((c) => c.kind.type)).toEqual(['json_claims']);
  });
});

describe('core additions for #43 (fail until implemented)', () => {
  it('detect classifies EDN text by the CBOR it encodes (COSE_Sign1 → CWT)', async () => {
    const kinds = (await engine.detect(utf8(SIGN1))).map((c) => c.kind.type);
    expect(kinds[0]).toBe('cwt');
  });

  it('detect classifies an EDN COSE_Key as a key', async () => {
    const kinds = (await engine.detect(utf8(COSE_KEY))).map((c) => c.kind.type);
    expect(kinds[0]).toBe('cose_key');
  });

  it('the binding has convert_claims (JSON ↔ EDN claim sets)', async () => {
    const mod = await import('tokenator-wasm');
    expect(
      typeof (mod.TokenatorEngine.prototype as unknown as Record<string, unknown>)[
        'convert_claims'
      ],
    ).toBe('function');
  });
});
