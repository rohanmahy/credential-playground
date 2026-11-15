// #42 and SPEC §3 (split detection): keys pasted into a key area in an
// encoded or wrapped form are found by detectKey, which unwraps the same
// layers as detect, and import through that candidate. Token detection
// never returns a key, and key detection never returns a token. Runs the
// real WasmEngine.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { EngineFailure } from '../../lib/engine/Engine';
import { WasmEngine } from '../../lib/engine/WasmEngine';
import { utf8 } from '../../lib/engine/bytes';
import { REPO, wasmBytes } from './helpers';

const fixture = (path: string) => readFileSync(join(REPO, 'testdata', path));

/** `xxd -p` output: lowercase hex, 60 characters per line. */
function xxd(bytes: Uint8Array): string {
  const hex = Buffer.from(bytes).toString('hex');
  return `${hex.match(/.{1,60}/g)?.join('\n') ?? ''}\n`;
}

const KEY_KINDS = ['jwk', 'jwk_set', 'cose_key', 'cose_key_set', 'pem'];

const COSE_KEY = fixture('keys/rfc8392-a2.3-ec-p256.cosekey.cbor');
const JWK = fixture('keys/sd-cwt-08-c1-holder-private.jwk.json');
const PEM = fixture('keys/sd-cwt-08-c1-holder-public.pem').toString('utf8').trim();
const JWS = fixture('tokens/rfc7515-a3-jws-es256.txt').toString('utf8');

const wrapped: [string, string, string][] = [
  ['hex COSE_Key (xxd -p)', xxd(COSE_KEY), 'cose_key'],
  ['base64url COSE_Key', Buffer.from(COSE_KEY).toString('base64url'), 'cose_key'],
  ['base64 JWK', Buffer.from(JWK).toString('base64'), 'jwk'],
  ['quoted PEM', `"${PEM}"`, 'pem'],
];

let engine: WasmEngine;

beforeAll(async () => {
  engine = await WasmEngine.load(null, { wasm: wasmBytes() });
});

describe('keys pasted into a key area (#42)', () => {
  it.each(wrapped)('%s is a key to detectKey and imports', async (_name, text, kind) => {
    const cands = await engine.detectKey(utf8(text));
    expect(cands.map((c) => c.kind.type).every((k) => KEY_KINDS.includes(k))).toBe(true);
    const top = cands[0];
    if (!top) return expect.fail('no key candidate');
    expect(top.kind.type).toBe(kind);
    const cards = await engine.keyImport({
      bytes: Buffer.from(text).toString('base64url'),
      candidate: top,
    });
    expect(cards).toHaveLength(1);
    expect(cards[0]?.crv).toBe('P-256');
  });

  it.each(wrapped)('%s gives detect no key candidate', async (_name, text) => {
    const kinds = (await engine.detect(utf8(text))).map((c) => c.kind.type);
    expect(kinds.filter((k) => KEY_KINDS.includes(k))).toEqual([]);
  });

  it('the hex COSE_Key is the same key as the raw binary one', async () => {
    const hex = xxd(COSE_KEY);
    const [top] = await engine.detectKey(utf8(hex));
    if (!top) return expect.fail('no key candidate');
    const [fromHex] = await engine.keyImport({
      bytes: Buffer.from(hex).toString('base64url'),
      candidate: top,
    });
    const [raw] = await engine.keyImport({ bytes: Buffer.from(COSE_KEY).toString('base64url') });
    expect(fromHex?.cose_thumbprint).toBe(raw?.cose_thumbprint);
  });
});

describe('tokens pasted into a key area', () => {
  it('detectKey finds nothing in a JWT, a CWT, or a claim set', async () => {
    for (const input of [
      utf8(JWS),
      new Uint8Array(fixture('tokens/rfc8392-a3-signed-cwt.cbor')),
      new Uint8Array(fixture('tokens/rfc7519-s3.1-claims.json')),
    ]) {
      expect(await engine.detectKey(input)).toEqual([]);
    }
  });

  it('keyImport of a token rejects with not_a_key', async () => {
    const failure = await engine
      .keyImport({ bytes: Buffer.from(JWS).toString('base64url') })
      .catch((x: unknown) => x);
    expect(failure).toBeInstanceOf(EngineFailure);
    expect((failure as EngineFailure).error.code as string).toBe('not_a_key');
    expect((failure as EngineFailure).message).toBe('Not a recognized key');
  });

  it('keyImport with a token candidate rejects with not_a_key', async () => {
    const [top] = await engine.detect(utf8(JWS));
    if (!top) return expect.fail('nothing detected');
    const failure = await engine
      .keyImport({ bytes: Buffer.from(JWS).toString('base64url'), candidate: top })
      .catch((x: unknown) => x);
    expect(failure).toBeInstanceOf(EngineFailure);
    expect((failure as EngineFailure).error.code as string).toBe('not_a_key');
  });
});
