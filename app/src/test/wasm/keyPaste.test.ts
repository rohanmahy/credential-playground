// #42: keys pasted into the input in an encoded or wrapped form reach the
// key panel. Detection unwraps the layers, so the import must use the
// unwrapped payload, not the raw input. Runs the real WasmEngine through
// the Workspace store.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createAppContext } from '../../lib/context';
import { WasmEngine } from '../../lib/engine/WasmEngine';
import { MockPlatform } from '../MockPlatform';
import { REPO, wasmBytes } from './helpers';

const wasm = wasmBytes();
const fixture = (path: string) => readFileSync(join(REPO, 'testdata', path));

/** `xxd -p` output: lowercase hex, 60 characters per line. */
function xxd(bytes: Uint8Array): string {
  const hex = Buffer.from(bytes).toString('hex');
  return `${hex.match(/.{1,60}/g)?.join('\n') ?? ''}\n`;
}

const COSE_KEY = fixture('keys/rfc8392-a2.3-ec-p256.cosekey.cbor');
const JWK = fixture('keys/sd-cwt-08-c1-holder-private.jwk.json');
const PEM = fixture('keys/sd-cwt-08-c1-holder-public.pem').toString('utf8').trim();

const cases: [string, string][] = [
  ['hex COSE_Key (xxd -p)', xxd(COSE_KEY)],
  ['base64url COSE_Key', Buffer.from(COSE_KEY).toString('base64url')],
  ['base64 JWK', Buffer.from(JWK).toString('base64')],
  ['quoted PEM', `"${PEM}"`],
];

async function setup() {
  const engine = await WasmEngine.load(null, { wasm });
  return createAppContext(engine, new MockPlatform());
}

describe('keys pasted into the input (#42)', () => {
  it.each(cases)('%s goes to the key panel', async (_name, text) => {
    const app = await setup();
    const res = await app.workspace.openText(text, { type: 'pasted' });
    expect(res.type).toBe('keys');
    expect(app.workspace.tabs).toHaveLength(0);
    expect(app.keys.cards).toHaveLength(1);
    expect(app.keys.cards[0]?.info.crv).toBe('P-256');
    // Provenance names where the input came from, not the unwrapped form.
    expect(app.keys.cards[0]?.provenance).toEqual({ type: 'pasted' });
  });

  it('the hex COSE_Key is the same key as the raw binary one', async () => {
    const app = await setup();
    await app.workspace.openText(xxd(COSE_KEY), { type: 'clipboard' });
    await app.workspace.openInput(new Uint8Array(COSE_KEY), { type: 'file', name: 'k.cbor' });
    const [hex, raw] = app.keys.cards;
    expect(hex?.info.cose_thumbprint).toBe(raw?.info.cose_thumbprint);
    expect(hex?.provenance).toEqual({ type: 'clipboard' });
  });
});
