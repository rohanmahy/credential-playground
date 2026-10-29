import { describe, expect, it } from 'vitest';
import { b64uToText, fromB64u, textToB64u, toB64u } from '../../lib/engine/bytes';
import { defaultViewOptions } from '../../lib/engine/defaults';
import { isTauri, selectEngine } from '../../lib/engine/select';
import { TauriEngine } from '../../lib/engine/TauriEngine';
import { WasmEngine } from '../../lib/engine/WasmEngine';
import { selectPlatform } from '../../lib/platform/select';
import { TauriPlatform } from '../../lib/platform/TauriPlatform';
import { WebPlatform } from '../../lib/platform/WebPlatform';

describe('engine and platform selection', () => {
  it('uses Tauri when window.__TAURI__ exists', async () => {
    const win = { __TAURI__: {} };
    expect(isTauri(win)).toBe(true);
    expect(await selectEngine(win)).toBeInstanceOf(TauriEngine);
    expect(selectPlatform(win)).toBeInstanceOf(TauriPlatform);
  });

  it('uses WASM and the browser otherwise', async () => {
    expect(isTauri({})).toBe(false);
    expect(await selectEngine({})).toBeInstanceOf(WasmEngine);
    expect(selectPlatform({})).toBeInstanceOf(WebPlatform);
  });
});

describe('base64url (core wire convention)', () => {
  it('round-trips unpadded base64url', () => {
    expect(toB64u(Uint8Array.of(0xd2, 0x84))).toBe('0oQ');
    expect([...fromB64u('0oQ')]).toEqual([0xd2, 0x84]);
    expect(b64uToText(textToB64u('{"alg":"ES256"}'))).toBe('{"alg":"ES256"}');
    expect(toB64u(Uint8Array.of(0xfb, 0xff))).toBe('-_8');
  });

  it('rejects padded or classic base64', () => {
    expect(() => fromB64u('0oQ=')).toThrow();
    expect(() => fromB64u('+/8')).toThrow();
  });
});

describe('defaults', () => {
  it('match the core ViewOptions defaults', () => {
    expect(defaultViewOptions()).toEqual({
      layout: 'indented',
      indent: 2,
      decoded_views: true,
      hide_decoded: [],
      manual_decode: [],
      annotations: true,
      byte_style: 'hex',
      dt_literals: false,
      json_layout: 'original',
      now: null,
      local_offset_minutes: 0,
    });
  });
});
