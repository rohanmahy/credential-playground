// TauriPlatform over a mocked IPC (app/src-tauri/TEST-PLAN.md): each
// Platform method maps to its command, bytes cross as base64url, and
// PlatformErrors become FetchError (fetch kinds) or Error.
import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { toB64u, utf8 } from '../../lib/engine/bytes';
import { FetchError } from '../../lib/platform/Platform';
import { TauriPlatform } from '../../lib/platform/TauriPlatform';

interface Call {
  cmd: string;
  args: unknown;
}

let calls: Call[] = [];
let respond: Record<string, (args: unknown) => unknown> = {};

beforeEach(() => {
  calls = [];
  respond = {};
  mockIPC((cmd, args) => {
    calls.push({ cmd, args });
    const handler = respond[cmd];
    return handler ? handler(args) : null;
  });
});

afterEach(() => clearMocks());

const URL = 'https://issuer.example/.well-known/jwks.json';

function platformError(kind: string, message: string, extra: object = {}) {
  return { kind, message, url: null, status: null, ...extra };
}

describe('fetchUrl', () => {
  it('invokes fetch_url and decodes the body', async () => {
    const body = utf8('{"keys":[]}');
    respond['fetch_url'] = () => ({
      url: 'https://issuer.example/jwks',
      status: 200,
      content_type: 'application/jwk-set+json',
      bytes: toB64u(body),
    });
    const r = await new TauriPlatform().fetchUrl(URL);
    expect(calls).toEqual([{ cmd: 'fetch_url', args: { url: URL } }]);
    expect(r).toEqual({
      url: 'https://issuer.example/jwks',
      status: 200,
      contentType: 'application/jwk-set+json',
      bytes: body,
    });
    expect(r.bytes).toBeInstanceOf(Uint8Array);
  });

  it('keeps a null content type', async () => {
    respond['fetch_url'] = () => ({ url: URL, status: 200, content_type: null, bytes: '' });
    const r = await new TauriPlatform().fetchUrl(URL);
    expect(r.contentType).toBeNull();
    expect(r.bytes).toEqual(new Uint8Array());
  });

  it.each([
    ['blocked', null],
    ['network', null],
    ['http', 404],
  ] as const)('maps a %s PlatformError to FetchError', async (kind, status) => {
    respond['fetch_url'] = () => {
      throw platformError(kind, `failed: ${kind}`, { url: URL, status });
    };
    const e = await new TauriPlatform().fetchUrl(URL).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(FetchError);
    expect(e).toMatchObject({ kind, url: URL, status, message: `failed: ${kind}` });
  });

  it('uses the requested URL when the error has none', async () => {
    respond['fetch_url'] = () => {
      throw platformError('blocked', 'Only https: URLs can be fetched');
    };
    const e = await new TauriPlatform().fetchUrl('http://x.example/').catch((x: unknown) => x);
    expect(e).toMatchObject({ kind: 'blocked', url: 'http://x.example/', status: null });
  });

  it('never reports cors on the desktop; a string rejection is network', async () => {
    respond['fetch_url'] = () => {
      throw 'invalid args `url` for command `fetch_url`';
    };
    const e = await new TauriPlatform().fetchUrl(URL).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(FetchError);
    expect((e as FetchError).kind).toBe('network');
  });
});

describe('files', () => {
  it('openFile passes accept and decodes the file', async () => {
    respond['open_file'] = () => ({ name: 'issuer.pem', bytes: toB64u(Uint8Array.of(0, 255)) });
    const f = await new TauriPlatform().openFile({ accept: ['.pem', 'application/jwt'] });
    expect(calls).toEqual([{ cmd: 'open_file', args: { accept: ['.pem', 'application/jwt'] } }]);
    expect(f).toEqual({ name: 'issuer.pem', bytes: Uint8Array.of(0, 255) });
  });

  it('openFile without options sends accept null; cancel is null', async () => {
    respond['open_file'] = () => null;
    expect(await new TauriPlatform().openFile()).toBeNull();
    expect(calls).toEqual([{ cmd: 'open_file', args: { accept: null } }]);
  });

  it('saveFile sends bytes as base64url and returns the result', async () => {
    respond['save_file'] = () => true;
    const ok = await new TauriPlatform().saveFile('cwt.cbor', Uint8Array.of(0xd2, 0x84));
    expect(ok).toBe(true);
    expect(calls).toEqual([
      { cmd: 'save_file', args: { suggested_name: 'cwt.cbor', data: '0oQ' } },
    ]);
  });

  it('saveFile encodes strings as UTF-8', async () => {
    respond['save_file'] = () => false;
    const ok = await new TauriPlatform().saveFile('key.jwk', '{"kty":"OKP","x":"é"}');
    expect(ok).toBe(false);
    expect(calls[0]?.args).toEqual({
      suggested_name: 'key.jwk',
      data: toB64u(utf8('{"kty":"OKP","x":"é"}')),
    });
  });

  it('file errors reject with an Error carrying the message', async () => {
    respond['open_file'] = () => {
      throw platformError('io', 'cannot read the file');
    };
    const e = await new TauriPlatform().openFile().catch((x: unknown) => x);
    expect(e).toBeInstanceOf(Error);
    expect(e).not.toBeInstanceOf(FetchError);
    expect((e as Error).message).toBe('cannot read the file');
  });
});

describe('clipboard', () => {
  it('readClipboard invokes read_clipboard', async () => {
    respond['read_clipboard'] = () => 'Bearer eyJ';
    expect(await new TauriPlatform().readClipboard()).toBe('Bearer eyJ');
    expect(calls.map((c) => c.cmd)).toEqual(['read_clipboard']);
  });

  it('writeClipboard sends text and sensitive (default false)', async () => {
    const p = new TauriPlatform();
    await p.writeClipboard('public');
    await p.writeClipboard('private', { sensitive: true });
    expect(calls).toEqual([
      { cmd: 'write_clipboard', args: { text: 'public', sensitive: false } },
      { cmd: 'write_clipboard', args: { text: 'private', sensitive: true } },
    ]);
  });

  it('clipboard errors reject with an Error', async () => {
    respond['read_clipboard'] = () => {
      throw platformError('clipboard', 'no text on the clipboard');
    };
    await expect(new TauriPlatform().readClipboard()).rejects.toThrow('no text on the clipboard');
  });
});

describe('registry cache', () => {
  it('get decodes base64url, or null', async () => {
    const cache = new TauriPlatform().registryCache;
    respond['registry_cache_get'] = () => null;
    expect(await cache.get()).toBeNull();
    respond['registry_cache_get'] = () => 'AQID';
    expect(await cache.get()).toEqual(Uint8Array.of(1, 2, 3));
    expect(calls.map((c) => c.cmd)).toEqual(['registry_cache_get', 'registry_cache_get']);
  });

  it('put sends base64url; clear invokes registry_cache_clear', async () => {
    const cache = new TauriPlatform().registryCache;
    await cache.put(Uint8Array.of(1, 2, 3));
    await cache.clear();
    expect(calls).toEqual([
      { cmd: 'registry_cache_put', args: { snapshot: 'AQID' } },
      { cmd: 'registry_cache_clear', args: {} },
    ]);
  });

  it('cache errors reject with an Error', async () => {
    respond['registry_cache_put'] = () => {
      throw platformError('io', 'disk full');
    };
    await expect(new TauriPlatform().registryCache.put(Uint8Array.of(1))).rejects.toThrow(
      'disk full',
    );
  });
});

describe('local services', () => {
  it('now, localOffsetMinutes, and randomBytes do not invoke', () => {
    const p = new TauriPlatform();
    expect(Number.isInteger(p.now())).toBe(true);
    expect(typeof p.localOffsetMinutes()).toBe('number');
    const r = p.randomBytes(32);
    expect(r).toBeInstanceOf(Uint8Array);
    expect(r).toHaveLength(32);
    expect(calls).toEqual([]);
  });

  it('is the tauri platform', () => {
    expect(new TauriPlatform().kind).toBe('tauri');
  });
});
