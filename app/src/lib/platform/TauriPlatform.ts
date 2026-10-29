// Desktop implementation over Tauri commands (app/src-tauri): `fetch_url`
// (reqwest, no CORS), `open_file`/`save_file` (native dialog from Rust; the
// webview never names a path), `read_clipboard`/`write_clipboard`, and
// `registry_cache_*` (a file in the app data dir). Bytes cross as
// base64url; PlatformErrors of kind blocked/network/http become FetchError,
// others Error. now/randomBytes stay local (the interface is synchronous).
// Contract: app/src-tauri/TEST-PLAN.md.
import { invoke } from '@tauri-apps/api/core';
import { fromB64u, toB64u, utf8 } from '../engine/bytes';
import {
  FetchError,
  type FetchErrorKind,
  type FetchResult,
  type OpenFileOptions,
  type OpenedFile,
  type Platform,
  type RegistryCache,
  type WriteClipboardOptions,
} from './Platform';

/** `PlatformError` in app/src-tauri/src/error.rs. */
interface PlatformError {
  kind: string;
  message: string;
  url: string | null;
  status: number | null;
}

function isPlatformError(x: unknown): x is PlatformError {
  return (
    typeof x === 'object' &&
    x !== null &&
    typeof (x as PlatformError).kind === 'string' &&
    typeof (x as PlatformError).message === 'string'
  );
}

function messageOf(x: unknown): string {
  if (isPlatformError(x) || x instanceof Error) return x.message;
  return String(x);
}

/** A non-fetch command; failures reject with `Error(message)`. */
async function call<T>(cmd: string, args: Record<string, unknown> = {}): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (x) {
    throw new Error(messageOf(x), { cause: x });
  }
}

const FETCH_KINDS: readonly FetchErrorKind[] = ['blocked', 'network', 'http'];

/** The desktop has no CORS: a fetch kind is kept, anything else is
 *  `network`. */
function toFetchError(x: unknown, requested: string): FetchError {
  if (isPlatformError(x)) {
    const kind = FETCH_KINDS.find((k) => k === x.kind) ?? 'network';
    return new FetchError(kind, x.url ?? requested, x.message, x.status ?? null);
  }
  return new FetchError('network', requested, messageOf(x));
}

interface WireFetchResponse {
  url: string;
  status: number;
  content_type: string | null;
  bytes: string;
}

class TauriRegistryCache implements RegistryCache {
  async get(): Promise<Uint8Array | null> {
    const snapshot = await call<string | null>('registry_cache_get');
    return snapshot === null ? null : fromB64u(snapshot);
  }

  async put(snapshot: Uint8Array): Promise<void> {
    await call('registry_cache_put', { snapshot: toB64u(snapshot) });
  }

  async clear(): Promise<void> {
    await call('registry_cache_clear');
  }
}

export class TauriPlatform implements Platform {
  readonly kind = 'tauri' as const;
  readonly registryCache: RegistryCache = new TauriRegistryCache();

  async fetchUrl(url: string): Promise<FetchResult> {
    let r: WireFetchResponse;
    try {
      r = await invoke<WireFetchResponse>('fetch_url', { url });
    } catch (x) {
      throw toFetchError(x, url);
    }
    return { url: r.url, status: r.status, contentType: r.content_type, bytes: fromB64u(r.bytes) };
  }

  async openFile(options?: OpenFileOptions): Promise<OpenedFile | null> {
    const f = await call<{ name: string; bytes: string } | null>('open_file', {
      accept: options?.accept ?? null,
    });
    return f === null ? null : { name: f.name, bytes: fromB64u(f.bytes) };
  }

  async saveFile(suggestedName: string, data: Uint8Array | string): Promise<boolean> {
    const bytes = typeof data === 'string' ? utf8(data) : data;
    return call<boolean>('save_file', { suggested_name: suggestedName, data: toB64u(bytes) });
  }

  async readClipboard(): Promise<string> {
    return call<string>('read_clipboard');
  }

  async writeClipboard(text: string, options?: WriteClipboardOptions): Promise<void> {
    await call('write_clipboard', { text, sensitive: options?.sensitive ?? false });
  }

  now(): number {
    return Math.floor(Date.now() / 1000);
  }

  localOffsetMinutes(epoch: number = this.now()): number {
    return -new Date(epoch * 1000).getTimezoneOffset();
  }

  randomBytes(n: number): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(n));
  }
}
