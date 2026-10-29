// Desktop implementation over Tauri commands (app/src-tauri): `fetch_url`
// (reqwest, no CORS), `open_file`/`save_file` (native dialog from Rust; the
// webview never names a path), `read_clipboard`/`write_clipboard`, and
// `registry_cache_*` (a file in the app data dir). Bytes cross as
// base64url; PlatformErrors of kind blocked/network/http become FetchError,
// others Error. now/randomBytes stay local (the interface is synchronous).
// Contract: app/src-tauri/TEST-PLAN.md.
import type {
  FetchResult,
  OpenFileOptions,
  OpenedFile,
  Platform,
  RegistryCache,
  WriteClipboardOptions,
} from './Platform';
import { notImplemented } from '../notImplemented';

class TauriRegistryCache implements RegistryCache {
  async get(): Promise<Uint8Array | null> {
    notImplemented('TauriRegistryCache.get');
  }

  async put(_snapshot: Uint8Array): Promise<void> {
    notImplemented('TauriRegistryCache.put');
  }

  async clear(): Promise<void> {
    notImplemented('TauriRegistryCache.clear');
  }
}

export class TauriPlatform implements Platform {
  readonly kind = 'tauri' as const;
  readonly registryCache: RegistryCache = new TauriRegistryCache();

  async fetchUrl(_url: string): Promise<FetchResult> {
    notImplemented('TauriPlatform.fetchUrl');
  }

  async openFile(_options?: OpenFileOptions): Promise<OpenedFile | null> {
    notImplemented('TauriPlatform.openFile');
  }

  async saveFile(_suggestedName: string, _data: Uint8Array | string): Promise<boolean> {
    notImplemented('TauriPlatform.saveFile');
  }

  async readClipboard(): Promise<string> {
    notImplemented('TauriPlatform.readClipboard');
  }

  async writeClipboard(_text: string, _options?: WriteClipboardOptions): Promise<void> {
    notImplemented('TauriPlatform.writeClipboard');
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
