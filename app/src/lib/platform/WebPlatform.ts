// Browser implementation: fetch (CORS applies), the File System Access API
// with <input type=file> / download fallbacks, the Clipboard API, and
// IndexedDB for the registry cache only.
import type {
  FetchResult,
  OpenFileOptions,
  OpenedFile,
  Platform,
  RegistryCache,
  WriteClipboardOptions,
} from './Platform';
import { IndexedDbRegistryCache } from './registryCache';
import { notImplemented } from '../notImplemented';

export class WebPlatform implements Platform {
  readonly kind = 'web' as const;
  readonly registryCache: RegistryCache = new IndexedDbRegistryCache();

  /** Must map a TypeError from fetch to FetchError('cors'), a non-2xx
   *  status to 'http', and a non-https URL to 'blocked' (without fetching). */
  async fetchUrl(_url: string): Promise<FetchResult> {
    notImplemented('WebPlatform.fetchUrl');
  }

  async openFile(_options?: OpenFileOptions): Promise<OpenedFile | null> {
    notImplemented('WebPlatform.openFile');
  }

  async saveFile(_suggestedName: string, _data: Uint8Array | string): Promise<boolean> {
    notImplemented('WebPlatform.saveFile');
  }

  async readClipboard(): Promise<string> {
    notImplemented('WebPlatform.readClipboard');
  }

  async writeClipboard(_text: string, _options?: WriteClipboardOptions): Promise<void> {
    notImplemented('WebPlatform.writeClipboard');
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
