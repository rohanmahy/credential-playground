// Browser implementation: fetch (CORS applies), the File System Access API
// with <input type=file> / download fallbacks, the Clipboard API, and
// IndexedDB for the registry cache only.
import {
  FetchError,
  type FetchResult,
  type OpenFileOptions,
  type OpenedFile,
  type Platform,
  type RegistryCache,
  type WriteClipboardOptions,
} from './Platform';
import { IndexedDbRegistryCache } from './registryCache';

/** The File System Access API where the browser has it (Chromium). */
interface FilePickerWindow {
  showOpenFilePicker?: (options?: object) => Promise<{ getFile(): Promise<File> }[]>;
  showSaveFilePicker?: (options?: { suggestedName?: string }) => Promise<{
    createWritable(): Promise<{ write(data: Blob): Promise<void>; close(): Promise<void> }>;
  }>;
}

function isAbort(e: unknown): boolean {
  return e instanceof DOMException && e.name === 'AbortError';
}

export class WebPlatform implements Platform {
  readonly kind = 'web' as const;
  readonly registryCache: RegistryCache = new IndexedDbRegistryCache();

  /** Maps a TypeError from fetch to FetchError('cors'), a non-2xx status
   *  to 'http', and a non-https URL to 'blocked' (without fetching). */
  async fetchUrl(url: string): Promise<FetchResult> {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new FetchError('blocked', url, 'Not a valid URL');
    }
    if (parsed.protocol !== 'https:') {
      throw new FetchError('blocked', url, 'Only https: URLs can be fetched');
    }
    let response: Response;
    try {
      // No credentials or referrer: the request reveals only the URL and the IP.
      response = await fetch(parsed, {
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        cache: 'no-store',
        redirect: 'follow',
      });
    } catch (e) {
      // The web cannot tell a CORS rejection from other failures before a
      // response; offline is the one case it can.
      if (typeof navigator !== 'undefined' && navigator.onLine === false) {
        throw new FetchError('network', url, 'The browser is offline');
      }
      throw new FetchError('cors', url, e instanceof Error ? e.message : String(e));
    }
    if (!response.ok) {
      throw new FetchError('http', url, response.statusText, response.status);
    }
    return {
      url: response.url || url,
      status: response.status,
      contentType: response.headers.get('content-type'),
      bytes: new Uint8Array(await response.arrayBuffer()),
    };
  }

  async openFile(options?: OpenFileOptions): Promise<OpenedFile | null> {
    const picker = (window as FilePickerWindow).showOpenFilePicker;
    if (picker) {
      try {
        const [handle] = await picker.call(window, { multiple: false });
        if (!handle) return null;
        const file = await handle.getFile();
        return { name: file.name, bytes: new Uint8Array(await file.arrayBuffer()) };
      } catch (e) {
        if (isAbort(e)) return null;
        throw e;
      }
    }
    return new Promise((resolve, reject) => {
      const input = document.createElement('input');
      input.type = 'file';
      if (options?.accept) input.accept = options.accept.join(',');
      input.addEventListener('change', () => {
        const file = input.files?.[0];
        if (!file) return resolve(null);
        file
          .arrayBuffer()
          .then((buf) => resolve({ name: file.name, bytes: new Uint8Array(buf) }), reject);
      });
      input.addEventListener('cancel', () => resolve(null));
      input.click();
    });
  }

  async saveFile(suggestedName: string, data: Uint8Array | string): Promise<boolean> {
    const blob = new Blob([typeof data === 'string' ? data : data.slice()], {
      type: typeof data === 'string' ? 'text/plain' : 'application/octet-stream',
    });
    const picker = (window as FilePickerWindow).showSaveFilePicker;
    if (picker) {
      try {
        const handle = await picker.call(window, { suggestedName });
        const writable = await handle.createWritable();
        await writable.write(blob);
        await writable.close();
        return true;
      } catch (e) {
        if (isAbort(e)) return false;
        throw e;
      }
    }
    const href = URL.createObjectURL(blob);
    try {
      const a = document.createElement('a');
      a.href = href;
      a.download = suggestedName;
      a.rel = 'noopener';
      a.click();
    } finally {
      setTimeout(() => URL.revokeObjectURL(href), 1000);
    }
    return true;
  }

  async readClipboard(): Promise<string> {
    return navigator.clipboard.readText();
  }

  /** The web cannot expire a copy; `sensitive` is labelled by the caller. */
  async writeClipboard(text: string, _options?: WriteClipboardOptions): Promise<void> {
    await navigator.clipboard.writeText(text);
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
