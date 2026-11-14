// A Platform that records calls: fixed clock, deterministic randomness,
// in-memory clipboard, queued files, scripted fetches.
import { vi } from 'vitest';
import type {
  FetchResult,
  OpenedFile,
  Platform,
  RegistryCache,
  WriteClipboardOptions,
} from '../lib/platform/Platform';
import { NOW } from './fixtures/documents';

export class MemoryRegistryCache implements RegistryCache {
  value: Uint8Array | null = null;
  get = vi.fn(async () => this.value);
  put = vi.fn(async (s: Uint8Array) => {
    this.value = s;
  });
  clear = vi.fn(async () => {
    this.value = null;
  });
}

export class MockPlatform implements Platform {
  kind: 'web' | 'tauri' = 'web';
  clipboard = '';
  /** Files returned by openFile, in order; null = the user cancelled. */
  files: (OpenedFile | null)[] = [];
  saved: { name: string; data: Uint8Array | string }[] = [];
  registryCache = new MemoryRegistryCache();
  clock = NOW;
  offsetMinutes = 60;

  fetchUrl = vi.fn(async (url: string): Promise<FetchResult> => ({
    url,
    status: 200,
    contentType: 'application/jwk-set+json',
    bytes: new TextEncoder().encode('{"keys":[]}'),
  }));
  openFile = vi.fn(async () => this.files.shift() ?? null);
  saveFile = vi.fn(async (name: string, data: Uint8Array | string) => {
    this.saved.push({ name, data });
    return true;
  });
  readClipboard = vi.fn(async () => this.clipboard);
  writeClipboard = vi.fn(async (text: string, _options?: WriteClipboardOptions) => {
    this.clipboard = text;
  });
  now = vi.fn(() => this.clock);
  localOffsetMinutes = vi.fn((_epoch?: number) => this.offsetMinutes);
  /** Desktop menu (SPEC §4): the app subscribes with `onMenu`; tests fire
   *  menu items with `emitMenu(id)`. Ids: new_tab, open_file,
   *  from_clipboard, close_tab, split_view, raw_pane, datetime, settings,
   *  about. */
  menuHandlers: ((id: string) => void)[] = [];
  onMenu = vi.fn((handler: (id: string) => void) => {
    this.menuHandlers.push(handler);
    return () => {
      this.menuHandlers = this.menuHandlers.filter((h) => h !== handler);
    };
  });
  emitMenu(id: string): void {
    for (const h of this.menuHandlers) h(id);
  }
  /** Bytes 0, 1, 2, … so requests are predictable. */
  randomBytes = vi.fn((n: number) => Uint8Array.from({ length: n }, (_, i) => i % 256));
}
