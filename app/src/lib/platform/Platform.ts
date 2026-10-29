// The Platform seam: every side effect the app has (network, files,
// clipboard, the one persistent cache, clock, randomness). The engine never
// does I/O; the stores pass it time and randomness from here.

export interface FetchResult {
  /** The final URL after redirects. */
  url: string;
  status: number;
  contentType: string | null;
  bytes: Uint8Array;
}

export type FetchErrorKind =
  /** The browser blocked the response (CORS), or the request failed before a
   *  response in a way the web cannot tell apart from CORS. */
  | 'cors'
  /** DNS, TLS, offline. */
  | 'network'
  /** A response with a non-2xx status. */
  | 'http'
  /** Not an https URL (the CSP allows https: only). */
  | 'blocked';

export class FetchError extends Error {
  readonly kind: FetchErrorKind;
  readonly url: string;
  readonly status: number | null;

  constructor(kind: FetchErrorKind, url: string, message: string, status: number | null = null) {
    super(message);
    this.name = 'FetchError';
    this.kind = kind;
    this.url = url;
    this.status = status;
  }
}

export interface OpenedFile {
  name: string;
  bytes: Uint8Array;
}

export interface OpenFileOptions {
  /** File extensions or media types, as for `<input accept>`. */
  accept?: readonly string[];
}

export interface WriteClipboardOptions {
  /** Private key material: the platform may label or expire the copy. */
  sensitive?: boolean;
}

/** The refreshed IANA registry snapshot: the only data that persists. */
export interface RegistryCache {
  get(): Promise<Uint8Array | null>;
  put(snapshot: Uint8Array): Promise<void>;
  clear(): Promise<void>;
}

export interface Platform {
  readonly kind: 'web' | 'tauri';
  /** Fetch a URL the user confirmed. Rejects with FetchError. */
  fetchUrl(url: string): Promise<FetchResult>;
  /** Ask the user for a file; null when cancelled. */
  openFile(options?: OpenFileOptions): Promise<OpenedFile | null>;
  /** Ask the user where to save; false when cancelled. */
  saveFile(suggestedName: string, data: Uint8Array | string): Promise<boolean>;
  readClipboard(): Promise<string>;
  writeClipboard(text: string, options?: WriteClipboardOptions): Promise<void>;
  readonly registryCache: RegistryCache;
  /** Seconds since the epoch (whole seconds). */
  now(): number;
  /** The local zone's offset east of UTC, in minutes, at `epoch` (default now). */
  localOffsetMinutes(epoch?: number): number;
  /** Cryptographically secure random bytes. */
  randomBytes(n: number): Uint8Array;
}
