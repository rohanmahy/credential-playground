// Settings: clock override, skew, key-binding expectations, view toggles,
// theme. In memory only (SPEC §1).
import type { Platform } from '../platform/Platform';
import type { ViewOptions } from '../engine/types';
import { defaultViewOptions } from '../engine/defaults';
import { notImplemented } from '../notImplemented';

export type Theme = 'system' | 'light' | 'dark';

export class Settings {
  /** Validation clock override (epoch seconds), or null for "now". */
  clockOverride = $state<number | null>(null);
  /** Allowed skew in seconds (SPEC §6 default 60). */
  skew = $state(60);
  expectedAud = $state<string | null>(null);
  expectedNonce = $state<string | null>(null);
  showRaw = $state(true);
  decodedViews = $state(true);
  annotations = $state(true);
  jsonPretty = $state(false);
  theme = $state<Theme>('system');

  readonly #platform: Platform;

  constructor(platform: Platform) {
    this.#platform = platform;
  }

  get platform(): Platform {
    return this.#platform;
  }

  /** The clock for validation, KB `iat`, and relative times: the override,
   *  else `Platform.now()`. */
  now(): number {
    notImplemented('Settings.now');
  }

  /** View options from the toggles, with `now` and the local offset filled in. */
  viewOptions(): ViewOptions {
    void defaultViewOptions;
    notImplemented('Settings.viewOptions');
  }
}
