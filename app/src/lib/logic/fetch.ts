// User-confirmed fetches (SPEC §1, §4.2, §6).
import type { FetchResult, Platform } from '../platform/Platform';
import { notImplemented } from '../notImplemented';

export type Confirm = (url: string) => Promise<boolean>;

export type FetchOutcome =
  | { type: 'ok'; result: FetchResult }
  | { type: 'cancelled' }
  /** `explanation` is user-facing; `pasteFallback` is true when pasting the
   *  content (or the desktop app) is the way out (CORS on the web). */
  | { type: 'error'; kind: string; explanation: string; pasteFallback: boolean };

/** Asks `confirm` first; never calls `platform.fetchUrl` unless it resolves true. */
export async function confirmedFetch(
  _platform: Platform,
  _url: string,
  _confirm: Confirm,
): Promise<FetchOutcome> {
  notImplemented('confirmedFetch');
}

/** The note shown in every fetch confirmation (SPEC §9). */
export const FETCH_PRIVACY_NOTE = 'Fetching reveals your IP address and this URL to its host.';
