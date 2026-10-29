// User-confirmed fetches (SPEC §1, §4.2, §6).
import { FetchError, type FetchResult, type Platform } from '../platform/Platform';

export type Confirm = (url: string) => Promise<boolean>;

export type FetchOutcome =
  | { type: 'ok'; result: FetchResult }
  | { type: 'cancelled' }
  /** `explanation` is user-facing; `pasteFallback` is true when pasting the
   *  content (or the desktop app) is the way out (CORS on the web). */
  | { type: 'error'; kind: string; explanation: string; pasteFallback: boolean };

function explain(e: unknown, url: string, platform: Platform): FetchOutcome {
  if (!(e instanceof FetchError)) {
    return {
      type: 'error',
      kind: 'network',
      explanation: `Could not fetch ${url}: ${e instanceof Error ? e.message : String(e)}`,
      pasteFallback: false,
    };
  }
  switch (e.kind) {
    case 'cors':
      return {
        type: 'error',
        kind: 'cors',
        explanation:
          `The browser blocked the response from ${url}: the server does not allow ` +
          'cross-origin (CORS) requests from this page. Open the URL yourself and paste ' +
          'the content instead, or use the desktop app, which is not subject to CORS.',
        pasteFallback: platform.kind === 'web',
      };
    case 'http':
      return {
        type: 'error',
        kind: 'http',
        explanation: `The server answered HTTP ${e.status ?? '?'} for ${url}${e.message ? ` (${e.message})` : ''}.`,
        pasteFallback: false,
      };
    case 'blocked':
      return {
        type: 'error',
        kind: 'blocked',
        explanation: `Only https: URLs can be fetched (${url}).`,
        pasteFallback: false,
      };
    case 'network':
      return {
        type: 'error',
        kind: 'network',
        explanation: `The request to ${url} failed: ${e.message}`,
        pasteFallback: false,
      };
  }
}

/** Asks `confirm` first; never calls `platform.fetchUrl` unless it resolves true. */
export async function confirmedFetch(
  platform: Platform,
  url: string,
  confirm: Confirm,
): Promise<FetchOutcome> {
  if (!(await confirm(url))) return { type: 'cancelled' };
  try {
    return { type: 'ok', result: await platform.fetchUrl(url) };
  } catch (e) {
    return explain(e, url, platform);
  }
}

/** The note shown in every fetch confirmation (SPEC §9). */
export const FETCH_PRIVACY_NOTE = 'Fetching reveals your IP address and this URL to its host.';
