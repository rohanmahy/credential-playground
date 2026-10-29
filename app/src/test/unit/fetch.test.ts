// Fetches happen only after the user confirms (SPEC §1, §4.2, §6).
import { describe, expect, it, vi } from 'vitest';
import { confirmedFetch } from '../../lib/logic/fetch';
import { FetchError } from '../../lib/platform/Platform';
import { MockPlatform } from '../MockPlatform';

const URL = 'https://issuer.example/.well-known/jwks.json';

describe('confirmedFetch', () => {
  it('asks first and fetches nothing when the user cancels', async () => {
    const p = new MockPlatform();
    const confirm = vi.fn(async () => false);
    expect(await confirmedFetch(p, URL, confirm)).toEqual({ type: 'cancelled' });
    expect(confirm).toHaveBeenCalledWith(URL);
    expect(p.fetchUrl).not.toHaveBeenCalled();
  });

  it('fetches after confirmation', async () => {
    const p = new MockPlatform();
    const order: string[] = [];
    const confirm = vi.fn(async () => {
      order.push('confirm');
      return true;
    });
    p.fetchUrl.mockImplementationOnce(async (url) => {
      order.push('fetch');
      return { url, status: 200, contentType: null, bytes: new Uint8Array() };
    });
    const out = await confirmedFetch(p, URL, confirm);
    expect(out.type).toBe('ok');
    expect(order).toEqual(['confirm', 'fetch']);
  });

  it('explains CORS failures and offers the paste fallback', async () => {
    const p = new MockPlatform();
    p.fetchUrl.mockRejectedValueOnce(new FetchError('cors', URL, 'Failed to fetch'));
    const out = await confirmedFetch(p, URL, async () => true);
    expect(out).toMatchObject({ type: 'error', kind: 'cors', pasteFallback: true });
    if (out.type !== 'error') throw new Error();
    expect(out.explanation).toMatch(/CORS|cross-origin/i);
    expect(out.explanation).toMatch(/paste|desktop/i);
  });

  it('reports HTTP errors without the CORS explanation', async () => {
    const p = new MockPlatform();
    p.fetchUrl.mockRejectedValueOnce(new FetchError('http', URL, 'Not Found', 404));
    const out = await confirmedFetch(p, URL, async () => true);
    expect(out).toMatchObject({ type: 'error', kind: 'http', pasteFallback: false });
    if (out.type !== 'error') throw new Error();
    expect(out.explanation).toContain('404');
  });
});
