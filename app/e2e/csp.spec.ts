// The production CSP (SPEC §9) holds with the wasm engine: the module
// compiles under 'wasm-unsafe-eval', JavaScript eval stays blocked, and
// connect-src allows exactly the app's origin plus https: (user-confirmed
// key URLs and www.iana.org for Update registries).
import { expect, test } from '@playwright/test';
import { fixtureText, guardNetwork, paste, validate, watchCsp } from './helpers';

function directives(policy: string): Map<string, string[]> {
  return new Map(
    policy
      .split(';')
      .map((d) => d.trim().split(/\s+/))
      .filter((d) => d[0])
      .map(([name, ...values]) => [name ?? '', values]),
  );
}

test('the served page carries the CSP with wasm-unsafe-eval and no unsafe-eval', async ({
  page,
}) => {
  await page.goto('/');
  const content = await page
    .locator('meta[http-equiv="Content-Security-Policy"]')
    .getAttribute('content');
  const csp = directives(content ?? '');
  expect(csp.get('script-src')).toEqual(["'self'", "'wasm-unsafe-eval'"]);
  for (const [name, values] of csp) {
    expect(values, name).not.toContain("'unsafe-eval'");
  }
  // Exactly what user-confirmed fetches need: https: covers key URLs and
  // https://www.iana.org; no http:, ws:, data:, or blob:.
  expect(csp.get('connect-src')).toEqual(["'self'", 'https:']);
});

test('the wasm engine compiles and runs under the CSP without violations', async ({ page }) => {
  const violations = await watchCsp(page);
  await page.goto('/');
  await paste(page, fixtureText('tokens/rfc9901-s5.2-sd-jwt-kb.txt'));
  await expect(page.getByTestId('detected-type')).toHaveText('SD-JWT+KB');
  await validate(page);
  expect(await violations()).toEqual([]);
});

test('inline scripts and string eval are blocked', async ({ page }) => {
  // page.evaluate itself is exempt from the CSP (DevTools protocol), so
  // the checks run code the page compiles later, as an attacker would.
  const violations = await watchCsp(page);
  await page.goto('/');
  await page.addScriptTag({ content: 'window.__inline = true;' }).catch(() => undefined);
  await page.evaluate(() => {
    // A string timer is compiled by the page later: eval under the CSP.
    (setTimeout as unknown as (code: string, ms: number) => void)('window.__evaled = true;', 0);
  });
  await page.waitForTimeout(200);
  const ran = await page.evaluate(() => {
    const w = window as unknown as { __inline?: boolean; __evaled?: boolean };
    return { inline: w.__inline ?? false, evaled: w.__evaled ?? false };
  });
  expect(ran).toEqual({ inline: false, evaled: false });
  const seen = await violations();
  expect(seen.some((v) => v.startsWith('script-src') && v.endsWith('inline'))).toBe(true);
  expect(seen.some((v) => v.startsWith('script-src') && v.endsWith('eval'))).toBe(true);
});

test('connections outside connect-src are refused by the CSP', async ({ page, context }) => {
  // The guard aborts the request should the CSP let it through.
  const net = await guardNetwork(context);
  const violations = await watchCsp(page);
  await page.goto('/');
  await page.evaluate(async () => {
    await fetch('http://example.com/plain-http').catch(() => undefined);
    try {
      new WebSocket('ws://example.com/socket').close();
    } catch {
      // a CSP-blocked WebSocket may throw synchronously
    }
  });
  await expect
    .poll(violations)
    .toEqual(
      expect.arrayContaining([
        'connect-src http://example.com/plain-http',
        expect.stringMatching(/^connect-src ws:\/\/example\.com/),
      ]),
    );
  expect(net.foreign).toEqual([]);
});
