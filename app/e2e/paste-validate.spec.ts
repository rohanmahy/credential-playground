// Paste each token family → detect → open → Validate, with the real
// WasmEngine. Binary fixtures are pasted as hex.
import { expect, test } from '@playwright/test';
import { fixtureHex, fixtureText, importKey, paste, validate } from './helpers';

test.beforeEach(async ({ page }) => {
  await page.goto('/');
});

interface Family {
  name: string;
  input: () => string;
  kind: string | RegExp;
  /** Text the main pane shows. */
  shows: string;
  raw: 'Raw pane' | null;
}

const families: Family[] = [
  {
    name: 'JWT (RFC 7515 A.3, ES256)',
    input: () => fixtureText('tokens/rfc7515-a3-jws-es256.txt'),
    kind: 'JWT',
    shows: '"alg":"ES256"',
    raw: 'Raw pane',
  },
  {
    name: 'JWS JSON, general (RFC 7515 A.6)',
    input: () => fixtureText('tokens/rfc7515-a6-jws-json-general.json'),
    kind: 'JWS JSON',
    shows: '"signatures"',
    raw: 'Raw pane',
  },
  {
    name: 'SD-JWT (RFC 9901 §5.1)',
    input: () => fixtureText('tokens/rfc9901-s5.1-sd-jwt.txt'),
    kind: 'SD-JWT',
    shows: '"_sd"',
    raw: 'Raw pane',
  },
  {
    name: 'SD-JWT+KB (RFC 9901 §5.2)',
    input: () => fixtureText('tokens/rfc9901-s5.2-sd-jwt-kb.txt'),
    kind: 'SD-JWT+KB',
    shows: '"kb"',
    raw: 'Raw pane',
  },
  {
    name: 'SD-JWT+KB JSON, general (RFC 9901 §8.3)',
    input: () => fixtureText('tokens/rfc9901-s8.3-sd-jwt-kb-json-general.json'),
    kind: 'SD-JWT+KB JSON',
    shows: '"signatures"',
    raw: 'Raw pane',
  },
  {
    name: 'CWT (RFC 8392 A.3, hex text)',
    input: () => fixtureText('tokens/rfc8392-a3-signed-cwt.hex'),
    kind: 'CWT',
    shows: 'coap://as.example.com',
    raw: 'Raw pane',
  },
  {
    name: 'CWT, tag 61 (derived from RFC 8392 A.3)',
    input: () => fixtureHex('tokens/derived-rfc8392-a3-tag61.cbor'),
    kind: 'CWT',
    shows: 'coap://as.example.com',
    raw: 'Raw pane',
  },
  {
    name: 'COSE_Sign1 that is not a CWT (RFC 9052 C.2.1)',
    input: () => fixtureHex('tokens/rfc9052-c2.1-sign1.cbor'),
    kind: 'COSE_Sign1',
    shows: '/ alg /',
    raw: 'Raw pane',
  },
  {
    name: 'SD-CWT (draft-ietf-spice-sd-cwt-08)',
    input: () => fixtureHex('tokens/sd-cwt-08-issuer-sd-cwt.cbor'),
    kind: 'SD-CWT',
    shows: 'simple(59)',
    raw: 'Raw pane',
  },
  {
    name: 'SD-KBT (draft-ietf-spice-sd-cwt-08)',
    input: () => fixtureHex('tokens/sd-cwt-08-sd-kbt.cbor'),
    kind: 'SD-KBT',
    shows: '/ kcwt /',
    raw: 'Raw pane',
  },
  {
    name: 'nested SD-KBT (draft-ietf-spice-sd-cwt-08)',
    input: () => fixtureHex('tokens/sd-cwt-08-nested-sd-kbt.cbor'),
    kind: 'SD-KBT',
    shows: '/ kcwt /',
    raw: 'Raw pane',
  },
];

for (const f of families) {
  test(`${f.name}: detect, open, validate`, async ({ page }) => {
    await paste(page, f.input());
    await expect(page.getByTestId('detected-type')).toHaveText(f.kind);
    await expect(page.getByRole('tree', { name: 'Main pane' })).toContainText(f.shows);
    if (f.raw) await expect(page.getByRole('tree', { name: f.raw })).toBeVisible();
    const report = await validate(page);
    await expect(page.getByTestId('report-overall')).toHaveText(/pass|fail|warn|skip/i);
    // The issuer signature item always comes first.
    await expect(report.locator('[data-status]').first()).toHaveAttribute(
      'data-status',
      /pass|fail|skip/,
    );
  });
}

test('unwrapping layers: a Bearer header around a JWT', async ({ page }) => {
  await paste(page, `Authorization: Bearer ${fixtureText('tokens/rfc7515-a3-jws-es256.txt')}`);
  await expect(page.getByTestId('detected-type')).toHaveText('JWT');
  const layers = page.getByRole('navigation', { name: 'Unwrapping layers' });
  await expect(layers.getByRole('listitem')).not.toHaveCount(0);
  await expect(layers).toContainText(/Bearer/);
});

test('JWT with its published key: the signature passes', async ({ page }) => {
  const jwk = JSON.stringify({
    kty: 'EC',
    crv: 'P-256',
    x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
    y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
  });
  await importKey(page, jwk);
  await paste(page, fixtureText('tokens/rfc7515-a3-jws-es256.txt'));
  const report = await validate(page);
  await expect(report.locator('[data-status]').first()).toHaveAttribute('data-status', 'pass');
});

test('SD-JWT+KB with the RFC 9901 issuer key: signature and disclosures pass', async ({ page }) => {
  await importKey(page, fixtureText('keys/rfc9901-a5-ec-p256-public.jwk.json'));
  await paste(page, fixtureText('tokens/rfc9901-s5.2-sd-jwt-kb.txt'));
  await expect(page.getByRole('table', { name: 'Disclosures' })).toContainText('given_name');
  const report = await validate(page);
  await expect(report.locator('[data-status]').first()).toHaveAttribute('data-status', 'pass');
  await expect(report).toContainText(/disclosure/i);
});

test('without a key, a JWT signature is skipped, not failed', async ({ page }) => {
  await paste(page, fixtureText('tokens/rfc7515-a3-jws-es256.txt'));
  const report = await validate(page);
  await expect(report.locator('[data-status]').first()).toHaveAttribute('data-status', 'skip');
});

for (const [name, input, kind] of [
  ['JSON', () => fixtureText('tokens/rfc7519-s3.1-claims.json'), 'JSON claim set'],
  ['EDN', () => fixtureText('tokens/sd-cwt-08-fig4-claims.edn'), 'EDN claim set'],
  ['CBOR', () => fixtureHex('tokens/rfc8392-a1-claims.cbor'), 'CBOR claim set'],
] as const) {
  test(`${name} claim set opens as an unsigned draft (Validate disabled)`, async ({ page }) => {
    await paste(page, input());
    await expect(page.getByTestId('detected-type')).toHaveText(kind);
    await expect(
      page.getByRole('toolbar', { name: 'Actions' }).getByRole('button', { name: 'Validate' }),
    ).toHaveAttribute('aria-disabled', 'true');
  });
}

test('a key pasted into the input goes to the key panel', async ({ page }) => {
  await paste(page, fixtureText('keys/sd-cwt-08-c1-holder-private.jwk.json'));
  await expect(page.getByRole('complementary', { name: 'Keys' }).getByRole('article')).toHaveCount(
    1,
  );
});

test('a hex COSE_Key (xxd -p) pasted into the input goes to the key panel (#42)', async ({
  page,
}) => {
  // `xxd -p` wraps at 60 hex characters per line.
  const hex = fixtureHex('keys/rfc8392-a2.3-ec-p256.cosekey.cbor')
    .match(/.{1,60}/g)
    ?.join('\n');
  await paste(page, `${hex}\n`);
  const cards = page.getByRole('complementary', { name: 'Keys' }).getByRole('article');
  await expect(cards).toHaveCount(1);
  await expect(cards.first()).toContainText('P-256');
  await expect(cards.first()).toContainText('Pasted');
  await expect(page.getByRole('tab')).toHaveCount(0);
  await expect(page.getByText(/TrailingBytes/)).toHaveCount(0);
});
