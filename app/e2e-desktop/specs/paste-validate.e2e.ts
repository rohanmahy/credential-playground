// Checklist §2 (through the paste box): each token family → detected type
// → open → Validate, on the native engine. Binary fixtures are pasted as
// hex. Mirrors app/e2e/paste-validate.spec.ts.
import { browser } from '@wdio/globals';
import {
  appReady,
  detectedType,
  expectSignature,
  expectThat,
  fixtureHex,
  fixtureText,
  importKey,
  keyCards,
  mainPane,
  page,
  paste,
  rawPane,
  validate,
} from '../helpers';

interface Family {
  name: string;
  input: () => string;
  kind: string;
  /** Text the main pane shows. */
  shows: string;
}

const families: Family[] = [
  {
    name: 'JWT (RFC 7515 A.3, ES256)',
    input: () => fixtureText('tokens/rfc7515-a3-jws-es256.txt'),
    kind: 'JWT',
    shows: '"alg":"ES256"',
  },
  {
    name: 'JWS JSON, general (RFC 7515 A.6)',
    input: () => fixtureText('tokens/rfc7515-a6-jws-json-general.json'),
    kind: 'JWS JSON',
    shows: '"signatures"',
  },
  {
    name: 'SD-JWT (RFC 9901 §5.1)',
    input: () => fixtureText('tokens/rfc9901-s5.1-sd-jwt.txt'),
    kind: 'SD-JWT',
    shows: '"_sd"',
  },
  {
    name: 'SD-JWT+KB (RFC 9901 §5.2)',
    input: () => fixtureText('tokens/rfc9901-s5.2-sd-jwt-kb.txt'),
    kind: 'SD-JWT+KB',
    shows: '"kb"',
  },
  {
    name: 'CWT, tag 18 (RFC 8392 A.3, hex text)',
    input: () => fixtureText('tokens/rfc8392-a3-signed-cwt.hex'),
    kind: 'CWT',
    shows: 'coap://as.example.com',
  },
  {
    name: 'CWT, tag 61 (derived from RFC 8392 A.3)',
    input: () => fixtureHex('tokens/derived-rfc8392-a3-tag61.cbor'),
    kind: 'CWT',
    shows: 'coap://as.example.com',
  },
  {
    name: 'CWT, untagged (derived from RFC 8392 A.3)',
    input: () => fixtureHex('tokens/derived-rfc8392-a3-untagged.cbor'),
    kind: 'CWT',
    shows: 'coap://as.example.com',
  },
  {
    name: 'SD-CWT (draft-ietf-spice-sd-cwt-08)',
    input: () => fixtureHex('tokens/sd-cwt-08-issuer-sd-cwt.cbor'),
    kind: 'SD-CWT',
    shows: 'simple(59)',
  },
  {
    name: 'SD-KBT (draft-ietf-spice-sd-cwt-08)',
    input: () => fixtureHex('tokens/sd-cwt-08-sd-kbt.cbor'),
    kind: 'SD-KBT',
    shows: '/ kcwt /',
  },
];

describe('paste and validate', () => {
  beforeEach(async () => {
    // A fresh webview state per test, as `page.goto('/')` in the web specs.
    await browser.refresh();
    await appReady();
  });

  for (const f of families) {
    it(`${f.name}: detect, open, validate`, async () => {
      await paste(f.input());
      await expectThat(detectedType()).toHaveText(f.kind);
      await expectThat(mainPane()).toContainText(f.shows);
      await expectThat(rawPane()).toBeVisible();
      await validate();
      await expectThat(page.getByTestId('report-overall')).toHaveText(/pass|fail|warn|skip/i);
      // The issuer signature item always comes first; without a key it is skipped.
      await expectSignature(/pass|fail|skip/);
    });
  }

  it('unwrapping layers: a Bearer header around a JWT', async () => {
    await paste(`Authorization: Bearer ${fixtureText('tokens/rfc7515-a3-jws-es256.txt')}`);
    await expectThat(detectedType()).toHaveText('JWT');
    const layers = page.getByRole('navigation', 'Unwrapping layers');
    await expectThat(layers).toContainText(/Bearer/);
  });

  it('JWT with its published key: the signature passes', async () => {
    await importKey(
      JSON.stringify({
        kty: 'EC',
        crv: 'P-256',
        x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
        y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
      }),
    );
    await paste(fixtureText('tokens/rfc7515-a3-jws-es256.txt'));
    await validate();
    await expectSignature('pass');
  });

  it('SD-JWT+KB with the RFC 9901 issuer key: signature and disclosures pass', async () => {
    await importKey(fixtureText('keys/rfc9901-a5-ec-p256-public.jwk.json'));
    await paste(fixtureText('tokens/rfc9901-s5.2-sd-jwt-kb.txt'));
    await expectThat(page.getByRole('table', 'Disclosures')).toContainText('given_name');
    const report = await validate();
    await expectSignature('pass');
    await expectThat(report).toContainText(/disclosure/i);
  });

  it('a key pasted into the input goes to the key panel', async () => {
    await paste(fixtureText('keys/sd-cwt-08-c1-holder-private.jwk.json'));
    await expectThat(keyCards()).toHaveCount(1);
    await expectThat(page.getByRole('tab')).toHaveCount(0);
  });

  it('a JSON claim set opens as an unsigned draft (Validate disabled)', async () => {
    await paste(fixtureText('tokens/rfc7519-s3.1-claims.json'));
    await expectThat(detectedType()).toHaveText('JSON claim set');
    await expectThat(
      page.getByRole('toolbar', 'Actions').getByRole('button', 'Validate'),
    ).toHaveAttribute('aria-disabled', 'true');
  });
});
