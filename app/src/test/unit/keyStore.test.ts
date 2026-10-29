// The KeyStore (SPEC §4.2).
import { describe, expect, it, vi } from 'vitest';
import { textToB64u, toB64u, utf8 } from '../../lib/engine/bytes';
import * as fx from '../fixtures';
import { seedKeys, setupApp } from '../render';

describe('create', () => {
  it('random keys use 32 bytes of platform entropy', async () => {
    const app = setupApp();
    const card = await app.keys.generate(
      { type: 'p256' },
      { seed: { type: 'random' }, role: 'issuer' },
    );
    expect(app.platform.randomBytes).toHaveBeenCalledWith(32);
    expect(app.engine.keyGenerate).toHaveBeenCalledWith(
      expect.objectContaining({
        spec: { type: 'p256' },
        role: 'issuer',
        seed: { type: 'entropy', bytes: toB64u(Uint8Array.from({ length: 32 }, (_, i) => i)) },
      }),
    );
    expect(card.provenance).toEqual({ type: 'generated' });
    expect(card.role).toBe('issuer');
    expect(app.keys.cards).toHaveLength(1);
  });

  it('the well-known test seed and user seeds are deterministic', async () => {
    const app = setupApp();
    await app.keys.generate({ type: 'ed25519' }, { seed: { type: 'well_known' } });
    await app.keys.generate({ type: 'ml_dsa65' }, { seed: { type: 'text', seed: 'my seed' } });
    const seeds = app.engine.keyGenerate.mock.calls.map((c) => c[0].seed);
    expect(seeds).toEqual([{ type: 'well_known' }, { type: 'seed', bytes: textToB64u('my seed') }]);
    expect(app.platform.randomBytes).not.toHaveBeenCalled();
  });

  it('can set a kid from the thumbprint right away', async () => {
    const app = setupApp();
    await app.keys.generate(
      { type: 'p256' },
      { seed: { type: 'well_known' }, kid: { type: 'jwk_thumbprint', hash: 'sha256' } },
    );
    expect(app.engine.keyGenerate.mock.calls[0]?.[0].kid).toEqual({
      type: 'jwk_thumbprint',
      hash: 'sha256',
    });
  });
});

describe('import', () => {
  it('a set imports as several cards with the same provenance', async () => {
    const app = setupApp();
    app.engine.keyImport.mockResolvedValueOnce([fx.issuerInfo, fx.holderInfo]);
    const cards = await app.keys.importBytes(utf8('{"keys":[…]}'), {
      type: 'file',
      name: 'jwks.json',
    });
    expect(cards).toHaveLength(2);
    expect(cards.map((c) => c.provenance)).toEqual([
      { type: 'file', name: 'jwks.json' },
      { type: 'file', name: 'jwks.json' },
    ]);
    expect(new Set(app.keys.cards.map((c) => c.id)).size).toBe(2);
  });

  it('from the clipboard', async () => {
    const app = setupApp();
    app.platform.clipboard = fx.VERIFIER_JWK;
    const cards = await app.keys.importFromClipboard();
    expect(app.platform.readClipboard).toHaveBeenCalled();
    expect(app.engine.keyImport).toHaveBeenCalledWith(
      expect.objectContaining({ bytes: textToB64u(fx.VERIFIER_JWK) }),
    );
    expect(cards[0]?.provenance).toEqual({ type: 'clipboard' });
  });

  it('from a file, or nothing when the dialog is cancelled', async () => {
    const app = setupApp();
    app.platform.files = [{ name: 'issuer.pem', bytes: utf8('-----BEGIN PUBLIC KEY-----') }, null];
    const cards = await app.keys.importFromFile();
    expect(cards[0]?.provenance).toEqual({ type: 'file', name: 'issuer.pem' });
    expect(await app.keys.importFromFile()).toEqual([]);
    expect(app.engine.keyImport).toHaveBeenCalledTimes(1);
  });

  it('from a URL only after confirmation', async () => {
    const app = setupApp();
    const url = 'https://issuer.example/jwks.json';
    const no = await app.keys.fetchFromUrl(
      url,
      vi.fn(async () => false),
    );
    expect(no.outcome.type).toBe('cancelled');
    expect(app.platform.fetchUrl).not.toHaveBeenCalled();
    const yes = await app.keys.fetchFromUrl(
      url,
      vi.fn(async () => true),
    );
    expect(app.platform.fetchUrl).toHaveBeenCalledWith(url);
    expect(yes.cards[0]?.provenance).toEqual({ type: 'url', url });
  });
});

describe('export', () => {
  it('labels private clipboard copies and marks them sensitive', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard);
    const message = await app.keys.copyToClipboard('key-1', { type: 'jwk' }, 'private');
    expect(app.engine.keyExport).toHaveBeenCalledWith(
      expect.objectContaining({ format: { type: 'jwk' }, visibility: 'private' }),
    );
    expect(app.platform.writeClipboard).toHaveBeenCalledWith(fx.ISSUER_JWK, { sensitive: true });
    expect(message).toMatch(/private key/i);
  });

  it('public copies are not sensitive', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard);
    const message = await app.keys.copyToClipboard('key-1', { type: 'jwk' }, 'public');
    expect(app.platform.writeClipboard).toHaveBeenCalledWith(fx.VERIFIER_JWK, { sensitive: false });
    expect(message).toMatch(/public key/i);
    expect(message).not.toMatch(/private/i);
  });

  it('saves to a file through the platform', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard);
    expect(await app.keys.saveToFile('key-1', { type: 'jwk' }, 'public')).toBe(true);
    expect(app.platform.saveFile).toHaveBeenCalledWith(
      expect.stringMatching(/\.json$/),
      expect.anything(),
    );
  });
});

describe('cards', () => {
  it('derive public creates a linked card', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard);
    const pub = await app.keys.derivePublic('key-1');
    expect(app.engine.keyPublic).toHaveBeenCalledWith(
      expect.objectContaining({ bytes: fx.issuerInfo.key.bytes }),
    );
    expect(pub.provenance).toEqual({ type: 'derived_key', parent: 'key-1', how: 'public' });
    expect(pub.info.private).toBe(false);
    expect(app.keys.cards).toHaveLength(2);
  });

  it('refs carry the label and role; roles and kids can change', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard, fx.holderCard);
    app.keys.setRole('key-2', 'verifier');
    expect(app.keys.refs().map((r) => [r.label, r.role])).toEqual([
      ['Issuer P-256', 'issuer'],
      ['Holder Ed25519', 'verifier'],
    ]);
    const updated = await app.keys.assignKid('key-1', { type: 'jwk_thumbprint', hash: 'sha256' });
    expect(updated.info.kid).toEqual({ type: 'text', value: fx.issuerInfo.jwk_thumbprint });
    expect(app.keys.get('key-1')?.info.kid).toEqual(updated.info.kid);
  });
});
