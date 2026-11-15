// The KeyStore as two key areas (SPEC §4.2): `issuer` and `holder` hold
// one KeyCard each (id = role), `forRole` reads them, `cards` lists the
// non-empty ones. Input, detection, create, import, fetch, and the chooser
// are pinned through the UI in components/keyAreas.test.ts.
import { describe, expect, it } from 'vitest';
import * as fx from '../fixtures';
import { seedKeys, setupApp } from '../render';

describe('areas', () => {
  it('start empty', () => {
    const app = setupApp();
    expect(app.keys.issuer).toBeNull();
    expect(app.keys.holder).toBeNull();
    expect(app.keys.forRole('issuer')).toBeNull();
    expect(app.keys.forRole('holder')).toBeNull();
    expect(app.keys.cards).toEqual([]);
  });

  it('hold one key each, read by role; cards lists the filled areas', () => {
    const app = setupApp();
    seedKeys(app, fx.holderCard);
    expect(app.keys.forRole('holder')?.info.jwk_thumbprint).toBe(fx.holderInfo.jwk_thumbprint);
    expect(app.keys.forRole('issuer')).toBeNull();
    expect(app.keys.cards.map((c) => c.role)).toEqual(['holder']);
    seedKeys(app, fx.issuerCard);
    expect(app.keys.cards.map((c) => c.role).sort()).toEqual(['holder', 'issuer']);
  });

  it('a new key replaces the area key', () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard);
    seedKeys(app, fx.publicIssuerCard);
    expect(app.keys.cards).toHaveLength(1);
    expect(app.keys.forRole('issuer')?.info.private).toBe(false);
  });

  it('a card id is its role', () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard, fx.holderCard);
    expect(app.keys.forRole('issuer')?.id).toBe('issuer');
    expect(app.keys.forRole('holder')?.id).toBe('holder');
  });

  it('refs carry the label and the area role', () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard, fx.holderCard);
    const refs = app.keys.refs();
    expect(refs.map((r) => r.role).sort()).toEqual(['holder', 'issuer']);
    expect(refs.find((r) => r.role === 'issuer')?.bytes).toBe(fx.issuerInfo.key.bytes);
  });
});

describe('export', () => {
  it('labels private clipboard copies and marks them sensitive', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard);
    const message = await app.keys.copyToClipboard('issuer', { type: 'jwk' }, 'private');
    expect(app.engine.keyExport).toHaveBeenCalledWith(
      expect.objectContaining({ format: { type: 'jwk' }, visibility: 'private' }),
    );
    expect(app.platform.writeClipboard).toHaveBeenCalledWith(fx.ISSUER_JWK, { sensitive: true });
    expect(message).toMatch(/private key/i);
  });

  it('public copies are not sensitive', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard);
    const message = await app.keys.copyToClipboard('issuer', { type: 'jwk' }, 'public');
    expect(app.platform.writeClipboard).toHaveBeenCalledWith(fx.ISSUER_PUBLIC_JWK, {
      sensitive: false,
    });
    expect(message).toMatch(/public key/i);
    expect(message).not.toMatch(/private/i);
  });

  it('saves to a file through the platform', async () => {
    const app = setupApp();
    seedKeys(app, fx.holderCard);
    expect(await app.keys.saveToFile('holder', { type: 'jwk' }, 'public')).toBe(true);
    expect(app.platform.saveFile).toHaveBeenCalledWith(
      expect.stringMatching(/\.json$/),
      expect.anything(),
    );
  });
});

describe('kid', () => {
  it('assignKid updates the area key in place', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard);
    const updated = await app.keys.assignKid('issuer', { type: 'jwk_thumbprint', hash: 'sha256' });
    expect(updated.info.kid).toEqual({ type: 'text', value: fx.issuerInfo.jwk_thumbprint });
    expect(app.keys.forRole('issuer')?.info.kid).toEqual(updated.info.kid);
    expect(app.keys.cards).toHaveLength(1);
  });
});
