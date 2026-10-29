// The Workspace store: opening inputs, derived tabs and provenance, view
// state across re-renders and edits (SPEC §3–§6).
import { describe, expect, it } from 'vitest';
import { toB64u, utf8 } from '../../lib/engine/bytes';
import type { ActionRequest } from '../../lib/stores/workspace.svelte';
import * as fx from '../fixtures';
import { seedKeys, seedTab, setupApp } from '../render';

const RANDOM_32 = toB64u(Uint8Array.from({ length: 32 }, (_, i) => i));

describe('opening inputs', () => {
  it('detects, opens the top candidate, and activates a new tab', async () => {
    const app = setupApp();
    const input = utf8(fx.jwtToken);
    const res = await app.workspace.openInput(input, { type: 'pasted' });
    expect(res.type).toBe('tab');
    expect(app.engine.detect).toHaveBeenCalledWith(input);
    expect(app.engine.open).toHaveBeenCalledWith(
      input,
      fx.jwtCandidates[0],
      expect.objectContaining({ now: fx.NOW, local_offset_minutes: 60 }),
    );
    const tab = app.workspace.active;
    expect(tab?.doc.kind).toEqual({ type: 'jwt' });
    expect(tab?.provenance).toEqual({ type: 'pasted' });
    expect(tab?.title).toMatch(/JWT/);
    expect(tab?.candidates).toEqual(fx.jwtCandidates);
  });

  it('routes keys to the key panel instead of opening a tab', async () => {
    const app = setupApp();
    app.engine.detect.mockResolvedValueOnce(fx.jwkCandidates);
    const res = await app.workspace.openInput(utf8(fx.VERIFIER_JWK), { type: 'clipboard' });
    expect(res.type).toBe('keys');
    expect(app.engine.keyImport).toHaveBeenCalled();
    expect(app.engine.open).not.toHaveBeenCalled();
    expect(app.workspace.tabs).toHaveLength(0);
    expect(app.keys.cards[0]?.provenance).toEqual({ type: 'clipboard' });
  });

  it('re-opens the same input as another candidate ("Detected as…")', async () => {
    const app = setupApp();
    app.engine.detect.mockResolvedValueOnce(fx.containerCandidates);
    const res = await app.workspace.openInput(utf8('{"credential":"…"}'), { type: 'pasted' });
    if (res.type !== 'tab') throw new Error(res.type);
    await app.workspace.chooseCandidate(res.tabId, 1);
    expect(app.engine.open).toHaveBeenLastCalledWith(
      expect.any(Uint8Array),
      fx.containerCandidates[1],
      expect.anything(),
    );
    const tab = app.workspace.tab(res.tabId);
    expect(tab?.candidateIndex).toBe(1);
    expect(tab?.doc.kind).toEqual({ type: 'sd_jwt', kb: false });
    expect(app.workspace.tabs).toHaveLength(1);
  });

  it('numbers tabs in creation order and never reuses numbers', async () => {
    const app = setupApp();
    await app.workspace.openInput(utf8('a'), { type: 'pasted' });
    await app.workspace.openInput(utf8('b'), { type: 'pasted' });
    const second = app.workspace.tabs[1];
    app.workspace.close(second?.id ?? '');
    await app.workspace.openInput(utf8('c'), { type: 'pasted' });
    expect(app.workspace.tabs.map((t) => t.number)).toEqual([1, 3]);
  });
});

describe('actions open derived tabs', () => {
  it('Issue sends the claims, issuer key, SD marks, and platform randomness', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard, fx.holderCard);
    const parent = seedTab(app.workspace, fx.jsonClaims);
    app.workspace.toggleSdMark(parent.id, 'given_name');
    const child = await app.workspace.runAction(parent.id, {
      action: 'issue',
      issuerKeyId: 'key-1',
    });
    const req = app.engine.issue.mock.calls[0]?.[0];
    expect(req?.claims).toEqual({ kind: fx.jsonClaims.kind, bytes: fx.jsonClaims.bytes });
    expect(req?.issuer.bytes).toBe(fx.issuerInfo.key.bytes);
    expect(req?.issuer.label).toBe('Issuer P-256');
    expect(req?.sd.marks).toEqual(['given_name']);
    expect(req?.randomness).toBe(RANDOM_32);
    expect(child.provenance).toEqual({ type: 'derived', parent: parent.id, action: 'issue' });
    expect(app.workspace.activeId).toBe(child.id);
    expect(app.workspace.tabs).toHaveLength(2);
  });

  it('Present uses the clock for iat, the holder key, aud, and nonce', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard, fx.holderCard);
    app.settings.clockOverride = 1_900_000_000;
    const parent = seedTab(app.workspace, fx.sdJwt);
    const child = await app.workspace.runAction(parent.id, {
      action: 'present',
      keep: [1],
      holderKeyId: 'key-2',
      aud: 'https://verifier.example',
      nonce: 'n-0S6',
    });
    expect(app.engine.present).toHaveBeenCalledWith(
      expect.objectContaining({
        doc: { kind: fx.sdJwt.kind, bytes: fx.sdJwt.bytes },
        keep: [1],
        iat: 1_900_000_000,
        aud: 'https://verifier.example',
        nonce: { type: 'text', value: 'n-0S6' },
        randomness: RANDOM_32,
      }),
    );
    expect(app.engine.present.mock.calls[0]?.[0].holder.bytes).toBe(fx.holderInfo.key.bytes);
    expect(child.provenance).toMatchObject({ type: 'derived', action: 'present' });
  });

  it.each<
    [string, ActionRequest, 'disclose' | 'tamper' | 'reencode' | 'editDisclosures' | 'resign']
  >([
    ['disclose', { action: 'disclose', keep: [0] }, 'disclose'],
    ['tamper', { action: 'tamper', op: { type: 'strip_signature' } }, 'tamper'],
    ['reencode', { action: 'reencode', cbor: 'deterministic' }, 'reencode'],
    [
      'edit_disclosures',
      { action: 'edit_disclosures', ops: [{ type: 'remove', index: 0 }] },
      'editDisclosures',
    ],
    ['resign', { action: 'resign', keyId: 'key-1' }, 'resign'],
  ])('%s opens a derived tab', async (action, req, method) => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard);
    const parent = seedTab(app.workspace, fx.sdJwt);
    const child = await app.workspace.runAction(parent.id, req);
    expect(app.engine[method]).toHaveBeenCalledTimes(1);
    expect(child.provenance).toEqual({ type: 'derived', parent: parent.id, action });
    expect(app.workspace.activeId).toBe(child.id);
    expect(app.workspace.tab(parent.id)?.doc).toEqual(fx.sdJwt);
  });

  it('builds a breadcrumb from the root tab', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard, fx.holderCard);
    const root = seedTab(app.workspace, fx.jsonClaims);
    const issued = await app.workspace.runAction(root.id, {
      action: 'issue',
      issuerKeyId: 'key-1',
    });
    const presented = await app.workspace.runAction(issued.id, {
      action: 'present',
      keep: [],
      holderKeyId: 'key-2',
    });
    expect(app.workspace.breadcrumb(presented.id)).toEqual([
      { tabId: root.id, title: root.title, action: null },
      { tabId: issued.id, title: issued.title, action: 'issue' },
      { tabId: presented.id, title: presented.title, action: 'present' },
    ]);
  });
});

describe('validate', () => {
  it('passes the panel keys, the clock, skew, and expectations; stores the report', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard, fx.verifierCard);
    app.settings.skew = 120;
    app.settings.expectedAud = 'https://verifier.example';
    const tab = seedTab(app.workspace, fx.jwt);
    const report = await app.workspace.validate(tab.id);
    const req = app.engine.validate.mock.calls[0]?.[0];
    expect(req?.now).toBe(fx.NOW);
    expect(req?.skew).toBe(120);
    expect(req?.expected_aud).toBe('https://verifier.example');
    expect(req?.keys.map((k) => k.label)).toEqual(['Issuer P-256', 'Verifier P-256']);
    expect(report).toEqual(fx.jwtReport);
    expect(app.workspace.tab(tab.id)?.report).toEqual(fx.jwtReport);
  });
});

describe('view state survives re-render and edit', () => {
  it('keeps collapsed nodes and the selection across a re-render', async () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.cwt);
    app.workspace.setCollapsed(tab.id, 'payload', true);
    app.workspace.select(tab.id, 'payload/~e/4');
    app.settings.decodedViews = false;
    await app.workspace.rerender(tab.id);
    expect(app.engine.render).toHaveBeenCalledWith(
      expect.objectContaining({ view: expect.objectContaining({ decoded_views: false }) }),
    );
    const after = app.workspace.tab(tab.id);
    expect(after?.collapsed.has('payload')).toBe(true);
    expect(after?.selected).toBe('payload/~e/4');
  });

  it('a stale edit replaces the document, keeps view state, and marks the tab stale', async () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.jwt);
    app.workspace.setLiveEdit(tab.id, true);
    app.workspace.setCollapsed(tab.id, 'protected', true);
    const text = fx.jwtEdited.main.text;
    const res = await app.workspace.applyEdit(tab.id, text);
    expect(app.engine.parseEdit).toHaveBeenCalledWith(
      expect.objectContaining({ kind: fx.jwt.kind, base: fx.jwt.bytes, text }),
    );
    expect(res.signature_stale).toBe(true);
    const after = app.workspace.tab(tab.id);
    expect(after?.doc.bytes).toBe(fx.jwtEdited.bytes);
    expect(after?.stale).toBe(true);
    expect(after?.collapsed.has('protected')).toBe(true);
  });

  it('an invalid edit keeps the last good document and shows the diagnostic', async () => {
    const app = setupApp();
    app.engine.parseEdit.mockResolvedValueOnce(fx.editInvalid);
    const tab = seedTab(app.workspace, fx.jwt);
    app.workspace.setLiveEdit(tab.id, true);
    await app.workspace.applyEdit(tab.id, '{ "protected": ');
    const after = app.workspace.tab(tab.id);
    expect(after?.doc).toEqual(fx.jwt);
    expect(after?.stale).toBe(false);
    expect(after?.editDiagnostics).toEqual(fx.editInvalid.diagnostics);
  });

  it('"Keep original signature" keeps the stale bytes and labels the tab tampered', async () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.jwt);
    await app.workspace.applyEdit(tab.id, fx.jwtEdited.main.text);
    app.workspace.keepOriginalSignature(tab.id);
    const after = app.workspace.tab(tab.id);
    expect(after?.tampered).toBe(true);
    expect(after?.stale).toBe(true);
    expect(after?.doc.bytes).toBe(fx.jwtEdited.bytes);
  });
});
