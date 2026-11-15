// The Workspace store: the startup empty tab, derived tabs and provenance,
// view state across re-renders and edits (SPEC §3–§6). Filling tabs from a
// paste, drop, file, or the clipboard is pinned through the UI in
// components/emptyTab.test.ts.
import { describe, expect, it } from 'vitest';
import { toB64u, utf8 } from '../../lib/engine/bytes';
import type { ActionRequest } from '../../lib/stores/workspace.svelte';
import * as fx from '../fixtures';
import { seedKeys, seedTab, setupApp } from '../render';

const RANDOM_32 = toB64u(Uint8Array.from({ length: 32 }, (_, i) => i));

describe('tabs', () => {
  it('the workspace starts with one empty, editable tab (SPEC §4)', () => {
    const app = setupApp();
    expect(app.workspace.tabs).toHaveLength(1);
    const tab = app.workspace.tabs[0];
    expect(tab?.empty).toBe(true);
    expect(tab?.liveEdit).toBe(true);
    expect(tab?.editText).toBe('');
    expect(app.workspace.activeId).toBe(tab?.id);
    expect(app.engine.detect).not.toHaveBeenCalled();
  });

  it('typing into the empty tab parses as its type and never detects', async () => {
    const app = setupApp();
    const tab = app.workspace.tabs[0];
    if (!tab) throw new Error('no startup tab');
    await app.workspace.applyEdit(tab.id, '{"iss":"x"}');
    expect(app.engine.detect).not.toHaveBeenCalled();
    expect(app.engine.parseEdit).toHaveBeenCalledWith(
      expect.objectContaining({ kind: { type: 'json_claims' }, text: '{"iss":"x"}' }),
    );
    expect(app.workspace.tab(tab.id)?.empty).toBe(false);
  });

  it('re-opens the same input as another candidate ("Detected as…")', async () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.jwt, {
      candidates: fx.containerCandidates,
      input: utf8('{"credential":"…"}'),
    });
    await app.workspace.chooseCandidate(tab.id, 1);
    expect(app.engine.open).toHaveBeenLastCalledWith(
      expect.any(Uint8Array),
      fx.containerCandidates[1],
      expect.anything(),
    );
    const after = app.workspace.tab(tab.id);
    expect(after?.candidateIndex).toBe(1);
    expect(after?.doc.kind).toEqual({ type: 'sd_jwt', kb: false });
    expect(app.workspace.tabs).toHaveLength(1);
    expect(app.engine.detect).not.toHaveBeenCalled();
  });
});

describe('actions open derived tabs', () => {
  it('Issue sends the claims, the Issuer area key, SD marks, and platform randomness', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard, fx.holderCard);
    const parent = seedTab(app.workspace, fx.jsonClaims);
    app.workspace.toggleSdMark(parent.id, 'given_name');
    const child = await app.workspace.runAction(parent.id, { action: 'issue' });
    const req = app.engine.issue.mock.calls[0]?.[0];
    expect(req?.cnf ?? null).toBeNull();
    expect(req?.claims).toEqual({ kind: fx.jsonClaims.kind, bytes: fx.jsonClaims.bytes });
    expect(req?.issuer.bytes).toBe(fx.issuerInfo.key.bytes);
    expect(req?.issuer.label).toBe('Issuer P-256');
    expect(req?.sd?.marks).toEqual(['given_name']);
    expect(req?.randomness).toBe(RANDOM_32);
    expect(child.provenance).toEqual({ type: 'derived', parent: parent.id, action: 'issue' });
    expect(app.workspace.activeId).toBe(child.id);
    expect(app.workspace.tabs).toHaveLength(2);
  });

  it('Issue with cnf binds the Holder area key', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard, fx.holderCard);
    const parent = seedTab(app.workspace, fx.jsonClaims);
    await app.workspace.runAction(parent.id, { action: 'issue', cnf: true });
    const req = app.engine.issue.mock.calls[0]?.[0];
    expect(req?.issuer.bytes).toBe(fx.issuerInfo.key.bytes);
    expect(req?.cnf).toEqual({
      type: 'key',
      key: expect.objectContaining({ bytes: fx.holderInfo.key.bytes }),
    });
  });

  it('Present uses the clock for iat, the Holder area key, aud, and nonce', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard, fx.holderCard);
    app.settings.clockOverride = 1_900_000_000;
    const parent = seedTab(app.workspace, fx.sdJwt);
    const child = await app.workspace.runAction(parent.id, {
      action: 'present',
      keep: [1],
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
    ['resign', { action: 'resign', key: 'issuer' }, 'resign'],
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
    const issued = await app.workspace.runAction(root.id, { action: 'issue' });
    const presented = await app.workspace.runAction(issued.id, { action: 'present', keep: [] });
    expect(app.workspace.breadcrumb(presented.id)).toEqual([
      { tabId: root.id, title: root.title, action: null },
      { tabId: issued.id, title: issued.title, action: 'issue' },
      { tabId: presented.id, title: presented.title, action: 'present' },
    ]);
  });
});

describe('validate', () => {
  it('passes the area keys, the clock, skew, and expectations; stores the report', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard, fx.holderCard);
    app.settings.skew = 120;
    app.settings.expectedAud = 'https://verifier.example';
    const tab = seedTab(app.workspace, fx.jwt);
    const report = await app.workspace.validate(tab.id);
    const req = app.engine.validate.mock.calls[0]?.[0];
    expect(req?.now).toBe(fx.NOW);
    expect(req?.skew).toBe(120);
    expect(req?.expected_aud).toBe('https://verifier.example');
    // the Issuer area's key (or its public part) verifies the credential, the
    // Holder area's key the key binding
    const issuer = req?.keys?.filter((k) => k.role === 'issuer') ?? [];
    const holder = req?.keys?.filter((k) => k.role === 'holder') ?? [];
    expect(issuer).toHaveLength(1);
    expect([fx.issuerInfo.key.bytes, fx.issuerPublicInfo.key.bytes]).toContain(issuer[0]?.bytes);
    expect(holder).toHaveLength(1);
    expect(holder[0]?.bytes).toBe(fx.holderInfo.key.bytes);
    expect(req?.keys).toHaveLength(2);
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
