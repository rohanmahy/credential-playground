// Typed tabs (#43 under SPEC §3, §4.1): the empty startup tab keeps a
// draft (format, detected, explicit type); typed text parses as the tab's
// type and never re-runs detection; an explicit type sticks; typed tabs
// are never stale. Plus the draft rules in logic/drafts.ts.
import { describe, expect, it, vi } from 'vitest';
import { effectiveDraftKind } from '../../lib/logic/drafts';
import { provenanceLabel } from '../../lib/logic/provenance';
import * as fx from '../fixtures';
import { seedKeys, setupApp } from '../render';

/** The startup tab, after typing `text` into it. */
async function typed(text: string) {
  const app = setupApp();
  const tab = app.workspace.tabs[0];
  if (!tab) throw new Error('no startup tab');
  app.engine.parseEdit.mockResolvedValue(fx.edited(fx.jsonDraft));
  await app.workspace.applyEdit(tab.id, text);
  app.engine.parseEdit.mockClear();
  return { app, tab };
}

describe('draft rules', () => {
  it('the explicit type wins, then a detected kind that fits the format, then the default', () => {
    expect(effectiveDraftKind('edn', { type: 'cwt' }, { type: 'sd_cwt' })).toEqual({
      type: 'sd_cwt',
    });
    expect(effectiveDraftKind('edn', { type: 'cwt' }, null)).toEqual({ type: 'cwt' });
    expect(effectiveDraftKind('edn', { type: 'json_claims' }, null)).toEqual({
      type: 'edn_claims',
    });
    expect(effectiveDraftKind('json', { type: 'jws_json', general: false }, null)).toEqual({
      type: 'json_claims',
    });
    expect(effectiveDraftKind('json', null, null)).toEqual({ type: 'json_claims' });
  });

  it('the provenance label of "new" is "New"', () => {
    expect(provenanceLabel({ type: 'new' }, () => '')).toBe('New');
  });
});

describe('the startup tab', () => {
  it('is an empty draft in Live edit with the JSON claims type', () => {
    const app = setupApp();
    const tab = app.workspace.tabs[0];
    expect(tab?.empty).toBe(true);
    expect(tab?.liveEdit).toBe(true);
    expect(tab?.editText).toBe('');
    expect(tab?.draft).toEqual({ format: 'json', detected: null, override: null });
  });

  it('typed text parses as the tab type (empty base) and is not detected', async () => {
    const app = setupApp();
    const tab = app.workspace.tabs[0];
    if (!tab) throw new Error('no startup tab');
    app.engine.parseEdit.mockResolvedValue(fx.edited(fx.jsonDraft));
    await app.workspace.applyEdit(tab.id, fx.DRAFT_JSON_TEXT);
    expect(app.engine.detect).not.toHaveBeenCalled();
    expect(app.engine.parseEdit).toHaveBeenCalledWith(
      expect.objectContaining({
        kind: { type: 'json_claims' },
        base: '',
        text: fx.DRAFT_JSON_TEXT,
      }),
    );
    expect(tab.empty).toBe(false);
    expect(tab.doc.kind).toEqual({ type: 'json_claims' });
    expect(tab.title).toMatch(/JSON claim set/);
  });
});

describe('editing a typed tab', () => {
  it('never re-runs detection', async () => {
    const { app, tab } = await typed(fx.DRAFT_JSON_TEXT);
    await app.workspace.applyEdit(tab.id, fx.CWT_EDN);
    await app.workspace.applyEdit(tab.id, fx.jwtToken);
    expect(app.engine.detect).not.toHaveBeenCalled();
    expect(app.engine.parseEdit).toHaveBeenLastCalledWith(
      expect.objectContaining({ kind: { type: 'json_claims' } }),
    );
  });

  it('an explicit type is kept across edits', async () => {
    const { app, tab } = await typed(fx.CWT_EDN);
    app.engine.parseEdit.mockResolvedValue(fx.cwtDraftEdit);
    await app.workspace.setDraftKind(tab.id, { type: 'cwt' });
    expect(app.engine.parseEdit).toHaveBeenLastCalledWith(
      expect.objectContaining({ kind: { type: 'cwt' }, text: tab.editText }),
    );
    expect(tab.draft?.override).toEqual({ type: 'cwt' });
    expect(tab.doc.kind).toEqual({ type: 'cwt' });

    await app.workspace.applyEdit(tab.id, `${fx.CWT_EDN} `);
    expect(app.engine.parseEdit).toHaveBeenLastCalledWith(
      expect.objectContaining({ kind: { type: 'cwt' } }),
    );
    expect(app.engine.detect).not.toHaveBeenCalled();
  });

  it('is never stale (there is no original signature)', async () => {
    const { app, tab } = await typed(fx.CWT_EDN);
    app.engine.parseEdit.mockResolvedValue(fx.cwtDraftEdit);
    await app.workspace.setDraftKind(tab.id, { type: 'cwt' });
    await app.workspace.applyEdit(tab.id, `${fx.CWT_EDN} `);
    expect(tab.stale).toBe(false);
    expect(tab.tampered).toBe(false);
  });

  it('an edit that does not parse keeps the last document and shows the diagnostic', async () => {
    const { app, tab } = await typed(fx.DRAFT_JSON_TEXT);
    app.engine.parseEdit.mockResolvedValue(fx.editInvalid);
    await app.workspace.applyEdit(tab.id, '{"iss": ');
    expect(tab.editDiagnostics).toEqual(fx.editInvalid.diagnostics);
    expect(tab.doc).toEqual(fx.jsonDraft);
  });

  it('actions follow the type: a typed claim set is issued with the Issuer area key', async () => {
    const { app, tab } = await typed(fx.DRAFT_JSON_TEXT);
    seedKeys(app, fx.issuerCard);
    expect(app.workspace.availability(tab.id).issue.enabled).toBe(true);
    expect(app.workspace.availability(tab.id).validate.enabled).toBe(false);
    await app.workspace.runAction(tab.id, { action: 'issue' });
    expect(app.engine.issue.mock.calls[0]?.[0].claims).toEqual({
      kind: { type: 'json_claims' },
      bytes: fx.jsonDraft.bytes,
    });
    expect(app.engine.issue.mock.calls[0]?.[0].issuer.bytes).toBe(fx.issuerInfo.key.bytes);
  });
});

describe('switching Format of a typed tab', () => {
  it('JSON → EDN converts the text (with registry labels)', async () => {
    const { app, tab } = await typed(fx.DRAFT_JSON_TEXT);
    app.engine.parseEdit.mockResolvedValue(
      fx.edited(fx.convertedToEdn.document ?? fx.emptyEdnDraft),
    );
    const confirm = vi.fn(async () => true);
    expect(await app.workspace.setDraftFormat(tab.id, 'edn', confirm)).toBe(true);
    expect(app.engine.convertClaims).toHaveBeenCalledWith(
      expect.objectContaining({
        text: fx.DRAFT_JSON_TEXT,
        from: 'json',
        to: 'edn',
        map_claim_labels: true,
      }),
    );
    expect(confirm).not.toHaveBeenCalled();
    expect(tab.draft?.format).toBe('edn');
    expect(tab.editText).toBe(fx.DRAFT_EDN_TEXT);
    expect(app.engine.detect).not.toHaveBeenCalled();
  });

  it('EDN → JSON that cannot be represented asks, and keeps the text when declined', async () => {
    const { app, tab } = await typed(fx.DRAFT_JSON_TEXT);
    app.engine.parseEdit.mockResolvedValue(
      fx.edited(fx.convertedToEdn.document ?? fx.emptyEdnDraft),
    );
    await app.workspace.setDraftFormat(tab.id, 'edn', async () => true);
    await app.workspace.applyEdit(tab.id, "{1: h'00'}");
    app.engine.convertClaims.mockResolvedValueOnce(fx.notRepresentable);
    const confirm = vi.fn(async () => false);
    expect(await app.workspace.setDraftFormat(tab.id, 'json', confirm)).toBe(false);
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(tab.draft?.format).toBe('edn');
    expect(tab.editText).toBe("{1: h'00'}");
  });

  it('the same format is a no-op', async () => {
    const { app, tab } = await typed(fx.DRAFT_JSON_TEXT);
    expect(await app.workspace.setDraftFormat(tab.id, 'json', async () => true)).toBe(true);
    expect(app.engine.convertClaims).not.toHaveBeenCalled();
  });
});
