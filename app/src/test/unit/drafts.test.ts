// Typed tabs (#43 under SPEC §3, §4.1): the empty startup tab keeps a
// draft (format, detected, explicit type); typed text parses as the tab's
// type and never re-runs detection; an explicit type sticks; typed tabs
// are never stale. Plus the draft rules in logic/drafts.ts.
import { describe, expect, it, vi } from 'vitest';
import { b64uToText } from '../../lib/engine/bytes';
import type { Kind } from '../../lib/engine/types';
import { TAB_TYPES, effectiveDraftKind } from '../../lib/logic/drafts';
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

// The empty tab's Type picker also offers the compact JOSE types (SPEC
// §4.1): typed compact serialization parses as the picked kind
// (`parseEdit`, empty base), never through detection.
describe('JWT and SD-JWT tab types', () => {
  const sdJwtToken = b64uToText(fx.sdJwt.bytes);
  const typeOf = (label: string) => TAB_TYPES.find((t) => t.label === label);

  it('the Type picker lists JWT and SD-JWT after the claim types', () => {
    const labels = TAB_TYPES.map((t) => t.label);
    expect(labels.slice(0, 2)).toEqual(['JSON claims', 'EDN claims']);
    expect(labels).toContain('JWT');
    expect(labels).toContain('SD-JWT');
    expect(typeOf('JWT')?.kind).toEqual({ type: 'jwt' });
    expect(typeOf('SD-JWT')?.kind).toEqual({ type: 'sd_jwt', kb: false });
    // ids are unique (they are the <option> values)
    expect(new Set(TAB_TYPES.map((t) => t.id)).size).toBe(TAB_TYPES.length);
  });

  for (const [label, kind, text, doc] of [
    ['JWT', { type: 'jwt' }, fx.jwtToken, fx.jwt],
    ['SD-JWT', { type: 'sd_jwt', kb: false }, sdJwtToken, fx.sdJwt],
  ] as const) {
    it(`typing a compact token under ${label} parses it as ${kind.type}, no detection`, async () => {
      const app = setupApp();
      const tab = app.workspace.tabs[0];
      const type = typeOf(label);
      if (!tab || !type) throw new Error(`no startup tab or no ${label} type`);
      app.workspace.setTabType(tab.id, type.id);
      expect(app.workspace.tabType(tab).label).toBe(label);
      app.engine.parseEdit.mockResolvedValue(fx.edited(doc));
      await app.workspace.applyEdit(tab.id, text);
      expect(app.engine.detect).not.toHaveBeenCalled();
      expect(app.engine.open).not.toHaveBeenCalled();
      expect(app.engine.parseEdit).toHaveBeenCalledWith(
        expect.objectContaining({ kind: kind as Kind, base: '', text }),
      );
      expect(tab.empty).toBe(false);
      expect(tab.doc.kind).toEqual(kind);
      expect(tab.doc.disclosures).toHaveLength(doc.disclosures.length);
      expect(tab.title).toBe(`Tab ${tab.number} · ${label}`);
      expect(tab.stale).toBe(false);

      // a later paste or edit (the tab is no longer empty) keeps the type
      await app.workspace.applyEdit(tab.id, `${text} `);
      expect(app.engine.detect).not.toHaveBeenCalled();
      expect(app.engine.parseEdit).toHaveBeenLastCalledWith(
        expect.objectContaining({ kind: kind as Kind, text: `${text} ` }),
      );
    });
  }

  it('under SD-JWT the parsed kb wins: a typed SD-JWT+KB is titled SD-JWT+KB', async () => {
    const app = setupApp();
    const tab = app.workspace.tabs[0];
    const type = typeOf('SD-JWT');
    if (!tab || !type) throw new Error('no startup tab or no SD-JWT type');
    app.workspace.setTabType(tab.id, type.id);
    app.engine.parseEdit.mockResolvedValue(fx.edited(fx.sdJwtKb));
    const text = b64uToText(fx.sdJwtKb.bytes);
    await app.workspace.applyEdit(tab.id, text);
    expect(app.engine.detect).not.toHaveBeenCalled();
    expect(tab.doc.kind).toEqual({ type: 'sd_jwt', kb: true });
    expect(tab.title).toBe(`Tab ${tab.number} · SD-JWT+KB`);
    expect(app.workspace.draftKind(tab)).toEqual({ type: 'sd_jwt', kb: true });
  });

  it('there is no separate SD-JWT+KB entry in the Type picker', () => {
    expect(TAB_TYPES.map((t) => t.label)).not.toContain('SD-JWT+KB');
  });

  it('Clear puts a JWT-typed tab back to the default type', async () => {
    const app = setupApp();
    const tab = app.workspace.tabs[0];
    const type = typeOf('JWT');
    if (!tab || !type) throw new Error('no startup tab or no JWT type');
    app.workspace.setTabType(tab.id, type.id);
    app.workspace.clearTab(tab.id);
    expect(app.workspace.tabType(tab).label).toBe('JSON claims');
  });
});
