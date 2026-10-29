// New drafts and explicit type (#43): the Workspace store and the draft
// rules (app/TEST-PLAN.md "New drafts and explicit type").
import { describe, expect, it, vi } from 'vitest';
import { textToB64u, utf8 } from '../../lib/engine/bytes';
import {
  DRAFT_KINDS,
  DRAFT_TEMPLATES,
  draftParseKind,
  effectiveDraftKind,
} from '../../lib/logic/drafts';
import { provenanceLabel } from '../../lib/logic/provenance';
import * as fx from '../fixtures';
import { seedKeys, setupApp } from '../render';

async function draft(format: 'json' | 'edn' = 'json') {
  const app = setupApp();
  app.engine.parseEdit.mockResolvedValue(
    fx.edited(format === 'json' ? fx.emptyJsonDraft : fx.emptyEdnDraft),
  );
  app.engine.detect.mockResolvedValue(
    format === 'json' ? fx.jsonClaimsDetected : fx.ednClaimsDetected,
  );
  const tab = await app.workspace.newDraft(format);
  app.engine.parseEdit.mockClear();
  app.engine.detect.mockClear();
  return { app, tab };
}

describe('draft rules', () => {
  it('lists the types per format, claim sets first', () => {
    expect(DRAFT_KINDS.json.map((k) => k.type)).toEqual(['json_claims', 'jwk', 'jwk_set']);
    expect(DRAFT_KINDS.edn.map((k) => k.type)).toEqual([
      'edn_claims',
      'cose_sign1',
      'cwt',
      'sd_cwt',
      'sd_kbt',
      'cose_key',
      'cose_key_set',
    ]);
  });

  it('the explicit type wins, then a detected kind that fits the format, then the default', () => {
    expect(effectiveDraftKind('edn', { type: 'cwt' }, { type: 'cose_key' })).toEqual({
      type: 'cose_key',
    });
    expect(effectiveDraftKind('edn', { type: 'cwt' }, null)).toEqual({ type: 'cwt' });
    // `{}` is valid JSON too and detects as a JSON claim set: not an EDN type
    expect(effectiveDraftKind('edn', { type: 'json_claims' }, null)).toEqual({
      type: 'edn_claims',
    });
    expect(effectiveDraftKind('json', { type: 'jws_json', general: false }, null)).toEqual({
      type: 'json_claims',
    });
    expect(effectiveDraftKind('json', null, null)).toEqual({ type: 'json_claims' });
    expect(effectiveDraftKind('json', { type: 'jwk' }, null)).toEqual({ type: 'jwk' });
  });

  it('JWK drafts are parsed as JSON claim sets; the rest as their own kind', () => {
    expect(draftParseKind({ type: 'jwk' })).toEqual({ type: 'json_claims' });
    expect(draftParseKind({ type: 'jwk_set' })).toEqual({ type: 'json_claims' });
    expect(draftParseKind({ type: 'cose_key' })).toEqual({ type: 'cose_key' });
    expect(draftParseKind({ type: 'cwt' })).toEqual({ type: 'cwt' });
  });

  it('the provenance of a draft is "New"', () => {
    expect(provenanceLabel({ type: 'new' }, () => '')).toBe('New');
  });
});

describe('newDraft', () => {
  it('opens an active tab in Live edit with the JSON template', async () => {
    const app = setupApp();
    app.engine.parseEdit.mockResolvedValue(fx.edited(fx.emptyJsonDraft));
    const tab = await app.workspace.newDraft('json');
    expect(app.engine.parseEdit).toHaveBeenCalledWith(
      expect.objectContaining({
        kind: { type: 'json_claims' },
        base: '',
        text: DRAFT_TEMPLATES.json,
      }),
    );
    expect(app.workspace.activeId).toBe(tab.id);
    expect(tab.liveEdit).toBe(true);
    expect(tab.editText).toBe(DRAFT_TEMPLATES.json);
    expect(tab.provenance).toEqual({ type: 'new' });
    expect(tab.draft).toEqual({ format: 'json', detected: null, override: null });
    expect(tab.doc.kind).toEqual({ type: 'json_claims' });
    expect(tab.title).toMatch(/JSON claim set/);
    expect(app.engine.open).not.toHaveBeenCalled();
  });

  it('defaults to JSON; EDN drafts start as EDN claim sets', async () => {
    const app = setupApp();
    app.engine.parseEdit.mockResolvedValue(fx.edited(fx.emptyJsonDraft));
    expect((await app.workspace.newDraft()).draft?.format).toBe('json');
    app.engine.parseEdit.mockResolvedValue(fx.edited(fx.emptyEdnDraft));
    const edn = await app.workspace.newDraft('edn');
    expect(app.engine.parseEdit).toHaveBeenLastCalledWith(
      expect.objectContaining({ kind: { type: 'edn_claims' }, text: DRAFT_TEMPLATES.edn }),
    );
    expect(edn.draft?.format).toBe('edn');
    expect(app.workspace.tabs).toHaveLength(2);
  });
});

describe('editing a draft', () => {
  it('re-detects the text and parses it as the detected type', async () => {
    const { app, tab } = await draft('edn');
    app.engine.detect.mockResolvedValue(fx.cwtEdnDetected);
    app.engine.parseEdit.mockResolvedValue(fx.cwtDraftEdit);
    await app.workspace.applyEdit(tab.id, fx.CWT_EDN);
    expect(app.engine.detect).toHaveBeenCalledWith(utf8(fx.CWT_EDN));
    expect(app.engine.parseEdit).toHaveBeenCalledWith(
      expect.objectContaining({ kind: { type: 'cwt' }, base: '', text: fx.CWT_EDN }),
    );
    expect(tab.draft?.detected).toEqual({ type: 'cwt' });
    expect(tab.doc.kind).toEqual({ type: 'cwt' });
    expect(tab.title).toMatch(/CWT/);
  });

  it('never marks a draft stale (there is no original signature)', async () => {
    const { app, tab } = await draft('edn');
    app.engine.detect.mockResolvedValue(fx.cwtEdnDetected);
    app.engine.parseEdit.mockResolvedValue(fx.cwtDraftEdit);
    await app.workspace.applyEdit(tab.id, fx.CWT_EDN);
    expect(tab.stale).toBe(false);
    expect(tab.tampered).toBe(false);
  });

  it('falls back to the format default when detection finds nothing that fits', async () => {
    const { app, tab } = await draft('json');
    app.engine.detect.mockResolvedValue([]);
    app.engine.parseEdit.mockResolvedValue(fx.editInvalid);
    await app.workspace.applyEdit(tab.id, '{"iss": ');
    expect(app.engine.parseEdit).toHaveBeenCalledWith(
      expect.objectContaining({ kind: { type: 'json_claims' } }),
    );
    expect(tab.editDiagnostics).toEqual(fx.editInvalid.diagnostics);
    expect(tab.doc).toEqual(fx.emptyJsonDraft);
  });

  it('an explicit type overrides detection and is kept across edits until cleared', async () => {
    const { app, tab } = await draft('edn');
    app.engine.parseEdit.mockResolvedValue(fx.edited(fx.coseKeyDraft));
    await app.workspace.setDraftKind(tab.id, { type: 'cose_key' });
    expect(app.engine.parseEdit).toHaveBeenLastCalledWith(
      expect.objectContaining({ kind: { type: 'cose_key' }, text: tab.editText }),
    );
    expect(tab.draft?.override).toEqual({ type: 'cose_key' });
    expect(tab.doc.kind).toEqual({ type: 'cose_key' });

    app.engine.detect.mockResolvedValue(fx.ednClaimsDetected);
    await app.workspace.applyEdit(tab.id, fx.ISSUER_CWK_EDN);
    expect(app.engine.parseEdit).toHaveBeenLastCalledWith(
      expect.objectContaining({ kind: { type: 'cose_key' } }),
    );
    expect(tab.draft?.detected).toEqual({ type: 'edn_claims' });

    app.engine.parseEdit.mockResolvedValue(fx.edited(fx.emptyEdnDraft));
    await app.workspace.setDraftKind(tab.id, null);
    expect(tab.draft?.override).toBeNull();
    expect(app.engine.parseEdit).toHaveBeenLastCalledWith(
      expect.objectContaining({ kind: { type: 'edn_claims' } }),
    );
  });

  it('JWK drafts are shown as JSON and go to the key panel on request', async () => {
    const { app, tab } = await draft('json');
    app.engine.detect.mockResolvedValue(fx.jwkDetected);
    app.engine.parseEdit.mockResolvedValue(fx.edited(fx.emptyJsonDraft));
    await app.workspace.applyEdit(tab.id, fx.VERIFIER_JWK);
    expect(app.engine.parseEdit).toHaveBeenLastCalledWith(
      expect.objectContaining({ kind: { type: 'json_claims' } }),
    );
    expect(tab.draft?.detected).toEqual({ type: 'jwk' });
    const cards = await app.workspace.importDraftKey(tab.id);
    expect(app.engine.keyImport).toHaveBeenCalledWith({
      bytes: textToB64u(fx.VERIFIER_JWK),
      format: { type: 'jwk' },
    });
    expect(cards[0]?.provenance).toEqual({ type: 'new' });
  });

  it('COSE_Key drafts import the CBOR bytes', async () => {
    const { app, tab } = await draft('edn');
    app.engine.parseEdit.mockResolvedValue(fx.edited(fx.coseKeyDraft));
    await app.workspace.setDraftKind(tab.id, { type: 'cose_key' });
    await app.workspace.importDraftKey(tab.id);
    expect(app.engine.keyImport).toHaveBeenCalledWith({
      bytes: fx.coseKeyDraft.bytes,
      format: { type: 'cose_key' },
    });
  });

  it('a detected kind that is not a draft type can be opened as such in a new tab', async () => {
    const { app, tab } = await draft('json');
    const text = '{"payload":"e30","protected":"e30","signature":""}';
    app.engine.detect.mockResolvedValue(fx.jwsJsonDetected);
    app.engine.parseEdit.mockResolvedValue(fx.edited(fx.jsonDraft));
    await app.workspace.applyEdit(tab.id, text);
    expect(tab.doc.kind).toEqual({ type: 'json_claims' });
    const opened = await app.workspace.openDraftAs(tab.id);
    expect(app.engine.open).toHaveBeenCalledWith(
      utf8(text),
      fx.jwsJsonDetected[0],
      expect.anything(),
    );
    expect(opened.provenance).toEqual({ type: 'new' });
    expect(opened.draft ?? null).toBeNull();
    expect(app.workspace.activeId).toBe(opened.id);
  });

  it('actions follow the type: a claim-set draft can be issued', async () => {
    const { app, tab } = await draft('json');
    seedKeys(app, fx.issuerCard);
    app.engine.detect.mockResolvedValue(fx.jsonClaimsDetected);
    app.engine.parseEdit.mockResolvedValue(fx.edited(fx.jsonDraft));
    await app.workspace.applyEdit(tab.id, fx.DRAFT_JSON_TEXT);
    expect(app.workspace.availability(tab.id).issue.enabled).toBe(true);
    expect(app.workspace.availability(tab.id).validate.enabled).toBe(false);
    await app.workspace.runAction(tab.id, { action: 'issue', issuerKeyId: 'key-1' });
    expect(app.engine.issue.mock.calls[0]?.[0].claims).toEqual({
      kind: { type: 'json_claims' },
      bytes: fx.jsonDraft.bytes,
    });
  });
});

describe('switching Format', () => {
  it('JSON → EDN converts the text (with registry labels)', async () => {
    const { app, tab } = await draft('json');
    tab.editText = fx.DRAFT_JSON_TEXT;
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
    expect(app.engine.parseEdit).toHaveBeenLastCalledWith(
      expect.objectContaining({ kind: { type: 'edn_claims' }, text: fx.DRAFT_EDN_TEXT }),
    );
  });

  it('EDN → JSON that cannot be represented asks, and keeps the draft when declined', async () => {
    const { app, tab } = await draft('edn');
    tab.editText = "{1: h'00'}";
    app.engine.convertClaims.mockResolvedValueOnce(fx.notRepresentable);
    const confirm = vi.fn(async () => false);
    expect(await app.workspace.setDraftFormat(tab.id, 'json', confirm)).toBe(false);
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(tab.draft?.format).toBe('edn');
    expect(tab.editText).toBe("{1: h'00'}");
  });

  it('…and starts over from the template when the user agrees', async () => {
    const { app, tab } = await draft('edn');
    tab.editText = "{1: h'00'}";
    app.engine.convertClaims.mockResolvedValueOnce(fx.notRepresentable);
    app.engine.parseEdit.mockResolvedValue(fx.edited(fx.emptyJsonDraft));
    expect(await app.workspace.setDraftFormat(tab.id, 'json', async () => true)).toBe(true);
    expect(tab.draft?.format).toBe('json');
    expect(tab.editText).toBe(DRAFT_TEMPLATES.json);
    expect(tab.doc.kind).toEqual({ type: 'json_claims' });
  });

  it('asks before discarding when the engine cannot convert, and drops a type the new format lacks', async () => {
    const { app, tab } = await draft('edn');
    app.engine.parseEdit.mockResolvedValue(fx.edited(fx.coseKeyDraft));
    await app.workspace.setDraftKind(tab.id, { type: 'cose_key' });
    Reflect.deleteProperty(app.engine, 'convertClaims');
    app.engine.parseEdit.mockResolvedValue(fx.edited(fx.emptyJsonDraft));
    const confirm = vi.fn(async () => true);
    expect(await app.workspace.setDraftFormat(tab.id, 'json', confirm)).toBe(true);
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(tab.draft?.override).toBeNull();
  });

  it('the same format is a no-op', async () => {
    const { app, tab } = await draft('json');
    expect(await app.workspace.setDraftFormat(tab.id, 'json', async () => true)).toBe(true);
    expect(app.engine.convertClaims).not.toHaveBeenCalled();
  });
});
