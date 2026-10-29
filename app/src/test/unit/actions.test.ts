// Action enablement and "what's missing" (SPEC §4.1, §5; app/TEST-PLAN.md).
import { describe, expect, it } from 'vitest';
import type { Document } from '../../lib/engine/types';
import {
  ACTION_LABELS,
  actionAvailability,
  actionTooltip,
  reencodeChoices,
  type ActionContext,
} from '../../lib/logic/actions';
import { ACTION_IDS, type KeyCard } from '../../lib/model';
import * as fx from '../fixtures';

const ctx = (doc: Document, keys: KeyCard[] = [], sdMarks: string[] = []): ActionContext => ({
  doc,
  keys,
  sdMarks,
});
const all = [fx.issuerCard, fx.holderCard, fx.verifierCard];

describe('actionAvailability', () => {
  it('reports every action', () => {
    const a = actionAvailability(ctx(fx.jwt));
    expect(Object.keys(a).sort()).toEqual([...ACTION_IDS].sort());
    for (const id of ACTION_IDS) expect(ACTION_LABELS[id]).toBeTruthy();
  });

  it('Issue needs a claim set and an issuer key with a private part', () => {
    expect(actionAvailability(ctx(fx.jsonClaims, all)).issue).toEqual({
      enabled: true,
      missing: [],
    });
    const noKey = actionAvailability(ctx(fx.jsonClaims)).issue;
    expect(noKey.enabled).toBe(false);
    expect(noKey.missing.join(' ')).toMatch(/issuer key/i);
    const publicOnly = actionAvailability(ctx(fx.jsonClaims, [fx.publicIssuerCard])).issue;
    expect(publicOnly.enabled).toBe(false);
    expect(publicOnly.missing.join(' ')).toMatch(/private/i);
    const signed = actionAvailability(ctx(fx.jwt, all)).issue;
    expect(signed.enabled).toBe(false);
    expect(signed.missing.join(' ')).toMatch(/claim set/i);
  });

  it('Redact also needs a marked claim (JSON marks, or tags 58/62 in EDN)', () => {
    const unmarked = actionAvailability(ctx(fx.jsonClaims, all)).redact;
    expect(unmarked.enabled).toBe(false);
    expect(unmarked.missing.join(' ')).toMatch(/mark/i);
    expect(actionAvailability(ctx(fx.jsonClaims, all, ['given_name'])).redact.enabled).toBe(true);
    expect(actionAvailability(ctx(fx.ednClaims, all)).redact.enabled).toBe(true);
    expect(actionAvailability(ctx(fx.ednClaimsUnmarked, all)).redact.enabled).toBe(false);
  });

  it('Disclose needs an SD credential with disclosures and no key binding', () => {
    expect(actionAvailability(ctx(fx.sdJwt)).disclose.enabled).toBe(true);
    expect(actionAvailability(ctx(fx.sdCwt)).disclose.enabled).toBe(true);
    const plain = actionAvailability(ctx(fx.jwt)).disclose;
    expect(plain.enabled).toBe(false);
    expect(plain.missing.join(' ')).toMatch(/SD-JWT|SD-CWT|selective/i);
    const kb = actionAvailability(ctx(fx.sdJwtKb)).disclose;
    expect(kb.enabled).toBe(false);
    expect(kb.missing.join(' ')).toMatch(/key binding|presentation/i);
  });

  it('Present needs an SD-JWT, SD-CWT, or plain CWT and a holder key with a private part', () => {
    expect(actionAvailability(ctx(fx.sdJwt, all)).present.enabled).toBe(true);
    expect(actionAvailability(ctx(fx.sdCwt, all)).present.enabled).toBe(true);
    expect(actionAvailability(ctx(fx.cwt, all)).present.enabled).toBe(true);
    const noHolder = actionAvailability(ctx(fx.sdJwt, [fx.issuerCard])).present;
    expect(noHolder.enabled).toBe(false);
    expect(noHolder.missing.join(' ')).toMatch(/holder key/i);
    expect(actionAvailability(ctx(fx.jwt, all)).present.enabled).toBe(false);
    expect(actionAvailability(ctx(fx.sdJwtKb, all)).present.enabled).toBe(false);
    expect(actionAvailability(ctx(fx.sdKbt, all)).present.enabled).toBe(false);
  });

  it('lists every missing item at once', () => {
    const p = actionAvailability(ctx(fx.jwt)).present;
    expect(p.missing.length).toBeGreaterThanOrEqual(2);
  });

  it('Validate needs a signed credential but no keys', () => {
    expect(actionAvailability(ctx(fx.jwt)).validate.enabled).toBe(true);
    expect(actionAvailability(ctx(fx.cwt)).validate.enabled).toBe(true);
    const claims = actionAvailability(ctx(fx.jsonClaims, all)).validate;
    expect(claims.enabled).toBe(false);
    expect(claims.missing.join(' ')).toMatch(/claim set|issue/i);
  });

  it('Re-sign needs a signed credential and a private key', () => {
    const none = actionAvailability(ctx(fx.jwt, [fx.verifierCard])).resign;
    expect(none.enabled).toBe(false);
    expect(none.missing.join(' ')).toMatch(/private key/i);
    expect(actionAvailability(ctx(fx.jwt, all)).resign.enabled).toBe(true);
    expect(actionAvailability(ctx(fx.jsonClaims, all)).resign.enabled).toBe(false);
  });

  it('Tamper and Re-encode need a signed credential', () => {
    for (const doc of [fx.jwt, fx.sdJwtKb, fx.cwt, fx.sdKbt]) {
      const a = actionAvailability(ctx(doc));
      expect(a.tamper.enabled).toBe(true);
      expect(a.reencode.enabled).toBe(true);
    }
    const claims = actionAvailability(ctx(fx.jsonClaims));
    expect(claims.tamper.enabled).toBe(false);
    expect(claims.reencode.enabled).toBe(false);
  });

  it('Edit disclosures needs an SD-JWT or SD-CWT', () => {
    expect(actionAvailability(ctx(fx.sdJwt)).edit_disclosures.enabled).toBe(true);
    expect(actionAvailability(ctx(fx.sdJwtKb)).edit_disclosures.enabled).toBe(true);
    expect(actionAvailability(ctx(fx.sdCwt)).edit_disclosures.enabled).toBe(true);
    const cwt = actionAvailability(ctx(fx.cwt)).edit_disclosures;
    expect(cwt.enabled).toBe(false);
    expect(cwt.missing.join(' ')).toMatch(/SD-JWT|SD-CWT/);
  });
});

describe('actionTooltip', () => {
  it('describes enabled actions and lists what is missing otherwise', () => {
    const on = actionTooltip('validate', { enabled: true, missing: [] });
    expect(on).toBeTruthy();
    expect(on).not.toMatch(/missing/i);
    const off = actionTooltip('present', {
      enabled: false,
      missing: ['Needs an SD-JWT, SD-CWT, or CWT', 'Needs a holder key with a private part'],
    });
    expect(off).toContain('Needs an SD-JWT, SD-CWT, or CWT');
    expect(off).toContain('Needs a holder key with a private part');
  });
});

describe('reencodeChoices', () => {
  it('offers the three CBOR serializations for COSE', () => {
    const c = reencodeChoices(fx.cwt);
    expect(c.filter((x) => x.cbor).map((x) => [x.cbor, x.label])).toEqual([
      ['preserve', 'As received'],
      ['preferred_plus', 'Preferred-plus'],
      ['deterministic', 'Deterministic'],
    ]);
    expect(c.some((x) => x.jose)).toBe(false);
  });

  it('offers JOSE serializations for JOSE', () => {
    const c = reencodeChoices(fx.jwt);
    expect(c.map((x) => x.jose).filter(Boolean)).toEqual([
      'compact',
      'json_flattened',
      'json_general',
    ]);
    expect(c.some((x) => x.cbor)).toBe(false);
  });
});
