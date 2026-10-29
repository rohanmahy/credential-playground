// The hand-written fixtures obey the core range rules (core TEST-PLAN §5),
// so UI tests built on them exercise realistic documents.
import { describe, expect, it } from 'vitest';
import type { Document, Node } from '../../lib/engine/types';
import { b64uToText, fromB64u } from '../../lib/engine/bytes';
import { walk } from '../../lib/logic/tree';
import * as fx from '../fixtures';
import { textRange } from '../fixtures/build';

const docs: [string, Document][] = [
  ['jwt', fx.jwt],
  ['sdJwt', fx.sdJwt],
  ['sdJwtKb', fx.sdJwtKb],
  ['cwt', fx.cwt],
  ['jsonClaims', fx.jsonClaims],
  ['ednClaims', fx.ednClaims],
];

const nodes = (doc: Document): Node[] => [...walk(doc.tree)].map((w) => w.node);

describe.each(docs)('fixture %s', (_name, doc) => {
  it('has unique NodeIds and consistent line ranges', () => {
    const all = nodes(doc);
    expect(new Set(all.map((n) => n.id)).size).toBe(all.length);
    for (const n of all) {
      if (!n.main) continue;
      expect(n.main, n.id).toEqual(textRange(doc.main.text, n.main.start, n.main.end));
    }
    expect(doc.main.line_count).toBe(doc.main.text.split('\n').length);
  });
});

describe('hex fixtures', () => {
  it.each([
    ['cwt', fx.cwt],
    ['ednClaims', fx.ednClaims],
  ])('%s rows cover each node exactly', (_name, doc) => {
    if (doc.raw.type !== 'hex') throw new Error('hex');
    const rows = doc.raw.rows;
    const bytes = fromB64u(doc.raw.bytes);
    expect(rows.at(-1)?.payload.end).toBe(bytes.length);
    for (const n of nodes(doc)) {
      if (!n.raw) continue;
      expect(rows[n.raw.row_start]?.head.start, n.id).toBe(n.raw.start);
      for (const r of rows.slice(n.raw.row_start, n.raw.row_end)) {
        expect(r.head.start).toBeGreaterThanOrEqual(n.raw.start);
        expect(Math.max(r.head.end, r.payload.end)).toBeLessThanOrEqual(n.raw.end);
      }
    }
  });
});

describe('segment fixtures', () => {
  it.each([
    ['jwt', fx.jwt],
    ['sdJwtKb', fx.sdJwtKb],
  ])('%s nested nodes decode to their main slice', (_name, doc) => {
    if (doc.raw.type !== 'segments') throw new Error('segments');
    const token = b64uToText(doc.bytes);
    for (const s of doc.raw.segments) expect(token.slice(s.range.start, s.range.end)).toBe(s.text);
    for (const n of nodes(doc)) {
      if (!n.raw || !n.main || !n.id.includes('/~e')) continue;
      const chars = token.slice(n.raw.start, n.raw.end);
      const decoded = new TextDecoder().decode(
        fromB64u(chars.length % 4 === 1 ? chars.slice(0, -1) : chars),
      );
      expect(decoded, n.id).toContain(doc.main.text.slice(n.main.start, n.main.end));
    }
  });

  it('the JWT view object shows the decoded parts verbatim', () => {
    const iss = nodes(fx.jwt).find((n) => n.id === 'payload/~e/iss');
    expect(iss?.main && fx.jwt.main.text.slice(iss.main.start, iss.main.end)).toBe(
      '"https://issuer.example"',
    );
    expect(fx.jwtToken.split('.')).toHaveLength(3);
  });
});
