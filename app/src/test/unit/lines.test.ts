// Main-pane line model, folding, and raw-row ↔ main-line alignment, all
// derived from the DTO ranges (SPEC §4.1, app/ARCHITECTURE.md).
import { describe, expect, it } from 'vitest';
import {
  alignRows,
  hiddenLines,
  lineInfos,
  lineOfRow,
  segmentHighlight,
} from '../../lib/logic/lines';
import { cwt, jwt, sdJwtKb } from '../fixtures';

describe('lineInfos', () => {
  it('gives one entry per main-pane line with the outermost node starting there (CWT)', () => {
    const lines = lineInfos(cwt);
    expect(lines).toHaveLength(cwt.main.line_count);
    expect(lines.map((l) => l.nodeId)).toEqual([
      '',
      'protected',
      'protected/~e/1',
      null,
      'unprotected',
      'unprotected/4',
      null,
      'payload',
      'payload/~e/1',
      'payload/~e/2',
      'payload/~e/4',
      null,
      'signature',
      null,
    ]);
    expect(lines[1]).toMatchObject({ depth: 1, foldable: true, foldEnd: 4 });
    expect(lines[2]).toMatchObject({ depth: 3, foldable: false, foldEnd: null });
    expect(lines[0]).toMatchObject({ depth: 0, foldable: true, foldEnd: 14 });
  });

  it('treats JOSE parts as foldable only when they span lines (JWT)', () => {
    const lines = lineInfos(jwt);
    expect(lines[1]).toMatchObject({ nodeId: 'protected', foldable: false });
    expect(lines[2]).toMatchObject({ nodeId: 'payload', depth: 1, foldable: true, foldEnd: 8 });
    expect(lines[3]).toMatchObject({ nodeId: 'payload/~e/iss', depth: 3 });
  });
});

describe('hiddenLines', () => {
  it('hides the inner lines of a collapsed node, keeping its first and last line', () => {
    expect([...hiddenLines(cwt, new Set(['payload']))].sort((a, b) => a - b)).toEqual([8, 9, 10]);
  });

  it('collapsing the root hides everything but its first and last line', () => {
    const hidden = hiddenLines(cwt, new Set(['']));
    expect(hidden.size).toBe(12);
    expect(hidden.has(0)).toBe(false);
    expect(hidden.has(13)).toBe(false);
  });

  it('unions nested collapsed nodes and ignores ids that are not in the document', () => {
    const hidden = hiddenLines(cwt, new Set(['protected', 'payload', 'no/such/node']));
    expect([...hidden].sort((a, b) => a - b)).toEqual([2, 8, 9, 10]);
    expect(hiddenLines(cwt, new Set()).size).toBe(0);
  });
});

describe('alignRows (hex)', () => {
  it('lines every hex row up with the EDN line of its node', () => {
    const aligned = alignRows(cwt);
    expect(aligned).toHaveLength(cwt.main.line_count);
    expect(aligned.map((l) => l.rows)).toEqual([
      [0, 1], // 18([  : envelope tag and array head (node "")
      [2, 3], // << {  : protected bstr head, decoded map head
      [4, 5], // / alg / 1: -7
      [],
      [6],
      [7, 8], // / kid / 4: h'…' (key row, value row)
      [],
      [9, 10],
      [11, 12],
      [13, 14],
      [15, 16],
      [],
      [17],
      [],
    ]);
  });

  it('places every row exactly once, in byte order', () => {
    const flat = alignRows(cwt).flatMap((l) => l.rows);
    expect(flat).toEqual([...flat].sort((a, b) => a - b));
    expect(new Set(flat).size).toBe(cwt.raw.type === 'hex' ? cwt.raw.rows.length : -1);
  });

  it('maps a row back to its line', () => {
    expect(lineOfRow(cwt, 0)).toBe(0);
    expect(lineOfRow(cwt, 8)).toBe(5);
    expect(lineOfRow(cwt, 16)).toBe(10);
    expect(lineOfRow(cwt, 17)).toBe(12);
  });
});

describe('segmentHighlight (JOSE)', () => {
  it('finds the segment and the base64url characters of a nested node', () => {
    const iss = segmentHighlight(jwt, 'payload/~e/iss');
    expect(iss?.segment).toBe(1);
    expect(iss && iss.end > iss.start).toBe(true);
    expect(segmentHighlight(jwt, 'signature')).toMatchObject({ segment: 2 });
    expect(segmentHighlight(sdJwtKb, 'kb/payload/~e/nonce')?.segment).toBe(6);
  });

  it('returns null for nodes without a raw range', () => {
    expect(segmentHighlight(jwt, '')).toBeNull();
    expect(segmentHighlight(jwt, 'nope')).toBeNull();
  });
});
