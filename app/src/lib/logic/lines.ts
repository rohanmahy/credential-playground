// Line model of the main pane and its alignment with the raw pane
// (app/ARCHITECTURE.md "Panes and tree sync").
import type { Document, NodeId } from '../engine/types';
import { findNearest, nodeIndex, walk } from './tree';

export interface LineInfo {
  line: number;
  /** The outermost node whose `main.line_start` is this line. */
  nodeId: NodeId | null;
  /** Tree depth of that node (0 for the root). */
  depth: number;
  /** The node spans more than one line. */
  foldable: boolean;
  /** For foldable lines: the node's `main.line_end`. */
  foldEnd: number | null;
}

const lineCache = new WeakMap<Document, LineInfo[]>();

function lineCountOf(doc: Document): number {
  return Math.max(doc.main.line_count, 1);
}

/** One entry per line of `doc.main.text`. */
export function lineInfos(doc: Document): LineInfo[] {
  const cached = lineCache.get(doc);
  if (cached) return cached;
  const count = lineCountOf(doc);
  const lines: LineInfo[] = Array.from({ length: count }, (_, line) => ({
    line,
    nodeId: null,
    depth: 0,
    foldable: false,
    foldEnd: null,
  }));
  const best: (number | null)[] = Array.from({ length: count }, () => null);
  for (const { node, depth } of walk(doc.tree)) {
    const range = node.main;
    if (!range) continue;
    const line = range.line_start;
    const current = best[line];
    // Outermost wins; on a tie the first in pre-order (a value before its key).
    if (line >= count || (current !== null && current !== undefined && current <= depth)) continue;
    best[line] = depth;
    const foldable = range.line_end - range.line_start > 1;
    lines[line] = {
      line,
      nodeId: node.id,
      depth,
      foldable,
      foldEnd: foldable ? range.line_end : null,
    };
  }
  lineCache.set(doc, lines);
  return lines;
}

/** Lines hidden because a collapsed node folds them (all lines after the
 *  node's first line up to, not including, its last line). */
export function hiddenLines(doc: Document, collapsed: ReadonlySet<NodeId>): Set<number> {
  const hidden = new Set<number>();
  const index = nodeIndex(doc.tree);
  for (const id of collapsed) {
    const range = index.get(id)?.node.main;
    if (!range) continue;
    for (let l = range.line_start + 1; l < range.line_end - 1; l++) hidden.add(l);
  }
  return hidden;
}

export interface LineRows {
  line: number;
  /** Indexes into `doc.raw.rows` aligned to this line, in byte order. */
  rows: number[];
}

const alignCache = new WeakMap<Document, { lines: LineRows[]; rowLine: number[] }>();

function align(doc: Document): { lines: LineRows[]; rowLine: number[] } {
  const cached = alignCache.get(doc);
  if (cached) return cached;
  const count = lineCountOf(doc);
  const lines: LineRows[] = Array.from({ length: count }, (_, line) => ({ line, rows: [] }));
  const rowLine: number[] = [];
  if (doc.raw.type === 'hex') {
    let last = 0;
    doc.raw.rows.forEach((row, i) => {
      // Rows of nodes the main pane does not show (a tag's content) use the
      // nearest shown ancestor; rows without any stay on the previous line.
      const node = findNearest(doc.tree, row.node_id);
      const line = node?.main ? Math.min(node.main.line_start, count - 1) : last;
      last = line;
      rowLine.push(line);
      lines[line]?.rows.push(i);
    });
  }
  const result = { lines, rowLine };
  alignCache.set(doc, result);
  return result;
}

/** Hex views: every row aligned to the main-pane line of its node
 *  (`node.main.line_start`; key rows use the key node; envelope rows with
 *  node id `""` use the root). One entry per main-pane line. */
export function alignRows(doc: Document): LineRows[] {
  return align(doc).lines;
}

/** The main-pane line a hex row is shown on. */
export function lineOfRow(doc: Document, row: number): number {
  return align(doc).rowLine[row] ?? 0;
}

/** Segment views: the segment index and the character range to highlight
 *  for a node (from `node.raw`), or null when the node has no raw range. */
export function segmentHighlight(
  doc: Document,
  id: NodeId,
): { segment: number; start: number; end: number } | null {
  if (doc.raw.type !== 'segments') return null;
  const raw = nodeIndex(doc.tree).get(id)?.node.raw;
  if (!raw) return null;
  return { segment: raw.row_start, start: raw.start, end: raw.end };
}
