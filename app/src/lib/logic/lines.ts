// Line model of the main pane and its alignment with the raw pane
// (app/ARCHITECTURE.md "Panes and tree sync").
import type { Document, NodeId } from '../engine/types';
import { notImplemented } from '../notImplemented';

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

/** One entry per line of `doc.main.text`. */
export function lineInfos(_doc: Document): LineInfo[] {
  notImplemented('lineInfos');
}

/** Lines hidden because a collapsed node folds them (all lines after the
 *  node's first line up to, not including, its last line). */
export function hiddenLines(_doc: Document, _collapsed: ReadonlySet<NodeId>): Set<number> {
  notImplemented('hiddenLines');
}

export interface LineRows {
  line: number;
  /** Indexes into `doc.raw.rows` aligned to this line, in byte order. */
  rows: number[];
}

/** Hex views: every row aligned to the main-pane line of its node
 *  (`node.main.line_start`; key rows use the key node; envelope rows with
 *  node id `""` use the root). One entry per main-pane line. */
export function alignRows(_doc: Document): LineRows[] {
  notImplemented('alignRows');
}

/** The main-pane line a hex row is shown on. */
export function lineOfRow(_doc: Document, _row: number): number {
  notImplemented('lineOfRow');
}

/** Segment views: the segment index and the character range to highlight
 *  for a node (from `node.raw`), or null when the node has no raw range. */
export function segmentHighlight(
  _doc: Document,
  _id: NodeId,
): { segment: number; start: number; end: number } | null {
  notImplemented('segmentHighlight');
}
