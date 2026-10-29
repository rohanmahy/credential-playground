// Builds COSE/CBOR Documents from an EDN text, a hex row table, and a node
// table. Byte ranges come from the rows; text ranges from needles on lines.
import type { Document, HexRow, Kind, Node, NodeId, NodeKind } from '../../lib/engine/types';
import { toB64u } from '../../lib/engine/bytes';
import { bareNode, hexToBytes, lineCount, onLine, textRange, type NodeExtras } from './build';

/** [node id, depth, head hex, payload hex, description, comment] */
export type RowSpec = [NodeId, number, string, string, string, string | null];

export interface NodeSpec {
  id: NodeId;
  kind: NodeKind;
  label: string;
  /** Single line: [line, needle]. Multi-line: [[line, needle], [line, needle]]. */
  main: [number, string] | [[number, string], [number, string]];
  /** Half-open row range. */
  rows: [number, number];
  key?: Omit<NodeSpec, 'children' | 'key'>;
  children?: NodeSpec[];
  extras?: NodeExtras;
}

export interface CoseSpec {
  kind: Kind;
  signed: boolean;
  edn: string;
  rows: RowSpec[];
  tree: NodeSpec;
}

export function buildCose(spec: CoseSpec): Document {
  let offset = 0;
  let hex = '';
  const rows: HexRow[] = spec.rows.map(([nodeId, depth, head, payload, description, comment]) => {
    const headLen = head.length / 2;
    const payloadLen = payload.length / 2;
    const row: HexRow = {
      node_id: nodeId,
      kind: description === 'break' ? 'break' : 'item',
      depth,
      head: { start: offset, end: offset + headLen },
      payload: { start: offset + headLen, end: offset + headLen + payloadLen },
      description,
      comment,
    };
    offset += headLen + payloadLen;
    hex += head + payload;
    return row;
  });
  const bytes = hexToBytes(hex);

  const build = (n: Omit<NodeSpec, 'key' | 'children'> & Partial<NodeSpec>): Node => {
    const node = bareNode(n.id, n.kind, n.label);
    const [a, b] = n.main;
    const [start] =
      typeof a === 'number' ? onLine(spec.edn, a, b as string) : onLine(spec.edn, a[0], a[1]);
    const [, end] =
      typeof a === 'number'
        ? onLine(spec.edn, a, b as string)
        : onLine(spec.edn, (b as [number, string])[0], (b as [number, string])[1]);
    node.main = textRange(spec.edn, start, end);
    const [rs, re] = n.rows;
    const covered = rows.slice(rs, re);
    const first = covered[0];
    if (!first) throw new Error(`no rows for ${n.id}`);
    node.raw = {
      start: first.head.start,
      end: Math.max(...covered.map((r) => Math.max(r.head.end, r.payload.end))),
      row_start: rs,
      row_end: re,
    };
    Object.assign(node, n.extras ?? {});
    if (n.key) node.key = build(n.key);
    node.children = (n.children ?? []).map(build);
    return node;
  };

  return {
    kind: spec.kind,
    layers: [],
    bytes: toB64u(bytes),
    signed: spec.signed,
    signature_stale: false,
    tree: build(spec.tree),
    main: { language: 'edn', text: spec.edn, line_count: lineCount(spec.edn) },
    raw: { type: 'hex', bytes: toB64u(bytes), rows },
    disclosures: [],
    undisclosed: [],
    diagnostics: [],
  };
}
