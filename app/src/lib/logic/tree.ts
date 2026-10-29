// Node tree helpers keyed by NodeId.
import type { Node, NodeId } from '../engine/types';

/** Depth-first, pre-order, including map key nodes (`…/~k`). */
export function* walk(node: Node, depth = 0): Generator<{ node: Node; depth: number }> {
  yield { node, depth };
  if (node.key) yield* walk(node.key, depth + 1);
  for (const child of node.children) yield* walk(child, depth + 1);
}

export interface NodeIndex {
  node: Node;
  depth: number;
}

const indexes = new WeakMap<Node, Map<NodeId, NodeIndex>>();

/** Every node of the tree by id (cached per tree object). */
export function nodeIndex(root: Node): Map<NodeId, NodeIndex> {
  let index = indexes.get(root);
  if (!index) {
    index = new Map();
    for (const entry of walk(root)) {
      if (!index.has(entry.node.id)) index.set(entry.node.id, entry);
    }
    indexes.set(root, index);
  }
  return index;
}

export function findNode(root: Node, id: NodeId): Node | null {
  return nodeIndex(root).get(id)?.node ?? null;
}

/** The ids of every ancestor of `id`, root (`""`) first, excluding `id`.
 *  Segments never contain a raw `/` (it is escaped as `~1`). */
export function ancestorIds(id: NodeId): NodeId[] {
  if (id === '') return [];
  const segments = id.split('/');
  const out: NodeId[] = [''];
  for (let i = 1; i < segments.length; i++) out.push(segments.slice(0, i).join('/'));
  return out;
}

/** The node for `id`, or its nearest ancestor present in the tree. */
export function findNearest(root: Node, id: NodeId): Node | null {
  const index = nodeIndex(root);
  const own = index.get(id);
  if (own) return own.node;
  const ancestors = ancestorIds(id);
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const found = index.get(ancestors[i] ?? '');
    if (found) return found.node;
  }
  return null;
}
