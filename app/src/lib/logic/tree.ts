// Node tree helpers keyed by NodeId.
import type { Node, NodeId } from '../engine/types';
import { notImplemented } from '../notImplemented';

/** Depth-first, pre-order, including map key nodes (`…/~k`). */
export function* walk(node: Node, depth = 0): Generator<{ node: Node; depth: number }> {
  yield { node, depth };
  if (node.key) yield* walk(node.key, depth + 1);
  for (const child of node.children) yield* walk(child, depth + 1);
}

export function findNode(_root: Node, _id: NodeId): Node | null {
  notImplemented('findNode');
}

/** The ids of every ancestor of `id`, root (`""`) first, excluding `id`. */
export function ancestorIds(_id: NodeId): NodeId[] {
  notImplemented('ancestorIds');
}
