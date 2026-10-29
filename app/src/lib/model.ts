// App-level types (not engine DTOs).
import type { KeyInfo, NodeId, Role } from './engine/types';

/** Every action in the tab header (SPEC §5). */
export const ACTION_IDS = [
  'issue',
  'redact',
  'disclose',
  'present',
  'validate',
  'resign',
  'tamper',
  'reencode',
  'edit_disclosures',
] as const;
export type ActionId = (typeof ACTION_IDS)[number];

/** Where a key or credential came from (SPEC §4). */
export type Provenance =
  | { type: 'pasted' }
  | { type: 'dropped'; name: string | null }
  | { type: 'clipboard' }
  | { type: 'file'; name: string }
  | { type: 'url'; url: string }
  | { type: 'generated' }
  /** A tab derived from another tab by an action. */
  | { type: 'derived'; parent: string; action: ActionId }
  /** A key card derived from another card. */
  | { type: 'derived_key'; parent: string; how: 'public' | 'kid' };

export interface KeyCard {
  /** Workspace id (`key-1`, …). */
  id: string;
  /** Display name, also sent as `KeyRef.label`. */
  label: string;
  role: Role | null;
  info: KeyInfo;
  provenance: Provenance;
}

export interface Availability {
  enabled: boolean;
  /** What is missing, one human-readable item each (empty when enabled). */
  missing: string[];
}

export type ActionAvailability = Record<ActionId, Availability>;

/** One entry of a derived tab's breadcrumb, root first. */
export interface Crumb {
  tabId: string;
  title: string;
  /** The action that produced this tab from the previous crumb. */
  action: ActionId | null;
}

export type SelectedNode = NodeId | null;
