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
  /** A draft started from nothing with New (#43). */
  | { type: 'new' }
  /** A tab derived from another tab by an action. */
  | { type: 'derived'; parent: string; action: ActionId }
  /** A key derived from another (Make public). */
  | { type: 'derived_key'; parent: string; how: 'public' | 'kid' };

/** The two key areas (SPEC §4.2); the area a key sits in is its role.
 *  There is no Verifier: verification uses the Issuer key's public part. */
export type KeyRole = Extract<Role, 'issuer' | 'holder'>;

export const KEY_ROLES: readonly KeyRole[] = ['issuer', 'holder'];

/** `Issuer key`, `Holder key`: the area names, also the cards' labels. */
export const KEY_ROLE_LABELS: Readonly<Record<KeyRole, string>> = {
  issuer: 'Issuer key',
  holder: 'Holder key',
};

/** The key held by one key area. */
export interface KeyCard {
  /** The area's role (`issuer` or `holder`): one key per area. */
  id: KeyRole;
  /** Display name (`Issuer key`), also sent as `KeyRef.label`. */
  label: string;
  role: KeyRole;
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
