// Which header actions are enabled, and what is missing (SPEC §4.1, §5).
// Rules: app/TEST-PLAN.md "Rules encoded in the tests".
import type { CborSerialization, Document, JoseSerialization, NodeId } from '../engine/types';
import type { ActionAvailability, ActionId, Availability, KeyCard } from '../model';
import { notImplemented } from '../notImplemented';

export interface ActionContext {
  doc: Document;
  keys: readonly KeyCard[];
  /** JSON claims marked SD in the tree (Redact on JSON claim sets). */
  sdMarks: readonly NodeId[];
}

export const ACTION_LABELS: Record<ActionId, string> = {
  issue: 'Issue',
  redact: 'Redact',
  disclose: 'Disclose',
  present: 'Present',
  validate: 'Validate',
  resign: 'Re-sign',
  tamper: 'Tamper',
  reencode: 'Re-encode',
  edit_disclosures: 'Edit disclosures',
};

export function actionAvailability(_ctx: ActionContext): ActionAvailability {
  notImplemented('actionAvailability');
}

/** The button tooltip: what the action does, or what is missing. */
export function actionTooltip(_action: ActionId, _availability: Availability): string {
  notImplemented('actionTooltip');
}

export interface ReencodeChoice {
  label: string;
  cbor?: CborSerialization;
  jose?: JoseSerialization;
}

/** Re-encode menu entries for the document's family. */
export function reencodeChoices(_doc: Document): ReencodeChoice[] {
  notImplemented('reencodeChoices');
}
