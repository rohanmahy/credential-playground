// Which header actions are enabled, and what is missing (SPEC §4.1, §5).
// Rules: app/TEST-PLAN.md "Rules encoded in the tests".
import type { CborSerialization, Document, JoseSerialization, NodeId } from '../engine/types';
import type { ActionAvailability, ActionId, Availability, KeyCard } from '../model';
import { hasKeyBinding, isClaims, isSd, isSigned, kindFamily } from './kinds';

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

const DESCRIPTIONS: Record<ActionId, string> = {
  issue: 'Sign the claim set as a JWT/CWT (SD-JWT/SD-CWT if claims are marked)',
  redact: 'Issue an SD-JWT/SD-CWT with the marked claims redacted',
  disclose: 'Keep a chosen subset of the disclosures',
  present: 'Add key binding with the holder key, audience, and nonce',
  validate: 'Check the signature, times, disclosures, key binding, and conformance',
  resign: 'Sign the current content again',
  tamper: 'Break the credential on purpose (not re-signed)',
  reencode: 'Change the outer encoding or serialization',
  edit_disclosures: 'Add, remove, reorder, or forge disclosures',
};

/** Holder and verifier keys never issue; unassigned keys may. */
export function canIssueWith(card: KeyCard): boolean {
  return card.role === 'issuer' || card.role === null;
}

export function canHoldWith(card: KeyCard): boolean {
  return card.role === 'holder' || card.role === null;
}

/** EDN redaction marks: tag 58 (to be redacted) or 62 (to be decoy). */
function hasEdnMarks(doc: Document): boolean {
  return doc.main.language === 'edn' && /(^|[^\w.'"])(58|62)\(/m.test(doc.main.text);
}

function availability(missing: string[]): Availability {
  return { enabled: missing.length === 0, missing };
}

function keyNeed(keys: readonly KeyCard[], fits: (c: KeyCard) => boolean, role: string): string[] {
  const candidates = keys.filter(fits);
  if (candidates.length === 0) return [`Needs ${role} key`];
  if (!candidates.some((c) => c.info.private)) return [`Needs ${role} key with a private part`];
  return [];
}

export function actionAvailability(ctx: ActionContext): ActionAvailability {
  const { doc, keys, sdMarks } = ctx;
  const kind = doc.kind;
  const claims = isClaims(kind);
  const signed = isSigned(kind);
  const sd = isSd(kind);
  const kb = hasKeyBinding(kind);

  const needClaims = claims ? [] : ['Needs an unsigned claim set'];
  const needSigned = signed ? [] : ['Needs a signed credential (Issue the claim set first)'];
  const issuerKey = keyNeed(keys, canIssueWith, 'an issuer');

  const marked = sdMarks.length > 0 || hasEdnMarks(doc);
  const disclose: string[] = [];
  if (!sd) disclose.push('Needs an SD-JWT or SD-CWT (selective disclosure)');
  else if (kb) disclose.push('Not on a presentation (it already has key binding)');
  else if (doc.disclosures.length === 0) disclose.push('Needs disclosures');

  const presentable =
    (kind.type === 'sd_jwt' && !kind.kb) ||
    (kind.type === 'sd_jwt_json' && !kind.kb) ||
    kind.type === 'sd_cwt' ||
    kind.type === 'cwt';
  const present: string[] = [];
  if (kb) present.push('Not on a presentation (it already has key binding)');
  else if (!presentable) present.push('Needs an SD-JWT, SD-CWT, or CWT');
  present.push(...keyNeed(keys, canHoldWith, 'a holder'));

  const privateKey = keys.some((k) => k.info.private) ? [] : ['Needs a private key'];

  return {
    issue: availability([...needClaims, ...issuerKey]),
    redact: availability([
      ...needClaims,
      ...(claims && !marked ? ['Needs a claim marked selectively disclosable'] : []),
      ...issuerKey,
    ]),
    disclose: availability(disclose),
    present: availability(present),
    validate: availability(needSigned),
    resign: availability([...needSigned, ...privateKey]),
    tamper: availability(needSigned),
    reencode: availability(needSigned),
    edit_disclosures: availability(
      sd || kind.type === 'sd_kbt' ? [] : ['Needs an SD-JWT or SD-CWT'],
    ),
  };
}

/** The button tooltip: what the action does, or what is missing. */
export function actionTooltip(action: ActionId, availability: Availability): string {
  if (availability.enabled) return DESCRIPTIONS[action];
  return [
    `${ACTION_LABELS[action]} is unavailable:`,
    ...availability.missing.map((m) => `• ${m}`),
  ].join('\n');
}

export interface ReencodeChoice {
  label: string;
  cbor?: CborSerialization;
  jose?: JoseSerialization;
}

/** Re-encode menu entries for the document's family. */
export function reencodeChoices(doc: Document): ReencodeChoice[] {
  if (kindFamily(doc.kind) === 'cose') {
    return [
      { label: 'As received', cbor: 'preserve' },
      { label: 'Preferred-plus', cbor: 'preferred_plus' },
      { label: 'Deterministic', cbor: 'deterministic' },
    ];
  }
  return [
    { label: 'Compact', jose: 'compact' },
    { label: 'JSON (flattened)', jose: 'json_flattened' },
    { label: 'JSON (general)', jose: 'json_general' },
  ];
}
