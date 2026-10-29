// The workspace: credential tabs, their per-tab view state, the provenance
// graph, and the split (SPEC §4, §5). In memory only.
import { SvelteSet } from 'svelte/reactivity';
import type { Engine } from '../engine/Engine';
import type {
  Candidate,
  CborSerialization,
  Diagnostic,
  DisclosureOp,
  Document,
  EditResult,
  HeaderOptions,
  JoseSerialization,
  Layer,
  NodeId,
  TamperOp,
  ValidationReport,
} from '../engine/types';
import type { ActionAvailability, ActionId, Crumb, Provenance } from '../model';
import type { Platform } from '../platform/Platform';
import type { KeyStore } from './keys.svelte';
import type { Settings } from './settings.svelte';
import { notImplemented } from '../notImplemented';

export interface Tab {
  id: string;
  /** 1, 2, … in creation order (never reused). */
  number: number;
  /** `Tab 3 · SD-JWT`. */
  title: string;
  doc: Document;
  /** The bytes as received (before unwrapping), for re-detection. */
  input: Uint8Array | null;
  candidates: Candidate[];
  candidateIndex: number;
  provenance: Provenance;
  /** Collapsed nodes, shared by the main and raw panes. */
  collapsed: SvelteSet<NodeId>;
  selected: NodeId | null;
  liveEdit: boolean;
  /** Live-edit text (the main pane text when not editing). */
  editText: string;
  /** Diagnostics of the last edit that did not parse. */
  editDiagnostics: Diagnostic[];
  /** Signed content changed since the tab was opened or derived. */
  stale: boolean;
  /** The user chose "Keep original signature". */
  tampered: boolean;
  /** JSON claims marked selectively disclosable (Redact/Issue). */
  sdMarks: SvelteSet<NodeId>;
  report: ValidationReport | null;
}

export type OpenResult =
  | { type: 'tab'; tabId: string }
  /** Keys are routed to the key panel (SPEC §3). */
  | { type: 'keys'; cardIds: string[] }
  | { type: 'nothing' };

export type ActionRequest =
  | {
      action: 'issue' | 'redact';
      issuerKeyId: string;
      holderKeyId?: string | null;
      alg?: string | null;
      header?: HeaderOptions;
      jose?: JoseSerialization;
    }
  | { action: 'disclose'; keep: number[] }
  | {
      action: 'present';
      keep: number[];
      holderKeyId: string;
      aud?: string | null;
      nonce?: string | null;
    }
  | { action: 'resign'; keyId: string; alg?: string | null }
  | { action: 'tamper'; op: TamperOp }
  | {
      action: 'reencode';
      cbor?: CborSerialization;
      jose?: JoseSerialization | null;
      coseTags?: number[] | null;
      layers?: Layer[];
      deep?: boolean;
    }
  | { action: 'edit_disclosures'; ops: DisclosureOp[] };

export interface WorkspaceDeps {
  engine: Engine;
  platform: Platform;
  settings: Settings;
  keys: KeyStore;
}

export class Workspace {
  tabs = $state<Tab[]>([]);
  activeId = $state<string | null>(null);
  /** Two tabs side by side, or null. */
  split = $state<[string, string] | null>(null);

  readonly deps: WorkspaceDeps;

  constructor(deps: WorkspaceDeps) {
    this.deps = deps;
  }

  get active(): Tab | undefined {
    return this.tabs.find((t) => t.id === this.activeId);
  }

  tab(_id: string): Tab | undefined {
    notImplemented('Workspace.tab');
  }

  /** Detects, opens the top candidate in a new active tab, or routes keys
   *  to the key panel. */
  async openInput(_bytes: Uint8Array, _provenance: Provenance): Promise<OpenResult> {
    notImplemented('Workspace.openInput');
  }

  async openText(_text: string, _provenance: Provenance): Promise<OpenResult> {
    notImplemented('Workspace.openText');
  }

  async openFromClipboard(): Promise<OpenResult> {
    notImplemented('Workspace.openFromClipboard');
  }

  async openFromFile(): Promise<OpenResult> {
    notImplemented('Workspace.openFromFile');
  }

  /** "Detected as…": re-open the tab's input as another candidate. */
  async chooseCandidate(_tabId: string, _index: number): Promise<void> {
    notImplemented('Workspace.chooseCandidate');
  }

  activate(_id: string): void {
    notImplemented('Workspace.activate');
  }

  close(_id: string): void {
    notImplemented('Workspace.close');
  }

  splitWith(_left: string, _right: string): void {
    notImplemented('Workspace.splitWith');
  }

  unsplit(): void {
    notImplemented('Workspace.unsplit');
  }

  /** Root first, ending with this tab. */
  breadcrumb(_tabId: string): Crumb[] {
    notImplemented('Workspace.breadcrumb');
  }

  toggleCollapsed(_tabId: string, _id: NodeId): void {
    notImplemented('Workspace.toggleCollapsed');
  }

  setCollapsed(_tabId: string, _id: NodeId, _collapsed: boolean): void {
    notImplemented('Workspace.setCollapsed');
  }

  select(_tabId: string, _id: NodeId | null): void {
    notImplemented('Workspace.select');
  }

  toggleSdMark(_tabId: string, _id: NodeId): void {
    notImplemented('Workspace.toggleSdMark');
  }

  /** Re-render with the current settings (view toggles). Keeps view state. */
  async rerender(_tabId: string): Promise<void> {
    notImplemented('Workspace.rerender');
  }

  setLiveEdit(_tabId: string, _on: boolean): void {
    notImplemented('Workspace.setLiveEdit');
  }

  /** Live edit: parse `text`; on success replace the document (view state
   *  kept) and set `stale` from the result; on failure keep the document and
   *  store the diagnostics. */
  async applyEdit(_tabId: string, _text: string): Promise<EditResult> {
    notImplemented('Workspace.applyEdit');
  }

  /** "Keep original signature": keep the stale bytes, label the tab tampered. */
  keepOriginalSignature(_tabId: string): void {
    notImplemented('Workspace.keepOriginalSignature');
  }

  availability(_tabId: string): ActionAvailability {
    notImplemented('Workspace.availability');
  }

  /** Runs a credential-producing action; opens and activates a derived tab. */
  async runAction(_tabId: string, _req: ActionRequest): Promise<Tab> {
    notImplemented('Workspace.runAction');
  }

  /** Validates with the panel keys and settings; stores `tab.report`. */
  async validate(_tabId: string): Promise<ValidationReport> {
    notImplemented('Workspace.validate');
  }
}

export type { ActionId };
