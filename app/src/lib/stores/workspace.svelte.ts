// The workspace: credential tabs, their per-tab view state, the provenance
// graph, and the split (SPEC §4, §5). In memory only.
import { SvelteSet } from 'svelte/reactivity';
import type { Engine } from '../engine/Engine';
import type {
  Bytes,
  Candidate,
  CborSerialization,
  Diagnostic,
  DisclosureOp,
  DocRef,
  Document,
  EditResult,
  HeaderOptions,
  JoseSerialization,
  Layer,
  NodeId,
  TamperOp,
  ValidationReport,
  ViewOptions,
} from '../engine/types';
import type { ActionAvailability, ActionId, Crumb, Provenance } from '../model';
import type { Platform } from '../platform/Platform';
import type { KeyStore } from './keys.svelte';
import type { Settings } from './settings.svelte';
import { fromB64u, toB64u, utf8 } from '../engine/bytes';
import { actionAvailability } from '../logic/actions';
import { isKey, kindLabel } from '../logic/kinds';
import { ancestorIds } from '../logic/tree';

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
  /** Bytes live edits are compared against (set when live edit starts). */
  editBase?: Bytes | null;
  /** Byte strings the user chose to decode as CBOR (ViewOptions.manual_decode). */
  manualDecode?: NodeId[];
  /** Decoded views the user turned off (ViewOptions.hide_decoded). */
  hideDecoded?: NodeId[];
}

/** The open date/time chit and the node it was opened from. */
export interface ChitTarget {
  tabId: string | null;
  nodeId: NodeId | null;
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
      coseTags?: number[] | null;
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
  chit = $state<ChitTarget | null>(null);

  readonly deps: WorkspaceDeps;

  constructor(deps: WorkspaceDeps) {
    this.deps = deps;
  }

  get active(): Tab | undefined {
    return this.tabs.find((t) => t.id === this.activeId);
  }

  tab(id: string): Tab | undefined {
    return this.tabs.find((t) => t.id === id);
  }

  #get(id: string): Tab {
    const tab = this.tab(id);
    if (!tab) throw new Error(`no tab ${id}`);
    return tab;
  }

  #lastNumber = 0;

  #newTab(
    doc: Document,
    provenance: Provenance,
    extra: { input?: Uint8Array | null; candidates?: Candidate[]; tampered?: boolean } = {},
  ): Tab {
    const number = Math.max(this.#lastNumber, ...this.tabs.map((t) => t.number)) + 1;
    this.#lastNumber = number;
    const tab: Tab = {
      id: `tab-${number}`,
      number,
      title: tabTitle(number, doc),
      doc,
      input: extra.input ?? null,
      candidates: extra.candidates ?? [],
      candidateIndex: 0,
      provenance,
      collapsed: new SvelteSet(),
      selected: null,
      liveEdit: false,
      editText: doc.main.text,
      editDiagnostics: [],
      stale: false,
      tampered: extra.tampered ?? false,
      sdMarks: new SvelteSet(),
      report: null,
      editBase: null,
    };
    this.tabs.push(tab);
    this.activeId = tab.id;
    return this.#get(tab.id);
  }

  /** Detects, opens the top candidate in a new active tab, or routes keys
   *  to the key panel. */
  async openInput(bytes: Uint8Array, provenance: Provenance): Promise<OpenResult> {
    const { engine, keys, settings } = this.deps;
    const candidates = await engine.detect(bytes);
    const top = candidates[0];
    if (!top) return { type: 'nothing' };
    if (isKey(top.kind)) {
      const cards = await keys.importBytes(bytes, provenance);
      return { type: 'keys', cardIds: cards.map((c) => c.id) };
    }
    const doc = await engine.open(bytes, top, settings.viewOptions());
    const tab = this.#newTab(doc, provenance, { input: bytes, candidates });
    return { type: 'tab', tabId: tab.id };
  }

  async openText(text: string, provenance: Provenance): Promise<OpenResult> {
    return this.openInput(utf8(text), provenance);
  }

  async openFromClipboard(): Promise<OpenResult> {
    const text = await this.deps.platform.readClipboard();
    if (text.trim() === '') return { type: 'nothing' };
    return this.openInput(utf8(text), { type: 'clipboard' });
  }

  async openFromFile(): Promise<OpenResult> {
    const file = await this.deps.platform.openFile();
    if (!file) return { type: 'nothing' };
    return this.openInput(file.bytes, { type: 'file', name: file.name });
  }

  /** "Detected as…": re-open the tab's input as another candidate. */
  async chooseCandidate(tabId: string, index: number): Promise<void> {
    const tab = this.#get(tabId);
    const candidate = tab.candidates[index];
    if (!candidate || !tab.input) return;
    const doc = await this.deps.engine.open(
      tab.input,
      $state.snapshot(candidate),
      this.deps.settings.viewOptions(),
    );
    tab.doc = doc;
    tab.candidateIndex = index;
    tab.title = tabTitle(tab.number, doc);
    tab.collapsed.clear();
    tab.sdMarks.clear();
    tab.selected = null;
    tab.liveEdit = false;
    tab.editText = doc.main.text;
    tab.editDiagnostics = [];
    tab.editBase = null;
    tab.stale = false;
    tab.tampered = false;
    tab.report = null;
  }

  activate(id: string): void {
    if (this.tab(id)) this.activeId = id;
  }

  close(id: string): void {
    const at = this.tabs.findIndex((t) => t.id === id);
    if (at < 0) return;
    this.tabs.splice(at, 1);
    if (this.split?.includes(id)) this.split = null;
    if (this.activeId === id) {
      this.activeId = (this.tabs[at] ?? this.tabs[at - 1])?.id ?? null;
    }
  }

  splitWith(left: string, right: string): void {
    if (left === right || !this.tab(left) || !this.tab(right)) return;
    this.split = [left, right];
    if (this.activeId !== left && this.activeId !== right) this.activeId = left;
  }

  unsplit(): void {
    this.split = null;
  }

  /** Root first, ending with this tab. */
  breadcrumb(tabId: string): Crumb[] {
    const crumbs: Crumb[] = [];
    const seen: string[] = [];
    let tab = this.tab(tabId);
    while (tab && !seen.includes(tab.id)) {
      seen.push(tab.id);
      const p = tab.provenance;
      crumbs.unshift({
        tabId: tab.id,
        title: tab.title,
        action: p.type === 'derived' ? p.action : null,
      });
      tab = p.type === 'derived' ? this.tab(p.parent) : undefined;
    }
    return crumbs;
  }

  toggleCollapsed(tabId: string, id: NodeId): void {
    const tab = this.#get(tabId);
    this.setCollapsed(tabId, id, !tab.collapsed.has(id));
  }

  setCollapsed(tabId: string, id: NodeId, collapsed: boolean): void {
    const set = this.#get(tabId).collapsed;
    if (collapsed) set.add(id);
    else set.delete(id);
  }

  select(tabId: string, id: NodeId | null): void {
    this.#get(tabId).selected = id;
  }

  /** Selects a node and unfolds its ancestors so it is visible. */
  reveal(tabId: string, id: NodeId): void {
    const tab = this.#get(tabId);
    for (const a of ancestorIds(id)) tab.collapsed.delete(a);
    tab.selected = id;
  }

  toggleSdMark(tabId: string, id: NodeId): void {
    const marks = this.#get(tabId).sdMarks;
    if (marks.has(id)) marks.delete(id);
    else marks.add(id);
  }

  /** The settings' view options plus the tab's own decode choices. */
  viewFor(tab: Tab): ViewOptions {
    return {
      ...this.deps.settings.viewOptions(),
      manual_decode: [...(tab.manualDecode ?? [])],
      hide_decoded: [...(tab.hideDecoded ?? [])],
    };
  }

  /** Re-render with the current settings (view toggles). Keeps view state. */
  async rerender(tabId: string): Promise<void> {
    const tab = this.#get(tabId);
    const doc = await this.deps.engine.render({
      doc: docRef(tab.doc),
      layers: $state.snapshot(tab.doc.layers),
      view: this.viewFor(tab),
    });
    tab.doc = doc;
    if (!tab.liveEdit) tab.editText = doc.main.text;
  }

  async rerenderAll(): Promise<void> {
    await Promise.all(this.tabs.map((t) => this.rerender(t.id)));
  }

  /** "Decode as CBOR" at a byte string the format does not define. */
  async decodeAsCbor(tabId: string, id: NodeId): Promise<void> {
    const tab = this.#get(tabId);
    tab.manualDecode = [...(tab.manualDecode ?? []).filter((n) => n !== id), id];
    await this.rerender(tabId);
  }

  /** Turns a node's decoded view off or back on. */
  async toggleDecodedView(tabId: string, id: NodeId): Promise<void> {
    const tab = this.#get(tabId);
    const hidden = tab.hideDecoded ?? [];
    tab.hideDecoded = hidden.includes(id) ? hidden.filter((n) => n !== id) : [...hidden, id];
    tab.manualDecode = (tab.manualDecode ?? []).filter((n) => n !== id);
    await this.rerender(tabId);
  }

  openChit(tabId: string | null = null, nodeId: NodeId | null = null): void {
    this.chit = { tabId, nodeId };
  }

  closeChit(): void {
    this.chit = null;
  }

  setLiveEdit(tabId: string, on: boolean): void {
    const tab = this.#get(tabId);
    tab.liveEdit = on;
    tab.editDiagnostics = [];
    tab.editText = tab.doc.main.text;
    if (on) tab.editBase ??= tab.doc.bytes;
  }

  /** Live edit: parse `text`; on success replace the document (view state
   *  kept) and set `stale` from the result; on failure keep the document and
   *  store the diagnostics. */
  async applyEdit(tabId: string, text: string): Promise<EditResult> {
    const tab = this.#get(tabId);
    tab.editText = text;
    const result = await this.deps.engine.parseEdit({
      kind: $state.snapshot(tab.doc.kind),
      base: tab.editBase ?? tab.doc.bytes,
      text,
      view: this.viewFor(tab),
    });
    if (tab.editText !== text) return result; // a newer edit is under way
    if (result.ok && result.document) {
      tab.doc = result.document;
      tab.stale = result.signature_stale;
      tab.tampered = tab.tampered && tab.stale;
      tab.editDiagnostics = [];
      tab.report = null;
    } else {
      tab.editDiagnostics = result.diagnostics.filter((d) => d.severity === 'error');
      if (tab.editDiagnostics.length === 0) tab.editDiagnostics = result.diagnostics;
    }
    return result;
  }

  /** "Keep original signature": keep the stale bytes, label the tab tampered. */
  keepOriginalSignature(tabId: string): void {
    this.#get(tabId).tampered = true;
  }

  availability(tabId: string): ActionAvailability {
    const tab = this.#get(tabId);
    return actionAvailability({
      doc: tab.doc,
      keys: this.deps.keys.cards,
      sdMarks: [...tab.sdMarks],
    });
  }

  #randomness(): Bytes {
    return toB64u(this.deps.platform.randomBytes(32));
  }

  /** Runs a credential-producing action; opens and activates a derived tab. */
  async runAction(tabId: string, req: ActionRequest): Promise<Tab> {
    const tab = this.#get(tabId);
    const { engine, keys, settings } = this.deps;
    const doc = docRef(tab.doc);
    const view = settings.viewOptions();
    let out: Document;
    let input: Uint8Array | null = null;
    switch (req.action) {
      case 'issue':
      case 'redact': {
        const request = {
          claims: doc,
          issuer: keys.ref(req.issuerKeyId),
          alg: req.alg ?? null,
          ...(req.header ? { header: $state.snapshot(req.header) } : {}),
          sd: { marks: [...tab.sdMarks] },
          cnf: req.holderKeyId ? { type: 'key' as const, key: keys.ref(req.holderKeyId) } : null,
          jose_serialization: req.jose ?? 'compact',
          cose_tags: req.coseTags ? [...req.coseTags] : null,
          randomness: this.#randomness(),
          view,
        };
        out = await (req.action === 'issue' ? engine.issue(request) : engine.redact(request));
        break;
      }
      case 'disclose':
        out = await engine.disclose({ doc, keep: [...req.keep], view });
        break;
      case 'present':
        out = await engine.present({
          doc,
          keep: [...req.keep],
          holder: keys.ref(req.holderKeyId),
          alg: null,
          aud: req.aud || null,
          nonce: req.nonce ? { type: 'text', value: req.nonce } : null,
          iat: settings.now(),
          randomness: this.#randomness(),
          view,
        });
        break;
      case 'resign':
        out = await engine.resign({
          doc,
          key: keys.ref(req.keyId),
          alg: req.alg ?? null,
          randomness: this.#randomness(),
          view,
        });
        break;
      case 'tamper':
        out = await engine.tamper({ doc, op: $state.snapshot(req.op), view });
        break;
      case 'reencode': {
        const res = await engine.reencode({
          doc,
          layers: $state.snapshot(req.layers ?? tab.doc.layers),
          cose_tags: req.coseTags ?? null,
          cbor: req.cbor ?? 'preserve',
          deep: req.deep ?? false,
          jose: req.jose ?? null,
          view,
        });
        out = res.document;
        input = fromB64u(res.output);
        break;
      }
      case 'edit_disclosures':
        out = await engine.editDisclosures({
          doc,
          ops: $state.snapshot(req.ops),
          randomness: this.#randomness(),
          view,
        });
        break;
    }
    return this.#newTab(
      out,
      { type: 'derived', parent: tabId, action: req.action },
      { input, tampered: out.signature_stale },
    );
  }

  /** Validates with the panel keys and settings; stores `tab.report`. */
  async validate(tabId: string): Promise<ValidationReport> {
    const tab = this.#get(tabId);
    const { engine, keys, settings } = this.deps;
    const report = await engine.validate({
      doc: docRef(tab.doc),
      keys: keys.refs(),
      now: settings.now(),
      skew: settings.skew,
      expected_aud: settings.expectedAud || null,
      expected_nonce: settings.expectedNonce
        ? { type: 'text', value: settings.expectedNonce }
        : null,
      max_kb_age: null,
    });
    tab.report = report;
    return report;
  }
}

/** `Tab 3 · SD-JWT`. */
export function tabTitle(number: number, doc: Document): string {
  return `Tab ${number} · ${kindLabel(doc.kind)}`;
}

function docRef(doc: Document): DocRef {
  return { kind: $state.snapshot(doc.kind), bytes: doc.bytes };
}

export type { ActionId };
