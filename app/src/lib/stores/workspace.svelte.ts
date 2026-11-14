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
  Kind,
  Layer,
  NodeId,
  TamperOp,
  ValidationReport,
  ViewOptions,
} from '../engine/types';
import type { ActionAvailability, ActionId, Crumb, KeyRole, Provenance } from '../model';
import {
  TAB_TYPES,
  effectiveDraftKind,
  emptyDocument,
  isDraftKind,
  tabTypeOf,
  type DiscardReason,
  type DraftFormat,
  type TabType,
} from '../logic/drafts';
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
  /** Set for tabs written from scratch (#43); null/absent otherwise. */
  draft?: Draft | null;
  /** An empty tab (SPEC §4.1): no text yet. The first fill (typing, or a
   *  paste or drop that runs detection) ends it; only Clear brings it back. */
  empty?: boolean;
}

/** A draft tab's format and type (#43). */
export interface Draft {
  format: DraftFormat;
  /** Unused since edits stopped re-detecting (SPEC §3); kept null. */
  detected: Kind | null;
  /** The type: the empty tab's Type picker, or the type menu. Kept across
   *  edits until changed. */
  override: Kind | null;
}

/** The open date/time chit and the node it was opened from. */
export interface ChitTarget {
  tabId: string | null;
  nodeId: NodeId | null;
}

/** Shown when token detection finds nothing. */
export const NOTHING_DETECTED = 'Nothing recognizable was found in the input.';

export type ActionRequest =
  | {
      action: 'issue' | 'redact';
      /** Bind the Holder area's key (`cnf`). */
      cnf?: boolean;
      alg?: string | null;
      header?: HeaderOptions;
      jose?: JoseSerialization;
      coseTags?: number[] | null;
    }
  | { action: 'disclose'; keep: number[] }
  | {
      action: 'present';
      keep: number[];
      aud?: string | null;
      nonce?: string | null;
    }
  /** `key`: the area to sign with; by default the Issuer key when it
   *  has a private part, else the Holder key. */
  | { action: 'resign'; key?: KeyRole | null; alg?: string | null }
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

  /** Opens the one empty tab the app starts with (SPEC §4). */
  constructor(deps: WorkspaceDeps) {
    this.deps = deps;
    this.newTab();
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

  /** "+": a new empty tab (Live edit, no text, type not yet committed),
   *  active. */
  newTab(): Tab {
    const type = TAB_TYPES[0] as TabType;
    const tab = this.#newTab(emptyDocument(type.kind, type.format), { type: 'new' });
    this.#makeEmpty(tab, type);
    return tab;
  }

  #makeEmpty(tab: Tab, type: TabType): void {
    this.#cancelEdit(tab.id);
    tab.doc = emptyDocument(type.kind, type.format);
    tab.title = `Tab ${tab.number}`;
    tab.input = null;
    tab.candidates = [];
    tab.candidateIndex = 0;
    tab.provenance = { type: 'new' };
    tab.collapsed.clear();
    tab.sdMarks.clear();
    tab.selected = null;
    tab.liveEdit = true;
    tab.editText = '';
    tab.editDiagnostics = [];
    tab.editBase = '';
    tab.stale = false;
    tab.tampered = false;
    tab.report = null;
    tab.manualDecode = [];
    tab.hideDecoded = [];
    tab.draft = { format: type.format, detected: null, override: null };
    tab.empty = true;
  }

  /** Clear: the tab's text, type, decoded view, and title back to an
   *  empty tab. Keys are untouched. */
  clearTab(tabId: string): void {
    this.#makeEmpty(this.#get(tabId), TAB_TYPES[0] as TabType);
  }

  /** The Type picker entry of an empty tab (or a draft). */
  tabType(tab: Tab): TabType {
    const d = tab.draft;
    if (!d) return TAB_TYPES[0] as TabType;
    return tabTypeOf(d.format, effectiveDraftKind(d.format, null, d.override));
  }

  /** The empty tab's Type picker: the type typing will use. */
  setTabType(tabId: string, typeId: string): void {
    const tab = this.#get(tabId);
    const type = TAB_TYPES.find((t) => t.id === typeId);
    if (!tab.empty || !type) return;
    tab.draft = { format: type.format, detected: null, override: $state.snapshot(type.kind) };
    tab.doc = emptyDocument(type.kind, type.format);
  }

  /** First fill of an empty tab by a paste, drop, file, or clipboard:
   *  token detection (never keys, SPEC §3), and the top candidate opens
   *  in this tab with its text editable in Live edit. Rejects when nothing
   *  is detected (the tab stays empty). */
  async fillTab(tabId: string, bytes: Uint8Array, provenance: Provenance): Promise<Tab> {
    const { engine, settings } = this.deps;
    // `detect` returns no keys; dropping any keeps a JWK a JSON claim set
    // with an engine that still reports them.
    const candidates = (await engine.detect(bytes)).filter((c) => !isKey(c.kind));
    const top = candidates[0];
    if (!top) throw new Error(NOTHING_DETECTED);
    const doc = await engine.open(bytes, top, settings.viewOptions());
    const tab = this.#get(tabId);
    this.#cancelEdit(tabId);
    tab.doc = doc;
    tab.title = tabTitle(tab.number, doc);
    tab.input = bytes;
    tab.candidates = candidates;
    tab.candidateIndex = 0;
    tab.provenance = provenance;
    tab.collapsed.clear();
    tab.sdMarks.clear();
    tab.selected = null;
    tab.liveEdit = true;
    tab.editText = doc.main.text;
    tab.editDiagnostics = [];
    tab.editBase = doc.bytes;
    tab.stale = false;
    tab.tampered = false;
    tab.report = null;
    tab.draft = null;
    tab.empty = false;
    return tab;
  }

  /** Where input from outside a tab goes (Open File…, From Clipboard in
   *  the menu): the given or active tab when empty, else a new tab. */
  #target(tabId?: string | null): Tab {
    const tab = tabId ? this.tab(tabId) : this.active;
    return tab?.empty ? tab : this.newTab();
  }

  async openInput(bytes: Uint8Array, provenance: Provenance, tabId?: string | null): Promise<Tab> {
    return this.fillTab(this.#target(tabId).id, bytes, provenance);
  }

  async openText(text: string, provenance: Provenance, tabId?: string | null): Promise<Tab> {
    return this.openInput(utf8(text), provenance, tabId);
  }

  /** Null when the clipboard is empty. */
  async openFromClipboard(tabId?: string | null): Promise<Tab | null> {
    const text = await this.deps.platform.readClipboard();
    if (text.trim() === '') return null;
    return this.openInput(utf8(text), { type: 'clipboard' }, tabId);
  }

  /** Null when the user cancels the file dialog. */
  async openFromFile(tabId?: string | null): Promise<Tab | null> {
    const file = await this.deps.platform.openFile();
    if (!file) return null;
    return this.openInput(file.bytes, { type: 'file', name: file.name }, tabId);
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
    tab.editText = doc.main.text;
    tab.editDiagnostics = [];
    // A tab filled by a paste stays in Live edit.
    tab.editBase = tab.liveEdit ? doc.bytes : null;
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
    this.#cancelEdit(id);
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
    this.#commitType(tab, text);
    if (tab.draft) return this.#editDraft(tab, tab.draft, text);
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

  /** Pending (debounced) live edits by tab id. Not state: nothing renders them. */
  #scheduled: Record<string, { timer: ReturnType<typeof setTimeout>; text: string } | undefined> =
    {};

  /** Live edit from the editor: `editText` follows at once, the parse after
   *  a short pause. Actions flush it first, so they see the latest text. */
  scheduleEdit(tabId: string, text: string, delay = 150): void {
    const tab = this.#get(tabId);
    this.#commitType(tab, text);
    tab.editText = text;
    this.#cancelEdit(tabId);
    this.#scheduled[tabId] = {
      text,
      timer: setTimeout(() => void this.flushEdit(tabId).catch(() => undefined), delay),
    };
  }

  /** The first typed text ends an empty tab and commits the Type
   *  picker's type. */
  #commitType(tab: Tab, text: string): void {
    if (!tab.empty || !tab.draft || text === '') return;
    const d = tab.draft;
    d.override = $state.snapshot(effectiveDraftKind(d.format, null, d.override));
    tab.empty = false;
  }

  #cancelEdit(tabId: string): void {
    const pending = this.#scheduled[tabId];
    if (pending) clearTimeout(pending.timer);
    this.#scheduled[tabId] = undefined;
  }

  /** Runs a scheduled edit now, unless the text was replaced since (a
   *  Format switch, a date/time Insert). */
  async flushEdit(tabId: string): Promise<void> {
    const pending = this.#scheduled[tabId];
    if (!pending) return;
    clearTimeout(pending.timer);
    this.#scheduled[tabId] = undefined;
    const tab = this.tab(tabId);
    if (tab && tab.editText === pending.text) await this.applyEdit(tabId, pending.text);
  }

  /** "Keep original signature": keep the stale bytes, label the tab tampered. */
  keepOriginalSignature(tabId: string): void {
    this.#get(tabId).tampered = true;
  }

  availability(tabId: string): ActionAvailability {
    const tab = this.#get(tabId);
    return actionAvailability({
      doc: tab.doc,
      issuer: this.deps.keys.issuer,
      holder: this.deps.keys.holder,
      sdMarks: [...tab.sdMarks],
    });
  }

  #randomness(): Bytes {
    return toB64u(this.deps.platform.randomBytes(32));
  }

  /** Runs a credential-producing action; opens and activates a derived tab. */
  async runAction(tabId: string, req: ActionRequest): Promise<Tab> {
    await this.flushEdit(tabId);
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
          issuer: keys.ref('issuer'),
          alg: req.alg ?? null,
          ...(req.header ? { header: $state.snapshot(req.header) } : {}),
          sd: { marks: [...tab.sdMarks] },
          cnf: req.cnf ? { type: 'key' as const, key: keys.ref('holder') } : null,
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
          holder: keys.ref('holder'),
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
          key: keys.ref(req.key ?? (keys.issuer?.info.private ? 'issuer' : 'holder')),
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

  // ------------------------------------------------------------ drafts (#43)

  #draftOf(tabId: string): { tab: Tab; draft: Draft } {
    const tab = this.#get(tabId);
    if (!tab.draft) throw new Error(`${tab.title} is not a draft`);
    return { tab, draft: tab.draft };
  }

  /** The draft's type, from its format, detection, and explicit choice. */
  draftKind(tab: Tab): Kind | null {
    const d = tab.draft;
    return d ? effectiveDraftKind(d.format, d.detected, d.override) : null;
  }

  #retitle(tab: Tab): void {
    const kind = this.draftKind(tab) ?? tab.doc.kind;
    tab.title = `Tab ${tab.number} · ${kindLabel(kind)}`;
  }

  /** Parses a draft's text as its type. Edits never re-run detection
   *  (SPEC §3): the type changes only through the type menu. */
  async #editDraft(tab: Tab, draft: Draft, text: string): Promise<EditResult> {
    tab.editText = text;
    return this.#parseDraft(tab, draft, text);
  }

  /** Drafts have no original: the base is empty, and `signature_stale`
   *  (reported for signed kinds against that empty base) is ignored. */
  async #parseDraft(tab: Tab, draft: Draft, text: string): Promise<EditResult> {
    const kind = effectiveDraftKind(draft.format, draft.detected, draft.override);
    const result = await this.deps.engine.parseEdit({
      kind: $state.snapshot(kind),
      base: '',
      text,
      view: this.viewFor(tab),
    });
    if (tab.editText !== text) return result; // a newer edit is under way
    if (result.ok && result.document) {
      tab.doc = result.document;
      tab.editDiagnostics = [];
      tab.report = null;
    } else {
      tab.editDiagnostics = result.diagnostics.filter((d) => d.severity === 'error');
      if (tab.editDiagnostics.length === 0) tab.editDiagnostics = result.diagnostics;
    }
    tab.stale = false;
    tab.tampered = false;
    this.#retitle(tab);
    return result;
  }

  /** Switches a draft's Format, converting the text with
   *  `engine.convertClaims`; when that is missing or fails, asks
   *  `confirmDiscard` (with the reason) and, if allowed, starts over with
   *  no text. A draft with no text just switches. Returns whether the
   *  format changed. */
  async setDraftFormat(
    tabId: string,
    format: DraftFormat,
    confirmDiscard: (reason: DiscardReason) => Promise<boolean>,
  ): Promise<boolean> {
    await this.flushEdit(tabId);
    const { tab, draft } = this.#draftOf(tabId);
    const from = draft.format;
    if (from === format) return true;
    const text = tab.editText;
    let next: string | null = null;
    let reason: DiscardReason = {
      message: `This engine cannot convert ${from.toUpperCase()} to ${format.toUpperCase()}.`,
      nodeId: null,
    };
    if (text.trim() === '') {
      next = '';
    } else if (typeof this.deps.engine.convertClaims === 'function') {
      const result = await this.deps.engine.convertClaims({
        text,
        from,
        to: format,
        map_claim_labels: true,
        view: this.viewFor(tab),
      });
      if (result.ok && result.text !== null) next = result.text;
      else {
        const problem =
          result.diagnostics.find((d) => d.severity === 'error') ?? result.diagnostics[0];
        reason = {
          message: problem?.message ?? `The draft has no ${format.toUpperCase()} form.`,
          nodeId: problem?.node_id ?? null,
        };
      }
    }
    if (next === null) {
      if (!(await confirmDiscard(reason))) return false;
      next = '';
    }
    draft.format = format;
    if (draft.override && !isDraftKind(format, draft.override)) {
      draft.override = effectiveDraftKind(format, null, null);
    }
    await this.#editDraft(tab, draft, next);
    return true;
  }

  /** Sets (or with null clears) a draft's explicit type and re-parses. */
  async setDraftKind(tabId: string, kind: Kind | null): Promise<void> {
    await this.flushEdit(tabId);
    const { tab, draft } = this.#draftOf(tabId);
    draft.override = kind ? $state.snapshot(kind) : null;
    await this.#parseDraft(tab, draft, tab.editText);
  }

  /** Validates with the Issuer key (the engine verifies with its public
   *  part), the Holder key for key binding, and the settings; stores
   *  `tab.report`. */
  async validate(tabId: string): Promise<ValidationReport> {
    await this.flushEdit(tabId);
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
