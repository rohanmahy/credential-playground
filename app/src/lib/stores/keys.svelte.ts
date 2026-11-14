// The two key areas, Issuer and Holder (SPEC §4.2): each holds at most one
// key, plus the text shown for it. In memory only; keys reach the engine
// as KeyRef bytes on every call.
import type { Engine } from '../engine/Engine';
import type {
  Candidate,
  Document,
  HashName,
  KeyExport,
  KeyFormat,
  KeyInfo,
  KeyRef,
  KeySeed,
  KeySpec,
  KidSource,
  Thumbprint,
  ThumbprintKind,
  Visibility,
} from '../engine/types';
import { KEY_ROLE_LABELS, type KeyCard, type KeyRole, type Provenance } from '../model';
import type { Platform } from '../platform/Platform';
import { confirmedFetch, type Confirm, type FetchOutcome } from '../logic/fetch';
import { exportFileName } from '../logic/keys';
import { fromB64u, fromUtf8, textToB64u, toB64u, utf8 } from '../engine/bytes';

/** Where a new key's randomness comes from. */
export type SeedChoice =
  | { type: 'random' }
  | { type: 'well_known' }
  /** Deterministic from this user string (its UTF-8 bytes). */
  | { type: 'text'; seed: string };

export interface GenerateOptions {
  seed: SeedChoice;
  kid?: KidSource | null;
}

/** The key area's "Key format" toggle. */
export type KeyTextFormat = 'jwk' | 'cose_key';

/** Shown when key detection finds nothing (SPEC §3). */
export const NOT_A_KEY = 'Not a recognized key';

/** One key area's text and transient state. */
export interface KeyArea {
  /** The text area: the key as JWK or COSE_Key EDN, or what was typed. */
  text: string;
  format: KeyTextFormat;
  /** Why the text holds no key (it did not parse, or nothing was detected). */
  error: string | null;
  /** The keys of a set, waiting for the user to choose one. */
  choices: { infos: KeyInfo[]; provenance: Provenance } | null;
  /** `key.bytes` of the card `text` shows (null: none). The area
   *  re-renders when the card changes underneath it. */
  shown: string | null;
}

function emptyArea(): KeyArea {
  return { text: '', format: 'jwk', error: null, choices: null, shown: null };
}

/** The toggle position for a detected key kind: PEM shows as JWK. */
export function textFormatOf(candidate: Candidate): KeyTextFormat {
  const t = candidate.kind.type;
  return t === 'cose_key' || t === 'cose_key_set' ? 'cose_key' : 'jwk';
}

export class KeyStore {
  issuer = $state<KeyCard | null>(null);
  holder = $state<KeyCard | null>(null);
  areas = $state<Record<KeyRole, KeyArea>>({ issuer: emptyArea(), holder: emptyArea() });

  readonly #engine: Engine;
  readonly #platform: Platform;

  constructor(engine: Engine, platform: Platform) {
    this.#engine = engine;
    this.#platform = platform;
  }

  get engine(): Engine {
    return this.#engine;
  }

  get platform(): Platform {
    return this.#platform;
  }

  forRole(role: KeyRole): KeyCard | null {
    return role === 'issuer' ? this.issuer : this.holder;
  }

  #setCard(role: KeyRole, card: KeyCard | null): void {
    if (role === 'issuer') this.issuer = card;
    else this.holder = card;
  }

  area(role: KeyRole): KeyArea {
    return this.areas[role];
  }

  /** The keys held, Issuer first. */
  get cards(): KeyCard[] {
    return [this.issuer, this.holder].filter((c): c is KeyCard => c !== null);
  }

  /** A card by id (its role). */
  get(id: string): KeyCard | undefined {
    return id === 'issuer' || id === 'holder' ? (this.forRole(id) ?? undefined) : undefined;
  }

  #card(id: string): KeyCard {
    const card = this.get(id);
    if (!card) throw new Error(`No ${id} key`);
    return card;
  }

  /** `KeyRef`s for engine calls (label and role filled in). */
  refs(filter?: (card: KeyCard) => boolean): KeyRef[] {
    return this.cards.filter((c) => !filter || filter(c)).map((c) => this.#refOf(c));
  }

  ref(id: string): KeyRef {
    return this.#refOf(this.#card(id));
  }

  #refOf(card: KeyCard): KeyRef {
    const key = $state.snapshot(card.info.key);
    return { ...key, label: card.label, role: card.role };
  }

  /** Puts `info` into the area and shows it in the area's format. */
  async #fill(role: KeyRole, info: KeyInfo, provenance: Provenance): Promise<KeyCard> {
    this.#cancelEdit(role);
    const card: KeyCard = { id: role, label: KEY_ROLE_LABELS[role], role, info, provenance };
    this.#setCard(role, card);
    const area = this.areas[role];
    area.error = null;
    area.choices = null;
    await this.renderText(role);
    return this.forRole(role) ?? card;
  }

  /** Re-renders the area's text from its key, in the area's format.
   *  Private keys are shown with their private part. */
  async renderText(role: KeyRole): Promise<void> {
    const area = this.areas[role];
    const card = this.forRole(role);
    if (!card) {
      area.text = '';
      area.shown = null;
      return;
    }
    const bytes = card.info.key.bytes;
    area.shown = bytes;
    const visibility: Visibility = card.info.private ? 'private' : 'public';
    try {
      const text =
        area.format === 'jwk'
          ? prettyJson(await this.#engine.keyToJwk({ key: this.#refOf(card), visibility }))
          : (await this.#engine.keyToCwk({ key: this.#refOf(card), visibility })).main.text;
      if (this.forRole(role)?.info.key.bytes === bytes) area.text = text;
    } catch (e) {
      // A key neither JWK nor COSE_Key can hold (ML-DSA, expanded form
      // only) is referenced as PEM: show that.
      if (card.info.key.format?.type === 'pem') area.text = fromUtf8(fromB64u(bytes));
      else throw e;
    }
  }

  /** Key detection on input pasted or dropped into an empty area, or
   *  imported or fetched: one key fills the area; a set waits in
   *  `choices` for the user's pick. Rejects with "Not a recognized key"
   *  when nothing is detected. */
  async load(role: KeyRole, bytes: Uint8Array, provenance: Provenance): Promise<void> {
    const area = this.areas[role];
    area.error = null;
    const top = (await this.#engine.detectKey(bytes))[0];
    if (!top) throw new Error(NOT_A_KEY);
    // The original input goes in with its candidate, so the engine imports
    // the unwrapped payload (hex, base64, quotes, …).
    const infos = await this.#engine.keyImport({
      bytes: toB64u(bytes),
      candidate: $state.snapshot(top),
    });
    area.format = textFormatOf(top);
    await this.#offer(role, infos, provenance);
  }

  /** A paste or drop into the empty area: `load`, with a failure shown
   *  as the area's error ("Not a recognized key") instead of rejecting. */
  async drop(role: KeyRole, bytes: Uint8Array, provenance: Provenance): Promise<void> {
    try {
      await this.load(role, bytes, provenance);
    } catch (e) {
      this.areas[role].error = e instanceof Error ? e.message : String(e);
    }
  }

  async #offer(role: KeyRole, infos: KeyInfo[], provenance: Provenance): Promise<void> {
    const [only] = infos;
    if (!only) throw new Error(NOT_A_KEY);
    if (infos.length === 1) await this.#fill(role, only, provenance);
    else this.areas[role].choices = { infos, provenance };
  }

  /** The user picked key `index` of the waiting set. */
  async choose(role: KeyRole, index: number): Promise<void> {
    const choices = this.areas[role].choices;
    const info = choices?.infos[index];
    if (!choices || !info) return;
    await this.#fill(role, $state.snapshot(info), choices.provenance);
  }

  cancelChoice(role: KeyRole): void {
    this.areas[role].choices = null;
  }

  /** The "Key format" toggle: re-renders the key, or re-parses typed text
   *  that holds no key yet. */
  async setFormat(role: KeyRole, format: KeyTextFormat): Promise<void> {
    const area = this.areas[role];
    if (area.format === format) return;
    area.format = format;
    if (this.forRole(role)) {
      await this.flushEdit(role);
      if (this.forRole(role)) await this.renderText(role);
    } else if (area.text.trim() !== '') {
      this.#cancelEdit(role);
      await this.#parse(role, area.text);
    }
  }

  /** Pending (debounced) edits by role. Not state: nothing renders them. */
  #scheduled: Partial<Record<KeyRole, { timer: ReturnType<typeof setTimeout>; text: string }>> = {};

  /** Typed text: shown at once, parsed in the toggle's format after a
   *  pause. Typing never runs detection. */
  edit(role: KeyRole, text: string, delay = 300): void {
    const area = this.areas[role];
    area.text = text;
    area.choices = null;
    this.#cancelEdit(role);
    this.#scheduled[role] = {
      text,
      timer: setTimeout(() => void this.flushEdit(role).catch(() => undefined), delay),
    };
  }

  #cancelEdit(role: KeyRole): void {
    const pending = this.#scheduled[role];
    if (pending) clearTimeout(pending.timer);
    this.#scheduled[role] = undefined;
  }

  /** Runs a scheduled edit now. */
  async flushEdit(role: KeyRole): Promise<void> {
    const pending = this.#scheduled[role];
    if (!pending) return;
    this.#cancelEdit(role);
    if (this.areas[role].text === pending.text) await this.#parse(role, pending.text);
  }

  /** Parses typed text with the toggle's format hint. Text that does not
   *  parse leaves the area without a key and an error to show. */
  async #parse(role: KeyRole, text: string): Promise<void> {
    const area = this.areas[role];
    if (text.trim() === '') {
      this.#setCard(role, null);
      area.error = null;
      area.shown = null;
      return;
    }
    const format: KeyFormat = { type: area.format };
    const previous = this.forRole(role);
    try {
      const infos = await this.#engine.keyImport({ bytes: textToB64u(text), format });
      if (area.text !== text) return; // a newer edit is under way
      const [only] = infos;
      if (!only) throw new Error(NOT_A_KEY);
      if (infos.length > 1) {
        this.#setCard(role, null);
        area.shown = null;
        area.choices = { infos, provenance: previous?.provenance ?? { type: 'pasted' } };
        return;
      }
      // Keep the typed text as is: the area shows what the user wrote.
      this.#setCard(role, {
        id: role,
        label: KEY_ROLE_LABELS[role],
        role,
        info: only,
        provenance: previous?.provenance ?? { type: 'pasted' },
      });
      area.shown = only.key.bytes;
      area.error = null;
    } catch (e) {
      if (area.text !== text) return;
      this.#setCard(role, null);
      area.shown = null;
      area.error = e instanceof Error ? e.message : String(e);
    }
  }

  /** Clear: the area holds no key and no text; the next paste or drop
   *  runs detection again. */
  clear(role: KeyRole): void {
    this.#cancelEdit(role);
    this.#setCard(role, null);
    const area = this.areas[role];
    area.text = '';
    area.error = null;
    area.choices = null;
    area.shown = null;
  }

  async generate(role: KeyRole, spec: KeySpec, options: GenerateOptions): Promise<KeyCard> {
    const seed: KeySeed =
      options.seed.type === 'well_known'
        ? { type: 'well_known' }
        : options.seed.type === 'text'
          ? { type: 'seed', bytes: textToB64u(options.seed.seed) }
          : { type: 'entropy', bytes: toB64u(this.#platform.randomBytes(32)) };
    const info = await this.#engine.keyGenerate({ spec, role, seed, kid: options.kid ?? null });
    return this.#fill(role, info, { type: 'generated' });
  }

  async importText(role: KeyRole, text: string): Promise<void> {
    return this.load(role, utf8(text), { type: 'pasted' });
  }

  async importFromClipboard(role: KeyRole): Promise<void> {
    const text = await this.#platform.readClipboard();
    return this.load(role, utf8(text), { type: 'clipboard' });
  }

  /** False when the user cancels the file dialog. */
  async importFromFile(role: KeyRole): Promise<boolean> {
    const file = await this.#platform.openFile({ accept: KEY_FILE_TYPES });
    if (!file) return false;
    await this.load(role, file.bytes, { type: 'file', name: file.name });
    return true;
  }

  /** Confirmed fetch of a JWK Set / COSE_KeySet / jwt-vc-issuer metadata
   *  into the area. */
  async fetchFromUrl(role: KeyRole, url: string, confirm: Confirm): Promise<FetchOutcome> {
    const outcome = await confirmedFetch(this.#platform, url, confirm);
    if (outcome.type !== 'ok') return outcome;
    const metadata = issuerMetadata(outcome.result.bytes);
    if (metadata?.jwks) {
      await this.load(role, utf8(metadata.jwks), { type: 'url', url });
      return outcome;
    }
    if (metadata?.jwksUri) {
      // jwt-vc-issuer metadata pointing elsewhere: a second, separately confirmed fetch.
      return this.fetchFromUrl(role, metadata.jwksUri, confirm);
    }
    await this.load(role, outcome.result.bytes, { type: 'url', url });
    return outcome;
  }

  async export(id: string, format: KeyFormat, visibility: Visibility): Promise<KeyExport> {
    return this.#engine.keyExport({
      key: this.ref(id),
      format: $state.snapshot(format),
      visibility,
    });
  }

  /** Copies the export; private exports are sent with `sensitive: true`.
   *  Returns the status message to announce (names a private key as such). */
  async copyToClipboard(id: string, format: KeyFormat, visibility: Visibility): Promise<string> {
    const exported = await this.export(id, format, visibility);
    const text = exported.text ?? hex(fromB64u(exported.bytes));
    await this.#platform.writeClipboard(text, { sensitive: exported.private });
    return exported.private ? 'Private key copied to clipboard' : 'Public key copied to clipboard';
  }

  async saveToFile(id: string, format: KeyFormat, visibility: Visibility): Promise<boolean> {
    const exported = await this.export(id, format, visibility);
    const name = exportFileName(this.#card(id).label, format, exported.private);
    return this.#platform.saveFile(name, exported.text ?? fromB64u(exported.bytes));
  }

  /** Make public: the area's key is replaced by its public part. */
  async makePublic(role: KeyRole): Promise<KeyCard> {
    await this.flushEdit(role);
    const info = await this.#engine.keyPublic(this.ref(role));
    return this.#fill(role, info, { type: 'derived_key', parent: role, how: 'public' });
  }

  /** Auto kid: sets the kid and re-renders the text. */
  async assignKid(role: KeyRole, source: KidSource): Promise<KeyCard> {
    await this.flushEdit(role);
    const card = this.#card(role);
    const info = await this.#engine.keyAssignKid({ key: this.ref(role), source });
    return this.#fill(role, info, card.provenance);
  }

  async toJwk(id: string, visibility: Visibility): Promise<string> {
    return this.#engine.keyToJwk({ key: this.ref(id), visibility });
  }

  async toCwk(id: string, visibility: Visibility): Promise<Document> {
    return this.#engine.keyToCwk({ key: this.ref(id), visibility });
  }

  async thumbprint(id: string, kind: ThumbprintKind, hash: HashName): Promise<Thumbprint> {
    return this.#engine.keyThumbprint({ key: this.ref(id), kind, hash });
  }
}

const KEY_FILE_TYPES = ['.pem', '.json', '.jwk', '.jwks', '.cbor', '.cose', '.edn', '.key', '.txt'];

/** A JWK indented for the text area (member order kept). */
function prettyJson(text: string): string {
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** jwt-vc-issuer metadata (SD-JWT VC §5): inline `jwks` or a `jwks_uri`. */
function issuerMetadata(bytes: Uint8Array): { jwks?: string; jwksUri?: string } | null {
  try {
    const json: unknown = JSON.parse(fromUtf8(bytes));
    if (typeof json !== 'object' || json === null || 'keys' in json) return null;
    const meta = json as { jwks?: unknown; jwks_uri?: unknown };
    if (typeof meta.jwks === 'object' && meta.jwks !== null)
      return { jwks: JSON.stringify(meta.jwks) };
    if (typeof meta.jwks_uri === 'string') return { jwksUri: meta.jwks_uri };
    return null;
  } catch {
    return null;
  }
}
