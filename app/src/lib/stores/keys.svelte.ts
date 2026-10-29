// Key cards (SPEC §4.2). In memory only; keys reach the engine as KeyRef
// bytes on every call.
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
  Role,
  Thumbprint,
  ThumbprintKind,
  Visibility,
} from '../engine/types';
import type { KeyCard, Provenance } from '../model';
import type { Platform } from '../platform/Platform';
import { confirmedFetch, type Confirm, type FetchOutcome } from '../logic/fetch';
import { exportFileName, kidText } from '../logic/keys';
import { fromB64u, fromUtf8, textToB64u, toB64u, utf8 } from '../engine/bytes';

/** Where a new key's randomness comes from. */
export type SeedChoice =
  | { type: 'random' }
  | { type: 'well_known' }
  /** Deterministic from this user string (its UTF-8 bytes). */
  | { type: 'text'; seed: string };

export interface GenerateOptions {
  seed: SeedChoice;
  role?: Role | null;
  kid?: KidSource | null;
  label?: string;
}

export class KeyStore {
  cards = $state<KeyCard[]>([]);

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

  get(id: string): KeyCard | undefined {
    return this.cards.find((c) => c.id === id);
  }

  #card(id: string): KeyCard {
    const card = this.get(id);
    if (!card) throw new Error(`no key ${id}`);
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

  #nextId(): string {
    const used = this.cards.map((c) => c.id);
    let n = this.cards.length + 1;
    while (used.includes(`key-${n}`)) n++;
    return `key-${n}`;
  }

  #uniqueLabel(base: string): string {
    const used = this.cards.map((c) => c.label);
    if (!used.includes(base)) return base;
    let n = 2;
    while (used.includes(`${base} ${n}`)) n++;
    return `${base} ${n}`;
  }

  #add(info: KeyInfo, provenance: Provenance, label: string, role: Role | null): KeyCard {
    const card: KeyCard = {
      id: this.#nextId(),
      label: this.#uniqueLabel(label),
      role,
      info,
      provenance,
    };
    this.cards.push(card);
    return this.cards[this.cards.length - 1] ?? card;
  }

  async generate(spec: KeySpec, options: GenerateOptions): Promise<KeyCard> {
    const seed: KeySeed =
      options.seed.type === 'well_known'
        ? { type: 'well_known' }
        : options.seed.type === 'text'
          ? { type: 'seed', bytes: textToB64u(options.seed.seed) }
          : { type: 'entropy', bytes: toB64u(this.#platform.randomBytes(32)) };
    const role = options.role ?? null;
    const info = await this.#engine.keyGenerate({ spec, role, seed, kid: options.kid ?? null });
    const roleName = role ? `${role[0]?.toUpperCase()}${role.slice(1)} ` : '';
    return this.#add(
      info,
      { type: 'generated' },
      options.label ?? `${roleName}${info.description}`,
      role ?? info.role,
    );
  }

  /** Imports a key or a set (one card per key). */
  async importBytes(
    bytes: Uint8Array,
    provenance: Provenance,
    format?: KeyFormat | null,
    candidate?: Candidate | null,
  ): Promise<KeyCard[]> {
    // With a detected candidate, the engine unwraps its layers (hex,
    // base64, quotes, …) before importing (#42).
    const infos = await this.#engine.keyImport({
      bytes: toB64u(bytes),
      format: format ?? null,
      ...(candidate ? { candidate: $state.snapshot(candidate) } : {}),
    });
    return infos.map((info) => {
      const kid = kidText(info.kid);
      return this.#add(
        info,
        provenance,
        kid ? `${info.description} (${kid})` : info.description,
        info.role,
      );
    });
  }

  async importText(text: string): Promise<KeyCard[]> {
    return this.importBytes(utf8(text), { type: 'pasted' });
  }

  async importFromClipboard(): Promise<KeyCard[]> {
    const text = await this.#platform.readClipboard();
    return this.importBytes(utf8(text), { type: 'clipboard' });
  }

  /** Empty when the user cancels the file dialog. */
  async importFromFile(): Promise<KeyCard[]> {
    const file = await this.#platform.openFile({ accept: KEY_FILE_TYPES });
    if (!file) return [];
    return this.importBytes(file.bytes, { type: 'file', name: file.name });
  }

  /** Confirmed fetch of a JWK Set / COSE_KeySet / jwt-vc-issuer metadata. */
  async fetchFromUrl(
    url: string,
    confirm: Confirm,
  ): Promise<{ outcome: FetchOutcome; cards: KeyCard[] }> {
    const outcome = await confirmedFetch(this.#platform, url, confirm);
    if (outcome.type !== 'ok') return { outcome, cards: [] };
    const metadata = issuerMetadata(outcome.result.bytes);
    if (metadata?.jwks) {
      return { outcome, cards: await this.importBytes(utf8(metadata.jwks), { type: 'url', url }) };
    }
    if (metadata?.jwksUri) {
      // jwt-vc-issuer metadata pointing elsewhere: a second, separately confirmed fetch.
      return this.fetchFromUrl(metadata.jwksUri, confirm);
    }
    return { outcome, cards: await this.importBytes(outcome.result.bytes, { type: 'url', url }) };
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

  /** A new card with the public key, provenance `derived_key`. */
  async derivePublic(id: string): Promise<KeyCard> {
    const parent = this.#card(id);
    const info = await this.#engine.keyPublic(this.ref(id));
    return this.#add(
      info,
      { type: 'derived_key', parent: id, how: 'public' },
      `${parent.label} (public)`,
      'verifier',
    );
  }

  async assignKid(id: string, source: KidSource): Promise<KeyCard> {
    const info = await this.#engine.keyAssignKid({ key: this.ref(id), source });
    const card = this.#card(id);
    card.info = info;
    return card;
  }

  setRole(id: string, role: Role | null): void {
    this.#card(id).role = role;
  }

  setLabel(id: string, label: string): void {
    this.#card(id).label = label;
  }

  remove(id: string): void {
    this.cards = this.cards.filter((c) => c.id !== id);
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
