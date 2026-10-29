// Key cards (SPEC §4.2). In memory only; keys reach the engine as KeyRef
// bytes on every call.
import type { Engine } from '../engine/Engine';
import type {
  Document,
  HashName,
  KeyExport,
  KeyFormat,
  KeyRef,
  KeySpec,
  KidSource,
  Role,
  Thumbprint,
  ThumbprintKind,
  Visibility,
} from '../engine/types';
import type { KeyCard, Provenance } from '../model';
import type { Platform } from '../platform/Platform';
import type { Confirm, FetchOutcome } from '../logic/fetch';
import { notImplemented } from '../notImplemented';

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

  get(_id: string): KeyCard | undefined {
    notImplemented('KeyStore.get');
  }

  /** `KeyRef`s for engine calls (label and role filled in). */
  refs(_filter?: (card: KeyCard) => boolean): KeyRef[] {
    notImplemented('KeyStore.refs');
  }

  ref(_id: string): KeyRef {
    notImplemented('KeyStore.ref');
  }

  async generate(_spec: KeySpec, _options: GenerateOptions): Promise<KeyCard> {
    notImplemented('KeyStore.generate');
  }

  /** Imports a key or a set (one card per key). */
  async importBytes(
    _bytes: Uint8Array,
    _provenance: Provenance,
    _format?: KeyFormat | null,
  ): Promise<KeyCard[]> {
    notImplemented('KeyStore.importBytes');
  }

  async importText(_text: string): Promise<KeyCard[]> {
    notImplemented('KeyStore.importText');
  }

  async importFromClipboard(): Promise<KeyCard[]> {
    notImplemented('KeyStore.importFromClipboard');
  }

  /** Empty when the user cancels the file dialog. */
  async importFromFile(): Promise<KeyCard[]> {
    notImplemented('KeyStore.importFromFile');
  }

  /** Confirmed fetch of a JWK Set / COSE_KeySet / jwt-vc-issuer metadata. */
  async fetchFromUrl(
    _url: string,
    _confirm: Confirm,
  ): Promise<{ outcome: FetchOutcome; cards: KeyCard[] }> {
    notImplemented('KeyStore.fetchFromUrl');
  }

  async export(_id: string, _format: KeyFormat, _visibility: Visibility): Promise<KeyExport> {
    notImplemented('KeyStore.export');
  }

  /** Copies the export; private exports are sent with `sensitive: true`.
   *  Returns the status message to announce (names a private key as such). */
  async copyToClipboard(_id: string, _format: KeyFormat, _visibility: Visibility): Promise<string> {
    notImplemented('KeyStore.copyToClipboard');
  }

  async saveToFile(_id: string, _format: KeyFormat, _visibility: Visibility): Promise<boolean> {
    notImplemented('KeyStore.saveToFile');
  }

  /** A new card with the public key, provenance `derived_key`. */
  async derivePublic(_id: string): Promise<KeyCard> {
    notImplemented('KeyStore.derivePublic');
  }

  async assignKid(_id: string, _source: KidSource): Promise<KeyCard> {
    notImplemented('KeyStore.assignKid');
  }

  setRole(_id: string, _role: Role | null): void {
    notImplemented('KeyStore.setRole');
  }

  setLabel(_id: string, _label: string): void {
    notImplemented('KeyStore.setLabel');
  }

  remove(_id: string): void {
    notImplemented('KeyStore.remove');
  }

  async toJwk(_id: string, _visibility: Visibility): Promise<string> {
    notImplemented('KeyStore.toJwk');
  }

  async toCwk(_id: string, _visibility: Visibility): Promise<Document> {
    notImplemented('KeyStore.toCwk');
  }

  async thumbprint(_id: string, _kind: ThumbprintKind, _hash: HashName): Promise<Thumbprint> {
    notImplemented('KeyStore.thumbprint');
  }
}
