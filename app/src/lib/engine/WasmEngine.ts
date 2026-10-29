// The web Engine: wraps tokenator-wasm (wasm-bindgen). The wasm crate does
// not exist yet; `load()` will dynamically import
// `crates/tokenator-wasm/pkg` and every method will call the matching
// binding with the DTO serialized as JSON (or via serde-wasm-bindgen).
import type { Engine } from './Engine';
import { NotImplemented } from '../notImplemented';

const stub = (name: string) => () => Promise.reject(new NotImplemented(`WasmEngine.${name}`));

export class WasmEngine implements Engine {
  /** `snapshot` goes to `Engine::with_registry_snapshot` (null: bundled). */
  static async load(snapshot: Uint8Array | null = null): Promise<WasmEngine> {
    return new WasmEngine(snapshot);
  }

  readonly snapshot: Uint8Array | null;

  private constructor(snapshot: Uint8Array | null) {
    this.snapshot = snapshot;
  }

  info = stub('info');
  detect = stub('detect');
  open = stub('open');
  render = stub('render');
  parseEdit = stub('parseEdit');
  issue = stub('issue');
  redact = stub('redact');
  disclose = stub('disclose');
  present = stub('present');
  validate = stub('validate');
  lint = stub('lint');
  resign = stub('resign');
  tamper = stub('tamper');
  reencode = stub('reencode');
  editDisclosures = stub('editDisclosures');
  decodeEmbedded = stub('decodeEmbedded');
  keyImport = stub('keyImport');
  keyExport = stub('keyExport');
  keyPublic = stub('keyPublic');
  keyGenerate = stub('keyGenerate');
  keyThumbprint = stub('keyThumbprint');
  keyAssignKid = stub('keyAssignKid');
  keyToJwk = stub('keyToJwk');
  keyToCwk = stub('keyToCwk');
  datetime = stub('datetime');
  registryLookup = stub('registryLookup');
  registryMerge = stub('registryMerge');
}
