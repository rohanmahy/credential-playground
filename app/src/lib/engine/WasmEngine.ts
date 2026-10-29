// The web Engine: wraps tokenator-wasm (wasm-bindgen, `pnpm build:wasm`).
// Contract (crates/tokenator-wasm/TEST-PLAN.md §2):
// - `load()` resolves at once; the module `tokenator-wasm` is imported and
//   instantiated on the first call (once, shared by concurrent calls), and
//   a `TokenatorEngine` is built from `snapshot`.
// - Every method calls the binding of the same snake_case name with
//   `JSON.stringify(req)` (raw input as the Uint8Array itself) and parses
//   the `{"ok":…}` / `{"err":…}` envelope: `ok` resolves, `err` rejects
//   with `EngineFailure(err)`.
// - Anything else that fails (the module does not load, a panic traps,
//   the snapshot throws) rejects with an `EngineFailure` too: code
//   `internal` (or the envelope's code for the constructor), never a bare
//   Error. The engine keeps answering after a panic.
import type { Engine } from './Engine';
import { NotImplemented } from '../notImplemented';

export interface WasmEngineOptions {
  /** The .wasm to instantiate instead of fetching the bundled asset
   *  (Node tests pass the file's bytes). */
  wasm?: BufferSource | WebAssembly.Module;
}

const stub = (name: string) => () => Promise.reject(new NotImplemented(`WasmEngine.${name}`));

export class WasmEngine implements Engine {
  /** `snapshot` goes to `Engine::with_registry_snapshot` (null: bundled). */
  static async load(
    snapshot: Uint8Array | null = null,
    options: WasmEngineOptions = {},
  ): Promise<WasmEngine> {
    return new WasmEngine(snapshot, options);
  }

  readonly snapshot: Uint8Array | null;
  readonly options: WasmEngineOptions;

  private constructor(snapshot: Uint8Array | null, options: WasmEngineOptions) {
    this.snapshot = snapshot;
    this.options = options;
  }

  info: Engine['info'] = stub('info');
  detect: Engine['detect'] = stub('detect');
  open: Engine['open'] = stub('open');
  render: Engine['render'] = stub('render');
  parseEdit: Engine['parseEdit'] = stub('parseEdit');
  issue: Engine['issue'] = stub('issue');
  redact: Engine['redact'] = stub('redact');
  disclose: Engine['disclose'] = stub('disclose');
  present: Engine['present'] = stub('present');
  validate: Engine['validate'] = stub('validate');
  lint: Engine['lint'] = stub('lint');
  resign: Engine['resign'] = stub('resign');
  tamper: Engine['tamper'] = stub('tamper');
  reencode: Engine['reencode'] = stub('reencode');
  editDisclosures: Engine['editDisclosures'] = stub('editDisclosures');
  decodeEmbedded: Engine['decodeEmbedded'] = stub('decodeEmbedded');
  keyImport: Engine['keyImport'] = stub('keyImport');
  keyExport: Engine['keyExport'] = stub('keyExport');
  keyPublic: Engine['keyPublic'] = stub('keyPublic');
  keyGenerate: Engine['keyGenerate'] = stub('keyGenerate');
  keyThumbprint: Engine['keyThumbprint'] = stub('keyThumbprint');
  keyAssignKid: Engine['keyAssignKid'] = stub('keyAssignKid');
  keyToJwk: Engine['keyToJwk'] = stub('keyToJwk');
  keyToCwk: Engine['keyToCwk'] = stub('keyToCwk');
  datetime: Engine['datetime'] = stub('datetime');
  registryLookup: Engine['registryLookup'] = stub('registryLookup');
  registryMerge: Engine['registryMerge'] = stub('registryMerge');

  /** Test hook: calls the binding's `panic_for_tests` (always rejects). */
  panicForTests: (message: string) => Promise<never> = stub('panicForTests');
}
