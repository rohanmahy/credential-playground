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
import type { TokenatorEngine } from 'tokenator-wasm';
import { type Engine, EngineFailure } from './Engine';
import type { EngineError, ErrorCode } from './types';

export interface WasmEngineOptions {
  /** The .wasm to instantiate instead of fetching the bundled asset
   *  (Node tests pass the file's bytes). */
  wasm?: BufferSource | WebAssembly.Module;
}

type Envelope<T> = { ok: T } | { err: EngineError };

/** Failures outside the engine (load, trap) have no core code yet (#38). */
function internal(message: string): EngineFailure {
  return new EngineFailure({ code: 'internal' as ErrorCode, message, node_id: null });
}

/** A thrown value as an EngineFailure: the constructor throws the `err`
 *  envelope text; a panic is a wasm trap (RuntimeError). */
function toFailure(x: unknown): EngineFailure {
  if (x instanceof EngineFailure) return x;
  if (typeof x === 'string') {
    try {
      const env = JSON.parse(x) as { err?: EngineError };
      if (env.err) return new EngineFailure(env.err);
    } catch {
      // not an envelope: fall through
    }
    return internal(x);
  }
  if (x instanceof WebAssembly.RuntimeError) {
    return internal(`the engine panicked (wasm trap: ${x.message})`);
  }
  return internal(`tokenator-wasm: ${x instanceof Error ? x.message : String(x)}`);
}

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
  private engine: Promise<TokenatorEngine> | null = null;

  private constructor(snapshot: Uint8Array | null, options: WasmEngineOptions) {
    this.snapshot = snapshot;
    this.options = options;
  }

  /** Imports and instantiates the module once; a failure sticks. */
  private instance(): Promise<TokenatorEngine> {
    this.engine ??= (async () => {
      try {
        const mod = await import('tokenator-wasm');
        await mod.default({ module_or_path: this.options.wasm });
        return new mod.TokenatorEngine(this.snapshot);
      } catch (x) {
        throw toFailure(x);
      }
    })();
    return this.engine;
  }

  private async call<T>(binding: (engine: TokenatorEngine) => string): Promise<T> {
    const engine = await this.instance();
    let out: string;
    try {
      out = binding(engine);
    } catch (x) {
      throw toFailure(x);
    }
    const env = JSON.parse(out) as Envelope<T>;
    if ('err' in env) throw new EngineFailure(env.err);
    return env.ok;
  }

  info: Engine['info'] = () => this.call((e) => e.info());
  detect: Engine['detect'] = (input) => this.call((e) => e.detect(input));
  open: Engine['open'] = (input, candidate, view) =>
    this.call((e) => e.open(input, JSON.stringify(candidate), JSON.stringify(view)));
  render: Engine['render'] = (req) => this.call((e) => e.render(JSON.stringify(req)));
  parseEdit: Engine['parseEdit'] = (req) => this.call((e) => e.parse_edit(JSON.stringify(req)));
  convertClaims: Engine['convertClaims'] = (req) =>
    this.call((e) => e.convert_claims(JSON.stringify(req)));
  issue: Engine['issue'] = (req) => this.call((e) => e.issue(JSON.stringify(req)));
  redact: Engine['redact'] = (req) => this.call((e) => e.redact(JSON.stringify(req)));
  disclose: Engine['disclose'] = (req) => this.call((e) => e.disclose(JSON.stringify(req)));
  present: Engine['present'] = (req) => this.call((e) => e.present(JSON.stringify(req)));
  validate: Engine['validate'] = (req) => this.call((e) => e.validate(JSON.stringify(req)));
  lint: Engine['lint'] = (req) => this.call((e) => e.lint(JSON.stringify(req)));
  resign: Engine['resign'] = (req) => this.call((e) => e.resign(JSON.stringify(req)));
  tamper: Engine['tamper'] = (req) => this.call((e) => e.tamper(JSON.stringify(req)));
  reencode: Engine['reencode'] = (req) => this.call((e) => e.reencode(JSON.stringify(req)));
  editDisclosures: Engine['editDisclosures'] = (req) =>
    this.call((e) => e.edit_disclosures(JSON.stringify(req)));
  decodeEmbedded: Engine['decodeEmbedded'] = (req) =>
    this.call((e) => e.decode_embedded(JSON.stringify(req)));
  keyImport: Engine['keyImport'] = (req) => this.call((e) => e.key_import(JSON.stringify(req)));
  keyExport: Engine['keyExport'] = (req) => this.call((e) => e.key_export(JSON.stringify(req)));
  keyPublic: Engine['keyPublic'] = (key) => this.call((e) => e.key_public(JSON.stringify(key)));
  keyGenerate: Engine['keyGenerate'] = (req) =>
    this.call((e) => e.key_generate(JSON.stringify(req)));
  keyThumbprint: Engine['keyThumbprint'] = (req) =>
    this.call((e) => e.key_thumbprint(JSON.stringify(req)));
  keyAssignKid: Engine['keyAssignKid'] = (req) =>
    this.call((e) => e.key_assign_kid(JSON.stringify(req)));
  keyToJwk: Engine['keyToJwk'] = (req) => this.call((e) => e.key_to_jwk(JSON.stringify(req)));
  keyToCwk: Engine['keyToCwk'] = (req) => this.call((e) => e.key_to_cwk(JSON.stringify(req)));
  datetime: Engine['datetime'] = (req) => this.call((e) => e.datetime(JSON.stringify(req)));
  registryLookup: Engine['registryLookup'] = (query) =>
    this.call((e) => e.registry_lookup(JSON.stringify(query)));
  registryMerge: Engine['registryMerge'] = (req) =>
    this.call((e) => e.registry_merge(JSON.stringify(req)));

  /** Test hook: calls the binding's `panic_for_tests` (always rejects). */
  panicForTests = (message: string): Promise<never> =>
    this.call((e) => {
      e.panic_for_tests(message);
      throw internal('panic_for_tests returned');
    });
}
