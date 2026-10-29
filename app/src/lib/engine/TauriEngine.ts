// The desktop Engine: calls the Tauri commands `engine_<snake_name>` in
// app/src-tauri (`invoke` from @tauri-apps/api/core) with the core parameter
// names as argument keys (`{ req }`, `{ input, candidate, view }`, `{ key }`,
// `{ query }`); raw input crosses as base64url. Before the first call it
// invokes `engine_init { snapshot }` once. Every rejection becomes an
// EngineFailure (a Tauri string error: code `invalid_input`). Contract:
// app/src-tauri/TEST-PLAN.md.
import { invoke } from '@tauri-apps/api/core';
import { type Engine, EngineFailure } from './Engine';
import { toB64u } from './bytes';
import type { EngineError } from './types';

function isEngineError(x: unknown): x is EngineError {
  return (
    typeof x === 'object' &&
    x !== null &&
    typeof (x as EngineError).code === 'string' &&
    typeof (x as EngineError).message === 'string'
  );
}

/** A core EngineError as is; anything else (Tauri's string errors for bad
 *  arguments or unknown commands, IPC failures) as `invalid_input`. */
function toFailure(x: unknown): EngineFailure {
  if (isEngineError(x)) return new EngineFailure(x);
  const message = x instanceof Error ? x.message : String(x);
  return new EngineFailure({ code: 'invalid_input', message, node_id: null });
}

async function call<T>(cmd: string, args: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (x) {
    throw toFailure(x);
  }
}

export class TauriEngine implements Engine {
  /** Sent once to the shell so its Engine uses the cached registry snapshot. */
  readonly snapshot: Uint8Array | null;
  private ready: Promise<void> | null = null;

  constructor(snapshot: Uint8Array | null = null) {
    this.snapshot = snapshot;
  }

  /** `engine_init` once, before the first call; a failure sticks. */
  private init(): Promise<void> {
    this.ready ??= call<null>('engine_init', {
      snapshot: this.snapshot === null ? null : toB64u(this.snapshot),
    }).then(() => undefined);
    return this.ready;
  }

  private async run<T>(cmd: string, args: Record<string, unknown> = {}): Promise<T> {
    await this.init();
    return call<T>(cmd, args);
  }

  info: Engine['info'] = () => this.run('engine_info');
  detect: Engine['detect'] = (input) => this.run('engine_detect', { input: toB64u(input) });
  open: Engine['open'] = (input, candidate, view) =>
    this.run('engine_open', { input: toB64u(input), candidate, view });
  render: Engine['render'] = (req) => this.run('engine_render', { req });
  parseEdit: Engine['parseEdit'] = (req) => this.run('engine_parse_edit', { req });
  convertClaims: Engine['convertClaims'] = (req) => this.run('engine_convert_claims', { req });
  issue: Engine['issue'] = (req) => this.run('engine_issue', { req });
  redact: Engine['redact'] = (req) => this.run('engine_redact', { req });
  disclose: Engine['disclose'] = (req) => this.run('engine_disclose', { req });
  present: Engine['present'] = (req) => this.run('engine_present', { req });
  validate: Engine['validate'] = (req) => this.run('engine_validate', { req });
  lint: Engine['lint'] = (req) => this.run('engine_lint', { req });
  resign: Engine['resign'] = (req) => this.run('engine_resign', { req });
  tamper: Engine['tamper'] = (req) => this.run('engine_tamper', { req });
  reencode: Engine['reencode'] = (req) => this.run('engine_reencode', { req });
  editDisclosures: Engine['editDisclosures'] = (req) =>
    this.run('engine_edit_disclosures', { req });
  decodeEmbedded: Engine['decodeEmbedded'] = (req) => this.run('engine_decode_embedded', { req });
  keyImport: Engine['keyImport'] = (req) => this.run('engine_key_import', { req });
  keyExport: Engine['keyExport'] = (req) => this.run('engine_key_export', { req });
  keyPublic: Engine['keyPublic'] = (key) => this.run('engine_key_public', { key });
  keyGenerate: Engine['keyGenerate'] = (req) => this.run('engine_key_generate', { req });
  keyThumbprint: Engine['keyThumbprint'] = (req) => this.run('engine_key_thumbprint', { req });
  keyAssignKid: Engine['keyAssignKid'] = (req) => this.run('engine_key_assign_kid', { req });
  keyToJwk: Engine['keyToJwk'] = (req) => this.run('engine_key_to_jwk', { req });
  keyToCwk: Engine['keyToCwk'] = (req) => this.run('engine_key_to_cwk', { req });
  datetime: Engine['datetime'] = (req) => this.run('engine_datetime', { req });
  registryLookup: Engine['registryLookup'] = (query) =>
    this.run('engine_registry_lookup', { query });
  registryMerge: Engine['registryMerge'] = (req) => this.run('engine_registry_merge', { req });
}
