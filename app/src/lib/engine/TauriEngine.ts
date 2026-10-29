// The desktop Engine: calls the Tauri commands `engine_<snake_name>` in
// app/src-tauri (`invoke` from @tauri-apps/api/core) with the core parameter
// names as argument keys (`{ req }`, `{ input, candidate, view }`, `{ key }`,
// `{ query }`); raw input crosses as base64url. Before the first call it
// invokes `engine_init { snapshot }` once. Every rejection becomes an
// EngineFailure (a Tauri string error: code `invalid_input`). Contract:
// app/src-tauri/TEST-PLAN.md.
import type { Engine } from './Engine';
import { NotImplemented } from '../notImplemented';

const stub =
  (name: string) =>
  (..._args: unknown[]) =>
    Promise.reject(new NotImplemented(`TauriEngine.${name}`));

export class TauriEngine implements Engine {
  /** Sent once to the shell so its Engine uses the cached registry snapshot. */
  readonly snapshot: Uint8Array | null;

  constructor(snapshot: Uint8Array | null = null) {
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
