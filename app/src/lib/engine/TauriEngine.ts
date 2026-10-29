// The desktop Engine: calls the Tauri commands `engine_<snake_name>` with
// the DTO as the argument (`invoke` from @tauri-apps/api/core). The commands
// live in app/src-tauri, which does not exist yet; EngineError rejections
// must be wrapped in EngineFailure.
import type { Engine } from './Engine';
import { NotImplemented } from '../notImplemented';

const stub = (name: string) => () => Promise.reject(new NotImplemented(`TauriEngine.${name}`));

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
