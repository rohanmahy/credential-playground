import type { Platform } from './Platform';
import { TauriPlatform } from './TauriPlatform';
import { WebPlatform } from './WebPlatform';
import { isTauri } from '../engine/select';

export function selectPlatform(win: object = globalThis): Platform {
  return isTauri(win) ? new TauriPlatform() : new WebPlatform();
}
