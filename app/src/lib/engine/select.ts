import type { Engine } from './Engine';
import { TauriEngine } from './TauriEngine';
import { WasmEngine } from './WasmEngine';

/** Whether the app runs inside the Tauri shell. */
export function isTauri(win: object = globalThis): boolean {
  return '__TAURI__' in win;
}

/** TauriEngine inside the desktop app, WasmEngine on the web. `snapshot`
 *  is a cached registry snapshot (from `registry_merge`) to use instead of
 *  the bundled one. */
export async function selectEngine(
  win: object = globalThis,
  snapshot: Uint8Array | null = null,
): Promise<Engine> {
  return isTauri(win) ? new TauriEngine(snapshot) : WasmEngine.load(snapshot);
}
