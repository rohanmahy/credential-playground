import type { Engine } from './Engine';
import { TauriEngine } from './TauriEngine';
import { WasmEngine } from './WasmEngine';

/** Whether the app runs inside the Tauri shell. */
export function isTauri(win: object = globalThis): boolean {
  return '__TAURI__' in win;
}

/** TauriEngine inside the desktop app, WasmEngine on the web. */
export async function selectEngine(win: object = globalThis): Promise<Engine> {
  return isTauri(win) ? new TauriEngine() : WasmEngine.load();
}
