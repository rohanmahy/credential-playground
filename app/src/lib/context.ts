// Stores and seams are handed down through Svelte context, so tests can
// mount components around fresh instances and mocks.
import { getContext, setContext } from 'svelte';
import type { Engine } from './engine/Engine';
import type { Platform } from './platform/Platform';
import { KeyStore } from './stores/keys.svelte';
import { Settings } from './stores/settings.svelte';
import { Workspace } from './stores/workspace.svelte';

export interface AppContext {
  engine: Engine;
  platform: Platform;
  settings: Settings;
  keys: KeyStore;
  workspace: Workspace;
}

export const APP_CONTEXT_KEY = Symbol('tokenator');

export function createAppContext(engine: Engine, platform: Platform): AppContext {
  const settings = new Settings(platform);
  const keys = new KeyStore(engine, platform);
  const workspace = new Workspace({ engine, platform, settings, keys });
  return { engine, platform, settings, keys, workspace };
}

export function setAppContext(ctx: AppContext): void {
  setContext(APP_CONTEXT_KEY, ctx);
}

export function getAppContext(): AppContext {
  const ctx = getContext<AppContext | undefined>(APP_CONTEXT_KEY);
  if (!ctx) throw new Error('AppContext missing');
  return ctx;
}
