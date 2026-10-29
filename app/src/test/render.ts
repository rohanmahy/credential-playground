// Test helpers: an app context around the mocks, seeded tabs and keys.
import { render } from '@testing-library/svelte';
import type { Component } from 'svelte';
import { SvelteSet } from 'svelte/reactivity';
import { APP_CONTEXT_KEY, createAppContext, type AppContext } from '../lib/context';
import type { Candidate, Document } from '../lib/engine/types';
import type { KeyCard } from '../lib/model';
import type { Tab, Workspace } from '../lib/stores/workspace.svelte';
import { MockEngine } from './MockEngine';
import { MockPlatform } from './MockPlatform';
import { jwtCandidates } from './fixtures';

export interface TestApp extends AppContext {
  engine: MockEngine;
  platform: MockPlatform;
}

export function setupApp(): TestApp {
  const engine = new MockEngine();
  const platform = new MockPlatform();
  return createAppContext(engine, platform) as TestApp;
}

let tabCounter = 0;

/** Pushes a tab straight into the workspace (bypassing openInput) and
 *  activates it. Returns the tab as stored (reactive). */
export function seedTab(ws: Workspace, doc: Document, overrides: Partial<Tab> = {}): Tab {
  tabCounter += 1;
  const number = ws.tabs.length + 1;
  const tab: Tab = {
    id: `seed-${tabCounter}`,
    number,
    title: `Tab ${number}`,
    doc,
    input: null,
    candidates: overrides.candidates ?? (jwtCandidates satisfies Candidate[]),
    candidateIndex: 0,
    provenance: { type: 'pasted' },
    collapsed: new SvelteSet(),
    selected: null,
    liveEdit: false,
    editText: doc.main.text,
    editDiagnostics: [],
    stale: false,
    tampered: false,
    sdMarks: new SvelteSet(),
    report: null,
    ...overrides,
  };
  ws.tabs.push(tab);
  ws.activeId = tab.id;
  const stored = ws.tabs[ws.tabs.length - 1];
  if (!stored) throw new Error('seedTab');
  return stored;
}

export function seedKeys(app: AppContext, ...cards: KeyCard[]): void {
  app.keys.cards.push(...structuredClone(cards));
}

export function renderWithApp<P extends Record<string, unknown>>(
  component: Component<P>,
  props: P,
  app: TestApp = setupApp(),
) {
  // The generic props of render() do not narrow well; the call is checked
  // by the component's own prop types at each call site.
  const options = { props, context: new Map<unknown, unknown>([[APP_CONTEXT_KEY, app]]) };
  const result = render(component, options as never);
  return { ...result, app };
}
