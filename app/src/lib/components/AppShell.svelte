<script lang="ts">
  // Layout: key panel docked left, credential tabs right (SPEC §4), with the
  // input area and tools on top. Drop a file or text anywhere to open it.
  import type { Provenance } from '../model';
  import { getAppContext } from '../context';
  import type { OpenResult } from '../stores/workspace.svelte';
  import type { DraftFormat } from '../logic/drafts';
  import { errorMessage } from '../ui';
  import KeyPanel from './KeyPanel.svelte';
  import TabArea from './TabArea.svelte';
  import AboutBox from './AboutBox.svelte';
  import DateTimeChit from './DateTimeChit.svelte';
  import SettingsDialog from './SettingsDialog.svelte';

  const { workspace, settings } = getAppContext();

  let input = $state('');
  let notice = $state<string | null>(null);
  let busy = $state(false);
  let dialog = $state<'about' | 'settings' | null>(null);
  let dragging = $state(false);

  $effect(() => {
    const root = document.documentElement;
    if (settings.theme === 'system') delete root.dataset['theme'];
    else root.dataset['theme'] = settings.theme;
  });

  function report(result: OpenResult) {
    if (result.type === 'nothing') notice = 'Nothing recognizable was found in the input.';
    else if (result.type === 'keys') {
      notice = `Added ${result.cardIds.length} key${result.cardIds.length === 1 ? '' : 's'} to the key panel.`;
    } else notice = null;
  }

  async function open(task: () => Promise<OpenResult>, clear = false) {
    busy = true;
    notice = null;
    try {
      report(await task());
      if (clear) input = '';
    } catch (e) {
      notice = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  /** New (#43): a draft tab in Live edit. */
  async function startDraft(format: DraftFormat) {
    notice = null;
    try {
      await workspace.newDraft(format);
    } catch (e) {
      notice = errorMessage(e);
    }
  }

  function submit(e: SubmitEvent) {
    e.preventDefault();
    const text = input;
    if (text.trim() === '') return;
    void open(() => workspace.openText(text, { type: 'pasted' }), true);
  }

  async function drop(e: DragEvent) {
    e.preventDefault();
    dragging = false;
    const dt = e.dataTransfer;
    if (!dt) return;
    const file = dt.files[0];
    if (file) {
      const provenance: Provenance = { type: 'dropped', name: file.name };
      const bytes = new Uint8Array(await file.arrayBuffer());
      void open(() => workspace.openInput(bytes, provenance));
      return;
    }
    const text = dt.getData('text/plain');
    if (text.trim()) void open(() => workspace.openText(text, { type: 'dropped', name: null }));
  }
</script>

<!-- Dropping is a shortcut; every input is also reachable from the buttons. -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
  class="app"
  class:dragging
  ondragover={(e) => {
    e.preventDefault();
    dragging = true;
  }}
  ondragleave={(e) => {
    if (e.currentTarget === e.target) dragging = false;
  }}
  ondrop={drop}
>
  <header class="top">
    <h1>The Tokenator</h1>
    <form class="input" onsubmit={submit}>
      <textarea
        rows="2"
        class="mono"
        aria-label="Paste a credential or key"
        placeholder="Paste a JWT, SD-JWT, CWT, SD-CWT (base64url, base64, hex) or a key, then Open"
        bind:value={input}
        onkeydown={(e) => {
          if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
            e.preventDefault();
            e.currentTarget.form?.requestSubmit();
          }
        }}></textarea>
      <div class="buttons">
        <button type="submit" class="primary" disabled={busy}>Open</button>
        <button
          type="button"
          title="Start a JSON draft in Live edit"
          onclick={() => void startDraft('json')}>New</button
        >
        <button
          type="button"
          disabled={busy}
          onclick={() => open(() => workspace.openFromClipboard())}>From clipboard</button
        >
        <button type="button" disabled={busy} onclick={() => open(() => workspace.openFromFile())}
          >Open file…</button
        >
      </div>
    </form>
    <nav class="tools" aria-label="Tools">
      <button type="button" onclick={() => workspace.openChit()}>Date/time</button>
      <button type="button" onclick={() => (dialog = 'settings')}>Settings</button>
      <button type="button" onclick={() => (dialog = 'about')}>About</button>
    </nav>
  </header>
  {#if notice}<p class="notice" aria-live="polite">{notice}</p>{/if}
  <div class="shell">
    <KeyPanel />
    <TabArea />
  </div>
</div>

{#if workspace.chit}
  {#key workspace.chit}
    <DateTimeChit
      tabId={workspace.chit.tabId}
      nodeId={workspace.chit.nodeId}
      onClose={() => workspace.closeChit()}
    />
  {/key}
{/if}
{#if dialog === 'about'}
  <AboutBox onClose={() => (dialog = null)} />
{:else if dialog === 'settings'}
  <SettingsDialog onClose={() => (dialog = null)} />
{/if}

<style>
  .app {
    display: flex;
    flex-direction: column;
    height: 100%;
  }
  .app.dragging {
    outline: 3px dashed var(--accent);
    outline-offset: -6px;
  }
  .top {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--border);
  }
  h1 {
    font-size: 1.1rem;
    margin: 0;
    white-space: nowrap;
  }
  .input {
    flex: 1;
    display: flex;
    gap: 0.5rem;
    align-items: center;
  }
  .input textarea {
    flex: 1;
    resize: vertical;
    min-height: 2.4rem;
  }
  .tools {
    display: flex;
    gap: 0.25rem;
  }
  .notice {
    margin: 0;
    padding: 0.25rem 0.75rem;
    background: var(--hover);
    font-size: 0.85rem;
  }
  .shell {
    flex: 1;
    min-height: 0;
    display: grid;
    grid-template-columns: minmax(16rem, 22rem) minmax(0, 1fr);
  }
</style>
