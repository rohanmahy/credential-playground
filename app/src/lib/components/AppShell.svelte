<script lang="ts">
  // Layout (SPEC §4): a slim header with the tools, the Issuer and Holder
  // key areas docked left, credential tabs right. There's no global input:
  // input goes into a tab or a key area, and drops anywhere else are
  // ignored. On the desktop the native menu bar drives the same actions.
  import { getAppContext } from '../context';
  import { errorMessage } from '../ui';
  import KeyPanel from './KeyPanel.svelte';
  import TabArea from './TabArea.svelte';
  import AboutBox from './AboutBox.svelte';
  import DateTimeChit from './DateTimeChit.svelte';
  import SettingsDialog from './SettingsDialog.svelte';

  const { workspace, settings, platform } = getAppContext();

  let notice = $state<string | null>(null);
  let dialog = $state<'about' | 'settings' | null>(null);

  $effect(() => {
    const root = document.documentElement;
    if (settings.theme === 'system') delete root.dataset['theme'];
    else root.dataset['theme'] = settings.theme;
  });

  async function guard(task: () => Promise<unknown>) {
    notice = null;
    try {
      await task();
    } catch (e) {
      notice = errorMessage(e);
    }
  }

  function toggleSplit() {
    if (workspace.split) {
      workspace.unsplit();
      return;
    }
    const tabs = workspace.tabs;
    const at = tabs.findIndex((t) => t.id === workspace.activeId);
    const left = tabs[at];
    const right = tabs[at + 1] ?? tabs[at - 1];
    if (left && right) workspace.splitWith(left.id, right.id);
  }

  /** Desktop menu items (app/src-tauri/src/menu.rs), by id. */
  function onMenu(id: string) {
    switch (id) {
      case 'new_tab':
        workspace.newTab();
        break;
      case 'open_file':
        void guard(() => workspace.openFromFile());
        break;
      case 'from_clipboard':
        void guard(() => workspace.openFromClipboard());
        break;
      case 'close_tab':
        if (workspace.activeId) workspace.close(workspace.activeId);
        break;
      case 'split_view':
        toggleSplit();
        break;
      case 'raw_pane':
        settings.showRaw = !settings.showRaw;
        break;
      case 'datetime':
        workspace.openChit();
        break;
      case 'settings':
        dialog = 'settings';
        break;
      case 'about':
        dialog = 'about';
        break;
    }
  }

  $effect(() => platform.onMenu?.(onMenu));

  // Drops outside an empty text area are ignored; without this the browser
  // (or webview) would navigate to a dropped file.
  function ignoreDragOver(e: DragEvent) {
    if (e.defaultPrevented) return;
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = 'none';
  }
</script>

<svelte:window
  ondragover={ignoreDragOver}
  ondrop={(e) => {
    if (!e.defaultPrevented) e.preventDefault();
  }}
/>

<div class="app">
  <header class="top">
    <h1>The Tokenator</h1>
    <nav class="tools" aria-label="Tools">
      <button type="button" onclick={() => workspace.openChit()}>Date/time</button>
      <button type="button" onclick={() => (dialog = 'settings')}>Settings</button>
      <button type="button" onclick={() => (dialog = 'about')}>About</button>
    </nav>
  </header>
  {#if notice}<p class="notice" role="alert">{notice}</p>{/if}
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
  .top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding: 0.3rem 0.75rem;
    border-bottom: 1px solid var(--border);
  }
  h1 {
    font-size: 1.05rem;
    margin: 0;
    white-space: nowrap;
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
    grid-template-columns: minmax(18rem, 24rem) minmax(0, 1fr);
  }
</style>
