<script lang="ts">
  // An empty tab's bar (SPEC §4.1): the Type picker (applies when the user
  // types), and Open file… / From clipboard, which fill the tab and run
  // token detection. Pasting or dropping into the text below does the same.
  import { getAppContext } from '../context';
  import { TAB_TYPES } from '../logic/drafts';
  import { errorMessage } from '../ui';

  let { tabId }: { tabId: string } = $props();

  const { workspace } = getAppContext();
  const tab = $derived(workspace.tab(tabId));
  const type = $derived(tab ? workspace.tabType(tab) : TAB_TYPES[0]);

  let busy = $state(false);
  let error = $state<string | null>(null);

  async function open(task: () => Promise<unknown>) {
    busy = true;
    error = null;
    try {
      await task();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }
</script>

{#if tab}
  <header class="empty-bar">
    <div class="row">
      <label class="inline">
        <span>Type</span>
        <select
          value={type?.id}
          onchange={(e) => workspace.setTabType(tabId, e.currentTarget.value)}
        >
          {#each TAB_TYPES as t (t.id)}<option value={t.id}>{t.label}</option>{/each}
        </select>
      </label>
      <button
        type="button"
        disabled={busy}
        onclick={() => open(() => workspace.openFromFile(tabId))}>Open file…</button
      >
      <button
        type="button"
        disabled={busy}
        onclick={() => open(() => workspace.openFromClipboard(tabId))}>From clipboard</button
      >
    </div>
    <p class="muted hint">
      Paste or drop a JWT, SD-JWT, CWT, or SD-CWT (base64url, base64, hex) to detect it, or type a
      claim set as the Type above. Everything stays in this page's memory.
    </p>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
  </header>
{/if}

<style>
  .empty-bar {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--border);
  }
  .row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.6rem;
  }
  .hint {
    margin: 0;
    font-size: 0.85rem;
  }
  .error {
    color: var(--fail);
    margin: 0;
  }
</style>
