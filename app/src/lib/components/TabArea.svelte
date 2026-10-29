<script lang="ts">
  // Credential tabs (role=tablist) with an optional side-by-side split.
  import { tick } from 'svelte';
  import { getAppContext } from '../context';
  import CredentialTab from './CredentialTab.svelte';
  import { DRAFT_FORMATS, type DraftFormat } from '../logic/drafts';
  import { errorMessage } from '../ui';

  const { workspace } = getAppContext();

  let draftError = $state<string | null>(null);

  async function startDraft(format: DraftFormat) {
    draftError = null;
    try {
      await workspace.newDraft(format);
    } catch (e) {
      draftError = errorMessage(e);
    }
  }

  const shown = $derived.by(() => {
    const split = workspace.split;
    if (split && split.every((id) => workspace.tab(id))) return split;
    return workspace.activeId && workspace.tab(workspace.activeId) ? [workspace.activeId] : [];
  });

  let list: HTMLDivElement | undefined = $state();

  async function focusTab(id: string) {
    workspace.activate(id);
    await tick();
    list?.querySelector<HTMLElement>(`#${CSS.escape(`tab-${id}`)}`)?.focus();
  }

  function onkeydown(e: KeyboardEvent) {
    const tabs = workspace.tabs;
    const at = tabs.findIndex((t) => t.id === workspace.activeId);
    let next: number;
    switch (e.key) {
      case 'ArrowRight':
        next = (at + 1) % tabs.length;
        break;
      case 'ArrowLeft':
        next = (at - 1 + tabs.length) % tabs.length;
        break;
      case 'Home':
        next = 0;
        break;
      case 'End':
        next = tabs.length - 1;
        break;
      case 'Delete': {
        const id = workspace.activeId;
        if (id) workspace.close(id);
        e.preventDefault();
        return;
      }
      default:
        return;
    }
    e.preventDefault();
    const target = tabs[next];
    if (target) void focusTab(target.id);
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
</script>

<section class="tabs" aria-label="Credentials area">
  {#if workspace.tabs.length > 0}
    <div class="bar">
      <div
        bind:this={list}
        class="tablist"
        role="tablist"
        aria-label="Credentials"
        tabindex="-1"
        {onkeydown}
      >
        {#each workspace.tabs as t (t.id)}
          {@const active = t.id === workspace.activeId}
          <div class="tab-wrap" role="presentation" class:active>
            <button
              type="button"
              role="tab"
              id={`tab-${t.id}`}
              aria-selected={active}
              aria-controls={`panel-${t.id}`}
              tabindex={active ? 0 : -1}
              onclick={() => workspace.activate(t.id)}>{t.title}</button
            >
            <button
              type="button"
              class="close icon"
              tabindex="-1"
              aria-label={`Close ${t.title}`}
              title="Close (Delete)"
              onclick={() => workspace.close(t.id)}>×</button
            >
          </div>
        {/each}
      </div>
      {@render draftButtons()}
      <button
        type="button"
        aria-pressed={workspace.split !== null}
        disabled={workspace.tabs.length < 2}
        onclick={toggleSplit}>Split view</button
      >
    </div>
    <div class="panels" class:split={shown.length > 1}>
      {#each shown as id (id)}
        <div class="panel" role="tabpanel" id={`panel-${id}`} aria-labelledby={`tab-${id}`}>
          <CredentialTab tabId={id} />
        </div>
      {/each}
    </div>
  {:else}
    <div class="empty">
      <p>Paste, drop, or open a credential (JWT, SD-JWT, CWT, SD-CWT) or a key.</p>
      <p>Or start writing one in Live edit: {@render draftButtons()}</p>
      <p class="muted">Everything stays in this page's memory. Nothing is uploaded or stored.</p>
    </div>
  {/if}
  {#if draftError}<p class="error">{draftError}</p>{/if}
</section>

<!-- Shown once: in the empty state, or in the tab bar once there are tabs. -->
{#snippet draftButtons()}
  <span class="drafts">
    {#each DRAFT_FORMATS as f (f.format)}
      <button type="button" onclick={() => void startDraft(f.format)}>New {f.label} draft</button>
    {/each}
  </span>
{/snippet}

<style>
  .tabs {
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
  }
  .bar {
    display: flex;
    align-items: end;
    gap: 0.5rem;
    border-bottom: 1px solid var(--border);
    padding: 0.25rem 0.5rem 0;
  }
  .tablist {
    display: flex;
    gap: 0.15rem;
    overflow-x: auto;
    flex: 1;
  }
  .tab-wrap {
    display: flex;
    align-items: center;
    border: 1px solid var(--border);
    border-bottom: 0;
    border-radius: 6px 6px 0 0;
  }
  .tab-wrap.active {
    background: var(--hover);
    border-color: var(--accent);
  }
  [role='tab'] {
    border: 0;
    background: none;
    white-space: nowrap;
  }
  .bar > button {
    margin-bottom: 0.25rem;
  }
  .panels {
    flex: 1;
    display: grid;
    min-height: 0;
  }
  .panels.split {
    grid-template-columns: 1fr 1fr;
  }
  .panel {
    min-width: 0;
    min-height: 0;
    overflow: auto;
  }
  .panels.split .panel + .panel {
    border-left: 2px solid var(--border);
  }
  .drafts {
    display: inline-flex;
    gap: 0.25rem;
  }
  .bar .drafts {
    margin-bottom: 0.25rem;
  }
  .empty {
    padding: 2rem;
  }
</style>
