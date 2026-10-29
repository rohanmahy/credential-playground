<script lang="ts">
  // Detected type, Detected as…, unwrapping breadcrumb, provenance
  // breadcrumb, validation badge, Read-only / Live edit switch, actions,
  // and the "modified – signature stale" banner.
  import { getAppContext } from '../context';
  import { ACTION_LABELS } from '../logic/actions';
  import { kindLabel } from '../logic/kinds';
  import { provenanceLabel } from '../logic/provenance';
  import { errorMessage } from '../ui';
  import ActionBar from './ActionBar.svelte';
  import DetectedAsMenu from './DetectedAsMenu.svelte';
  import KeyChoiceDialog from './KeyChoiceDialog.svelte';

  let { tabId }: { tabId: string } = $props();

  const { workspace, keys } = getAppContext();
  const tab = $derived(workspace.tab(tabId));
  const crumbs = $derived(
    tab ? (tab.candidates[tab.candidateIndex]?.breadcrumb ?? [kindLabel(tab.doc.kind)]) : [],
  );
  const lineage = $derived(tab ? workspace.breadcrumb(tabId) : []);
  const root = $derived(lineage[0] ? workspace.tab(lineage[0].tabId) : undefined);
  const badge = $derived(
    !tab ? '' : tab.tampered ? 'tampered' : tab.report ? tab.report.overall : 'Not validated',
  );
  const privateKeys = $derived(keys.cards.filter((c) => c.info.private));

  let choosing = $state(false);
  let error = $state<string | null>(null);

  async function resign(keyId: string) {
    choosing = false;
    error = null;
    try {
      await workspace.runAction(tabId, { action: 'resign', keyId });
    } catch (e) {
      error = errorMessage(e);
    }
  }

  function startResign() {
    const only = privateKeys.length === 1 ? privateKeys[0] : undefined;
    if (only) void resign(only.id);
    else if (privateKeys.length === 0) error = 'Re-sign needs a private key in the key panel.';
    else choosing = true;
  }

  const title = (id: string) => workspace.tab(id)?.title ?? 'a closed tab';
</script>

{#if tab}
  <header class="tab-header">
    <div class="row">
      <strong class="kind" data-testid="detected-type">{kindLabel(tab.doc.kind)}</strong>
      <DetectedAsMenu {tabId} />
      <nav aria-label="Unwrapping layers" class="crumbs">
        <ol>
          {#each crumbs as c, i (i)}<li>{c}</li>{/each}
        </ol>
      </nav>
      <span
        class="badge"
        data-testid="validation-badge"
        data-status={tab.tampered ? 'tampered' : (tab.report?.overall ?? 'none')}>{badge}</span
      >
      <button
        type="button"
        class="switch"
        role="switch"
        aria-checked={tab.liveEdit}
        aria-label="Live edit"
        onclick={() => workspace.setLiveEdit(tabId, !tab.liveEdit)}
      >
        <span class:on={!tab.liveEdit}>Read-only</span><span class:on={tab.liveEdit}>Live edit</span
        >
      </button>
    </div>
    <nav aria-label="Provenance" class="provenance">
      {#if tab.provenance.type === 'derived'}
        {#if lineage.length > 1 && root}
          <span class="muted">{provenanceLabel(root.provenance, title)} ·</span>
          {#each lineage as c, i (c.tabId)}
            {#if i < lineage.length - 1}
              <button type="button" class="link" onclick={() => workspace.activate(c.tabId)}
                >{c.title}</button
              >
              <span aria-hidden="true">›</span>
              {@const next = lineage[i + 1]}
              {#if next?.action}<span>{ACTION_LABELS[next.action]}</span>{/if}
              {#if i < lineage.length - 2}<span aria-hidden="true">›</span>{/if}
            {/if}
          {/each}
        {:else}
          <span>{provenanceLabel(tab.provenance, title)}</span>
        {/if}
      {:else}
        <span>{provenanceLabel(tab.provenance, title)}</span>
      {/if}
    </nav>
    <ActionBar {tabId} />
    {#if tab.stale && !tab.tampered}
      <div class="stale" role="status">
        <span>modified – signature stale</span>
        <button type="button" onclick={startResign}>Re-sign</button>
        <button type="button" onclick={() => workspace.keepOriginalSignature(tabId)}
          >Keep original signature</button
        >
      </div>
    {/if}
    {#if error}<p class="error" role="alert">{error}</p>{/if}
  </header>
  {#if choosing}
    <KeyChoiceDialog
      title="Re-sign"
      cards={privateKeys}
      onChoose={(id) => void resign(id)}
      onClose={() => (choosing = false)}
    />
  {/if}
{/if}

<style>
  .tab-header {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--border);
  }
  .row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.6rem;
  }
  .kind {
    font-size: 1.05rem;
  }
  .crumbs ol {
    display: flex;
    flex-wrap: wrap;
    list-style: none;
    margin: 0;
    padding: 0;
    color: var(--muted);
    font-size: 0.85rem;
  }
  .crumbs li + li::before {
    content: '›';
    padding: 0 0.35em;
  }
  .badge {
    font-size: 0.8rem;
    padding: 0.1rem 0.5rem;
    border-radius: 999px;
    border: 1px solid var(--border);
  }
  .badge[data-status='pass'] {
    color: var(--pass);
    border-color: currentColor;
  }
  .badge[data-status='fail'],
  .badge[data-status='tampered'] {
    color: var(--fail);
    border-color: currentColor;
  }
  .badge[data-status='warn'] {
    color: var(--warn);
    border-color: currentColor;
  }
  .switch {
    margin-left: auto;
    display: inline-flex;
    padding: 0;
    overflow: hidden;
  }
  .switch span {
    padding: 0.2rem 0.5rem;
  }
  .switch span.on {
    background: var(--accent);
    color: white;
  }
  .provenance {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.3rem;
    font-size: 0.85rem;
  }
  .stale {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.3rem 0.5rem;
    border-radius: 4px;
    background: var(--warn-bg);
  }
  .error {
    color: var(--fail);
    margin: 0;
  }
</style>
