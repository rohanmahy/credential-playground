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
  import Dialog from './Dialog.svelte';
  import {
    DRAFT_FORMATS,
    isDraftKeyKind,
    openableAs,
    type DiscardReason,
    type DraftFormat,
  } from '../logic/drafts';

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

  // --- drafts (#43) ---------------------------------------------------
  const draftKind = $derived(tab ? workspace.draftKind(tab) : null);
  const openAs = $derived(tab?.draft ? openableAs(tab.draft.detected) : null);
  let asking = $state<{ reason: DiscardReason; resolve: (ok: boolean) => void } | null>(null);

  async function switchFormat(select: HTMLSelectElement) {
    error = null;
    const format = select.value as DraftFormat;
    try {
      const changed = await workspace.setDraftFormat(tabId, format, (reason) => {
        // Point at the node the engine named (selected in the editor).
        if (reason.nodeId !== null) workspace.select(tabId, reason.nodeId);
        return new Promise<boolean>((resolve) => (asking = { reason, resolve }));
      });
      // Declined: put the select back on the draft's format.
      if (!changed && tab?.draft) select.value = tab.draft.format;
    } catch (e) {
      error = errorMessage(e);
      if (tab?.draft) select.value = tab.draft.format;
    }
  }

  function answer(ok: boolean) {
    asking?.resolve(ok);
    asking = null;
  }

  async function draftAction(task: () => Promise<unknown>) {
    error = null;
    try {
      await task();
    } catch (e) {
      error = errorMessage(e);
    }
  }

  const title = (id: string) => workspace.tab(id)?.title ?? 'a closed tab';
</script>

{#if tab}
  <header class="tab-header">
    <div class="row">
      <strong class="kind" data-testid="detected-type"
        >{kindLabel(draftKind ?? tab.doc.kind)}</strong
      >
      <DetectedAsMenu {tabId} />
      {#if tab.draft}
        <label class="inline">
          <span>Format</span>
          <select value={tab.draft.format} onchange={(e) => void switchFormat(e.currentTarget)}>
            {#each DRAFT_FORMATS as f (f.format)}<option value={f.format}>{f.label}</option>{/each}
          </select>
        </label>
        {#if draftKind && isDraftKeyKind(draftKind)}
          <button type="button" onclick={() => draftAction(() => workspace.importDraftKey(tabId))}
            >Add to key panel</button
          >
        {/if}
        {#if openAs}
          <button type="button" onclick={() => draftAction(() => workspace.openDraftAs(tabId))}
            >Open as {kindLabel(openAs)}</button
          >
        {/if}
      {/if}
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
  {#if asking}
    {@const a = asking}
    <Dialog title="Discard the draft?" role="alertdialog" onClose={() => answer(false)}>
      <p>
        {a.reason.message}{#if a.reason.nodeId !== null}
          (at <code>{a.reason.nodeId || '(root)'}</code>){/if}
      </p>
      <p>Switching the Format starts over from an empty draft.</p>
      <div class="buttons">
        <button type="button" class="primary" onclick={() => answer(true)}
          >Discard and switch</button
        >
        <button type="button" onclick={() => answer(false)}>Cancel</button>
      </div>
    </Dialog>
  {/if}
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
