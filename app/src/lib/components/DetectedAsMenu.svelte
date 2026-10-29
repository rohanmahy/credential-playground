<script lang="ts">
  // "Detected as…" menu of the tab's candidates (menuitemradio). On a
  // draft (#43) it sets the type instead: Auto-detect, then the format's
  // draft types, the detected one marked.
  import type { Kind } from '../engine/types';
  import { getAppContext } from '../context';
  import { DRAFT_KINDS } from '../logic/drafts';
  import { kindLabel } from '../logic/kinds';
  import type { MenuItem } from '../ui';
  import { errorMessage } from '../ui';
  import Menu from './Menu.svelte';

  let { tabId }: { tabId: string } = $props();

  const { workspace } = getAppContext();
  const tab = $derived(workspace.tab(tabId));
  let open = $state(false);
  let error = $state<string | null>(null);

  function label(i: number): string {
    const c = tab?.candidates[i];
    if (!c) return '';
    const via = c.breadcrumb.slice(0, -1).join(' › ');
    return `${kindLabel(c.kind)}${via ? ` (${via})` : ''} · ${c.confidence}%`;
  }

  function setKind(kind: Kind | null) {
    error = null;
    workspace.setDraftKind(tabId, kind).catch((e: unknown) => (error = errorMessage(e)));
  }

  function draftItems(): MenuItem[] {
    const draft = tab?.draft;
    if (!draft) return [];
    return [
      {
        label: 'Auto-detect',
        role: 'menuitemradio',
        checked: draft.override === null,
        action: () => setKind(null),
      },
      ...DRAFT_KINDS[draft.format].map((k) => ({
        label: `${kindLabel(k)}${draft.detected?.type === k.type ? ' (detected)' : ''}`,
        role: 'menuitemradio' as const,
        checked: draft.override?.type === k.type,
        action: () => setKind(k),
      })),
    ];
  }
</script>

{#if tab?.draft}
  <span class="detected-as">
    <button type="button" aria-haspopup="menu" aria-expanded={open} onclick={() => (open = !open)}
      >Detected as…</button
    >
    {#if open}
      <Menu label="Draft type" items={draftItems()} onClose={() => (open = false)} />
    {/if}
    {#if error}<span class="error" role="alert">{error}</span>{/if}
  </span>
{:else if tab && tab.candidates.length > 0}
  <span class="detected-as">
    <button
      type="button"
      aria-haspopup="menu"
      aria-expanded={open}
      disabled={!tab.input || tab.candidates.length < 2}
      title={tab.candidates.length < 2 ? 'Only one interpretation was found' : undefined}
      onclick={() => (open = !open)}>Detected as…</button
    >
    {#if open}
      <Menu
        label="Detected as"
        items={tab.candidates.map((_, i) => ({
          label: label(i),
          role: 'menuitemradio' as const,
          checked: i === tab.candidateIndex,
          action: () => {
            error = null;
            workspace.chooseCandidate(tabId, i).catch((e: unknown) => (error = errorMessage(e)));
          },
        }))}
        onClose={() => (open = false)}
      />
    {/if}
    {#if error}<span class="error" role="alert">{error}</span>{/if}
  </span>
{/if}

<style>
  .detected-as {
    position: relative;
  }
</style>
