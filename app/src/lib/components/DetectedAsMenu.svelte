<script lang="ts">
  // "Detected as…" menu of the tab's candidates (menuitemradio).
  import { getAppContext } from '../context';
  import { kindLabel } from '../logic/kinds';
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
</script>

{#if tab && tab.candidates.length > 0}
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
