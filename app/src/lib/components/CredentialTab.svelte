<script lang="ts">
  // One credential tab: header, main pane, raw pane, SD view, report.
  // The main pane and a hex raw pane share one vertical scroll container,
  // so each hex block stays beside its EDN line; long documents render
  // only the lines in view.
  import { getAppContext } from '../context';
  import { hiddenLines, lineInfos } from '../logic/lines';
  import { LINE_HEIGHT, windowFor } from '../logic/viewport';
  import TabHeader from './TabHeader.svelte';
  import MainPane from './MainPane.svelte';
  import RawPane from './RawPane.svelte';
  import DisclosuresView from './DisclosuresView.svelte';
  import ValidationReport from './ValidationReport.svelte';
  import UrlFetch from './UrlFetch.svelte';

  let { tabId }: { tabId: string } = $props();

  const { workspace, settings } = getAppContext();
  const tab = $derived(workspace.tab(tabId));
  const hasRaw = $derived(tab ? tab.doc.raw.type !== 'none' : false);
  const showRaw = $derived(hasRaw && settings.showRaw);

  let scroller: HTMLDivElement | undefined = $state();
  let scrollTop = $state(0);
  let height = $state(0);

  const visibleCount = $derived.by(() => {
    if (!tab) return 0;
    const hidden = hiddenLines(tab.doc, tab.collapsed);
    return lineInfos(tab.doc).length - hidden.size;
  });
  const slice = $derived(tab?.liveEdit ? null : windowFor(visibleCount, scrollTop, height));

  let fetchUrl = $state<string | null>(null);
  let notice = $state<string | null>(null);

  function measure() {
    if (!scroller) return;
    scrollTop = scroller.scrollTop;
    height = scroller.clientHeight;
  }

  $effect(() => {
    measure();
    const onResize = () => measure();
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  });

  function scrollTo(index: number) {
    if (!scroller) return;
    scroller.scrollTop = Math.max(0, index * LINE_HEIGHT - scroller.clientHeight / 2);
    measure();
  }

  async function revalidate() {
    fetchUrl = null;
    notice = null;
    try {
      await workspace.validate(tabId);
    } catch (e) {
      notice = e instanceof Error ? e.message : String(e);
    }
  }
</script>

{#if tab}
  <div class="credential">
    <TabHeader {tabId} />
    <div class="toggles">
      {#if hasRaw}
        <label><input type="checkbox" bind:checked={settings.showRaw} /> Show raw pane</label>
      {/if}
      {#if tab.doc.diagnostics.length > 0}
        <details class="diagnostics">
          <summary
            >{tab.doc.diagnostics.length} diagnostic{tab.doc.diagnostics.length === 1
              ? ''
              : 's'}</summary
          >
          <ul>
            {#each tab.doc.diagnostics as d, i (i)}
              <li data-severity={d.severity}>
                <span class="sev">{d.severity}</span>
                {d.message}
                {#if d.node_id !== null}
                  {@const id = d.node_id}
                  <button
                    type="button"
                    class="link mono"
                    onclick={() => workspace.reveal(tabId, id)}>{id || '(root)'}</button
                  >
                {/if}
              </li>
            {/each}
          </ul>
        </details>
      {/if}
    </div>
    <div
      bind:this={scroller}
      class="panes"
      class:split={showRaw}
      class:segments={tab.doc.raw.type === 'segments'}
      onscroll={measure}
    >
      <div class="pane main"><MainPane {tabId} {slice} onScrollTo={scrollTo} /></div>
      {#if showRaw}
        <div class="pane raw"><RawPane {tabId} {slice} /></div>
      {/if}
    </div>
    <DisclosuresView {tabId} />
    {#if tab.report}
      <ValidationReport
        report={tab.report}
        onSelectNode={(id) => workspace.reveal(tabId, id)}
        onFetch={(hint) => (fetchUrl = hint.url)}
      />
    {/if}
    {#if fetchUrl}
      <UrlFetch url={fetchUrl} onImported={revalidate} onClose={() => (fetchUrl = null)} />
    {/if}
    {#if notice}<p class="error">{notice}</p>{/if}
  </div>
{/if}

<style>
  .credential {
    display: flex;
    flex-direction: column;
    min-height: 0;
    height: 100%;
  }
  .toggles {
    display: flex;
    flex-wrap: wrap;
    gap: 1rem;
    align-items: baseline;
    padding: 0.25rem 0.75rem;
    font-size: 0.85rem;
  }
  .diagnostics ul {
    margin: 0.25rem 0;
    padding-left: 1.2rem;
  }
  .sev {
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.75rem;
  }
  [data-severity='error'] .sev {
    color: var(--fail);
  }
  [data-severity='warning'] .sev {
    color: var(--warn);
  }
  .panes {
    flex: 1 1 auto;
    min-height: 10rem;
    overflow: auto;
    display: grid;
    grid-template-columns: minmax(0, 1fr);
    align-items: start;
    border-top: 1px solid var(--border);
  }
  .panes.split {
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  }
  .pane {
    overflow-x: auto;
    min-width: 0;
  }
  .pane.raw {
    border-left: 1px solid var(--border);
  }
  .error {
    color: var(--fail);
    padding: 0 0.75rem;
  }
</style>
