<script lang="ts">
  // SD view: disclosures with digest, salt, claim, value, status, and a link
  // to the slot they fill; undisclosed digests (decoys / withheld).
  // Layout (SPEC §4.1): a splitter above the view ("Resize disclosures")
  // and resize handles on the Value, Salt, and Digest columns. Until the
  // user resizes it, the view fits its content, up to a third of the
  // window. The sizes the user picks live in the tab (workspace) while the
  // app runs; they are never stored.
  import type { DisclosureStatus } from '../engine/types';
  import type { SdColumn } from '../stores/workspace.svelte';
  import { getAppContext } from '../context';
  import { clamp, dragResize, resizeKeyDelta } from '../logic/resize';

  let { tabId, panes }: { tabId: string; panes?: HTMLElement | undefined } = $props();

  const { workspace } = getAppContext();
  const tab = $derived(workspace.tab(tabId));

  const STATUS: Record<DisclosureStatus, string> = {
    matched: 'matched',
    unmatched: 'unmatched',
    duplicate: 'duplicate',
    malformed: 'malformed',
    forbidden_name: 'forbidden name',
    kind_mismatch: 'kind mismatch',
    name_collision: 'name collision',
  };

  /** The smallest SD view height. */
  const MIN_HEIGHT = 40;
  /** The least the panes above keep when the SD view grows. */
  const PANES_MIN = 160;
  const MIN_COLUMN = 32;
  const DEFAULT_COLUMNS: Record<SdColumn, number> = {
    Claim: 120,
    Value: 240,
    Salt: 120,
    Digest: 180,
  };
  const COLUMNS = ['Claim', 'Value', 'Salt', 'Digest', 'Status', 'Slot'] as const;

  const resizable = (c: (typeof COLUMNS)[number]): c is SdColumn =>
    c === 'Claim' || c === 'Value' || c === 'Salt' || c === 'Digest';

  let region: HTMLElement | undefined = $state();
  /** The view's rendered height while it fits its content (0: unmeasured,
   *  as in jsdom). */
  let natural = $state(0);
  let windowHeight = $state(window.innerHeight);
  const third = $derived(Math.floor(windowHeight / 3));
  const hasDisclosures = $derived((tab?.doc.disclosures.length ?? 0) > 0);
  const userHeight = $derived(hasDisclosures ? (tab?.sdHeight ?? null) : null);
  const height = $derived(userHeight ?? (natural > 0 ? Math.min(natural, third) : third));

  $effect(() => {
    const onResize = () => (windowHeight = window.innerHeight);
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  });

  $effect(() => {
    const el = region;
    if (!el) return;
    natural = el.offsetHeight;
    if (typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(() => (natural = el.offsetHeight));
    observer.observe(el);
    return () => observer.disconnect();
  });

  /** The tallest the view may get, leaving the panes PANES_MIN. Without
   *  a layout (nothing measured), the window height. */
  function maxHeight(): number {
    const room = panes?.clientHeight ?? 0;
    return room > 0 ? height + room - PANES_MIN : window.innerHeight;
  }

  function setHeight(px: number, max = maxHeight()) {
    workspace.setSdHeight(tabId, clamp(px, MIN_HEIGHT, max));
  }

  function splitterKey(e: KeyboardEvent) {
    const delta = resizeKeyDelta(e, 'horizontal');
    if (delta === null) return;
    e.preventDefault();
    setHeight(height + delta);
  }

  function splitterDrag(e: PointerEvent) {
    const start = height;
    const max = maxHeight();
    // dragging up (negative dy) grows the view below the splitter
    dragResize(e, 'y', (dy) => setHeight(start - dy, max));
  }

  function columnWidth(c: SdColumn): number {
    return tab?.sdColumns?.[c] ?? DEFAULT_COLUMNS[c];
  }

  /** Exactly the resized columns plus Status and Slot (CSS widths), so no
   *  column soaks up spare room; a wider table scrolls sideways. */
  const tableWidth = $derived(
    `calc(${(['Claim', 'Value', 'Salt', 'Digest'] as const).reduce((n, c) => n + columnWidth(c), 0)}px + 10rem)`,
  );

  function setColumn(c: SdColumn, px: number) {
    workspace.setSdColumn(tabId, c, clamp(px, MIN_COLUMN, Number.MAX_SAFE_INTEGER));
  }

  function columnKey(c: SdColumn, e: KeyboardEvent) {
    const delta = resizeKeyDelta(e, 'vertical');
    if (delta === null) return;
    e.preventDefault();
    setColumn(c, columnWidth(c) + delta);
  }

  function columnDrag(c: SdColumn, e: PointerEvent) {
    const start = columnWidth(c);
    dragResize(e, 'x', (dx) => setColumn(c, start + dx));
  }
</script>

{#if tab && (tab.doc.disclosures.length > 0 || tab.doc.undisclosed.length > 0)}
  {#if hasDisclosures}
    <!-- A focusable separator is a widget (WAI-ARIA), which Svelte's a11y
         lint does not know. -->
    <!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
    <div
      class="splitter"
      role="separator"
      tabindex="0"
      aria-label="Resize disclosures"
      aria-orientation="horizontal"
      aria-valuenow={height}
      aria-valuemin={MIN_HEIGHT}
      title="Drag, or use Arrow Up / Arrow Down, to resize"
      onkeydown={splitterKey}
      onpointerdown={splitterDrag}
    ></div>
  {/if}
  <section
    bind:this={region}
    class="sd"
    aria-labelledby={`${tabId}-sd`}
    style:height={userHeight !== null ? `${userHeight}px` : null}
    style:max-height={userHeight === null ? `${third}px` : null}
  >
    <h3 id={`${tabId}-sd`}>Selective disclosure</h3>
    <div class="body">
      {#if tab.doc.disclosures.length > 0}
        <table aria-label="Disclosures" style:width={tableWidth}>
          <thead>
            <tr>
              {#each COLUMNS as c (c)}
                {#if resizable(c)}
                  {@const w = columnWidth(c)}
                  <th scope="col" style:width={`${w}px`}
                    >{c}
                    <!-- A focusable separator is a widget (WAI-ARIA), which
                         Svelte's a11y lint does not know. -->
                    <!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
                    <span
                      class="col-handle"
                      role="separator"
                      tabindex="0"
                      aria-label={`Resize ${c} column`}
                      aria-orientation="vertical"
                      aria-valuenow={w}
                      aria-valuemin={MIN_COLUMN}
                      title="Drag, or use Arrow Left / Arrow Right, to resize"
                      onkeydown={(e) => columnKey(c, e)}
                      onpointerdown={(e) => columnDrag(c, e)}
                    ></span></th
                  >
                {:else}
                  <th scope="col" class={`col-${c.toLowerCase()}`}>{c}</th>
                {/if}
              {/each}
            </tr>
          </thead>
          <tbody>
            {#each tab.doc.disclosures as d (d.index)}
              <tr class:selected={tab.selected === d.node_id}>
                <td class="mono">
                  <button
                    type="button"
                    class="link"
                    onclick={() => workspace.reveal(tabId, d.node_id)}
                    >{d.claim ?? `[${d.index}]`}</button
                  >{#if d.decoy}<span class="muted"> (decoy)</span>{/if}
                </td>
                <td class="mono value">{d.value}</td>
                <td class="mono clip" title={d.salt}>{d.salt}</td>
                <td class="mono clip" title={d.digest}>{d.digest}</td>
                <td><span class="status" data-status={d.status}>{STATUS[d.status]}</span></td>
                <td>
                  {#if d.slot}
                    {@const slot = d.slot}
                    <button
                      type="button"
                      aria-label={`Show the slot of ${d.claim ?? `disclosure ${d.index + 1}`}`}
                      onclick={() => workspace.reveal(tabId, slot)}>slot</button
                    >
                  {:else}<span class="muted">none</span>{/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
      {#if tab.doc.undisclosed.length > 0}
        <h4>Digests without a disclosure</h4>
        <ul aria-label="Undisclosed digests">
          {#each tab.doc.undisclosed as u (u.node_id)}
            <li>
              <button
                type="button"
                class="link mono"
                onclick={() => workspace.reveal(tabId, u.node_id)}>{u.digest}</button
              >
              <span class="muted">decoy or withheld{u.array_element ? ' (array element)' : ''}</span
              >
            </li>
          {/each}
        </ul>
      {/if}
    </div>
  </section>
{/if}

<style>
  .splitter {
    flex: 0 0 auto;
    box-sizing: border-box;
    height: 6px;
    cursor: row-resize;
    border-top: 2px solid var(--border);
    touch-action: none;
  }
  .splitter:hover,
  .splitter:focus-visible {
    background: var(--hover);
    border-top-color: var(--accent);
  }
  .splitter:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
  }
  .sd {
    flex: 0 0 auto;
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    min-height: 0;
    overflow: hidden;
    padding: 0.5rem 0.75rem 0;
    border-top: 1px solid var(--border);
  }
  .splitter + .sd {
    border-top: 0;
  }
  h3 {
    flex: 0 0 auto;
    font-size: 0.95rem;
    margin: 0 0 0.4rem;
  }
  h4 {
    font-size: 0.85rem;
    margin: 0.6rem 0 0.2rem;
  }
  /* The SD view scrolls on its own, apart from the panes. */
  .body {
    flex: 1 1 auto;
    min-height: 0;
    overflow: auto;
    padding-bottom: 0.5rem;
  }
  table {
    table-layout: fixed;
    border-collapse: collapse;
    font-size: 0.85rem;
  }
  th,
  td {
    box-sizing: border-box;
    text-align: left;
    padding: 0.2rem 0.5rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
    overflow-wrap: anywhere;
  }
  th {
    position: relative;
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
  }
  .col-status {
    width: 5.5rem;
  }
  .col-slot {
    width: 4.5rem;
  }
  .col-handle {
    position: absolute;
    top: 0;
    right: 0;
    bottom: 0;
    box-sizing: border-box;
    width: 7px;
    cursor: col-resize;
    border-right: 2px solid var(--border);
    touch-action: none;
  }
  .col-handle:hover,
  .col-handle:focus-visible {
    background: var(--hover);
    border-right-color: var(--accent);
  }
  .col-handle:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
  }
  /* Value wraps anywhere (an h'' byte string has no spaces to break at)
     and is never truncated. */
  .value {
    word-break: break-all;
  }
  /* Salt and Digest: one line with an ellipsis. The DOM and the title keep
     the whole value, so select-and-copy copies all of it. */
  .clip {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    overflow-wrap: normal;
  }
  tr.selected {
    background: var(--sel);
  }
  .status[data-status='matched'] {
    color: var(--pass);
  }
  .status:not([data-status='matched']) {
    color: var(--fail);
  }
  ul {
    margin: 0;
    padding-left: 1.2rem;
    font-size: 0.85rem;
  }
</style>
