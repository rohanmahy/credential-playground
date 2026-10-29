<script lang="ts">
  // Raw pane: hex rows aligned to main-pane lines (COSE) or JOSE segments.
  // Hex blocks have the main pane's line height, so with a shared scroll
  // container each block sits next to its EDN line, and both panes render
  // the same window of lines on large documents.
  import { tick } from 'svelte';
  import type { Document, NodeId } from '../engine/types';
  import { fromB64u } from '../engine/bytes';
  import { getAppContext } from '../context';
  import { alignRows, hiddenLines, lineInfos, segmentHighlight } from '../logic/lines';
  import { nodeIndex } from '../logic/tree';
  import { LINE_HEIGHT, type Slice } from '../logic/viewport';
  import { hex } from '../ui';

  let { tabId, slice = null }: { tabId: string; slice?: Slice | null } = $props();

  /** Longer payloads are cut in the row (the decoded view shows them). */
  const MAX_PAYLOAD = 48;

  const { workspace } = getAppContext();
  const tab = $derived(workspace.tab(tabId));
  const doc = $derived(tab?.doc);
  const index = $derived(doc ? nodeIndex(doc.tree) : new Map());

  const bytesCache = new WeakMap<Document, Uint8Array>();
  function rawBytes(d: Document): Uint8Array {
    let b = bytesCache.get(d);
    if (!b) {
      b = d.raw.type === 'hex' ? fromB64u(d.raw.bytes) : new Uint8Array();
      bytesCache.set(d, b);
    }
    return b;
  }

  // --- hex ---------------------------------------------------------------
  const infos = $derived(doc ? lineInfos(doc) : []);
  const aligned = $derived(doc ? alignRows(doc) : []);
  const hidden = $derived(doc && tab ? hiddenLines(doc, tab.collapsed) : new Set<number>());
  const visible = $derived(aligned.filter((l) => !hidden.has(l.line)));
  const shown = $derived(slice ? visible.slice(slice.start, slice.end) : visible);

  /** Row index → the node it folds: the first row of a foldable node that
   *  is also the node of its main-pane line. */
  const foldRows = $derived.by(() => {
    const out: Record<number, NodeId> = {};
    for (const l of infos) {
      if (!l.foldable || l.nodeId === null) continue;
      const raw = index.get(l.nodeId)?.node.raw;
      if (raw) out[raw.row_start] = l.nodeId;
    }
    return out;
  });

  const selectedRows = $derived.by(() => {
    const id = tab?.selected;
    const raw = id === null || id === undefined ? null : index.get(id)?.node.raw;
    return raw && doc?.raw.type === 'hex' ? { start: raw.row_start, end: raw.row_end } : null;
  });

  const rowOrder = $derived(visible.flatMap((l) => l.rows));
  let focusedRow = $state<number | null>(null);
  const rowStop = $derived(
    focusedRow !== null && rowOrder.includes(focusedRow)
      ? focusedRow
      : ((selectedRows && rowOrder.find((r) => r >= selectedRows.start && r < selectedRows.end)) ??
          rowOrder[0] ??
          null),
  );

  let treeEl: HTMLDivElement | undefined = $state();

  function select(id: NodeId) {
    workspace.select(tabId, id);
  }

  async function focusRow(i: number) {
    const row = rowOrder[Math.max(0, Math.min(rowOrder.length - 1, i))];
    if (row === undefined) return;
    focusedRow = row;
    await tick();
    treeEl?.querySelector<HTMLElement>(`[data-row="${row}"]`)?.focus();
  }

  function onHexKey(e: KeyboardEvent) {
    const el = (e.target as HTMLElement).closest<HTMLElement>('[data-row]');
    if (!el || doc?.raw.type !== 'hex') return;
    const row = Number(el.dataset['row']);
    const at = rowOrder.indexOf(row);
    const folds = foldRows[row];
    switch (e.key) {
      case 'ArrowDown':
        void focusRow(at + 1);
        break;
      case 'ArrowUp':
        void focusRow(at - 1);
        break;
      case 'Home':
        void focusRow(0);
        break;
      case 'End':
        void focusRow(rowOrder.length - 1);
        break;
      case 'ArrowLeft':
        if (folds !== undefined) workspace.setCollapsed(tabId, folds, true);
        break;
      case 'ArrowRight':
        if (folds !== undefined) workspace.setCollapsed(tabId, folds, false);
        break;
      case 'Enter':
      case ' ':
        select(doc.raw.rows[row]?.node_id ?? '');
        break;
      default:
        return;
    }
    e.preventDefault();
  }

  // --- segments ----------------------------------------------------------
  const highlight = $derived(
    doc && tab && tab.selected !== null ? segmentHighlight(doc, tab.selected) : null,
  );

  function foldable(id: NodeId): boolean {
    const main = index.get(id)?.node.main;
    return !!main && main.line_end - main.line_start > 1;
  }

  let focusedSeg = $state(0);

  function onSegKey(e: KeyboardEvent) {
    if (doc?.raw.type !== 'segments') return;
    const segs = doc.raw.segments;
    const el = (e.target as HTMLElement).closest<HTMLElement>('[role="treeitem"]');
    const at = Number(el?.dataset['index'] ?? 0);
    const seg = segs[at];
    let next = at;
    switch (e.key) {
      case 'ArrowDown':
        next = Math.min(segs.length - 1, at + 1);
        break;
      case 'ArrowUp':
        next = Math.max(0, at - 1);
        break;
      case 'Home':
        next = 0;
        break;
      case 'End':
        next = segs.length - 1;
        break;
      case 'ArrowLeft':
        if (seg && foldable(seg.node_id)) workspace.setCollapsed(tabId, seg.node_id, true);
        break;
      case 'ArrowRight':
        if (seg && foldable(seg.node_id)) workspace.setCollapsed(tabId, seg.node_id, false);
        break;
      case 'Enter':
      case ' ':
        if (seg) select(seg.node_id);
        break;
      default:
        return;
    }
    e.preventDefault();
    if (next !== at) {
      focusedSeg = next;
      void tick().then(() => treeEl?.querySelector<HTMLElement>(`[data-index="${next}"]`)?.focus());
    }
  }
</script>

{#if tab && doc}
  {#if doc.raw.type === 'hex'}
    {@const raw = doc.raw}
    {@const bytes = rawBytes(doc)}
    <div
      bind:this={treeEl}
      class="hex mono"
      role="tree"
      aria-label="Raw pane"
      tabindex="-1"
      style:--line-h={`${LINE_HEIGHT}px`}
      onkeydown={onHexKey}
    >
      {#if slice}<div style:height={`${slice.start * LINE_HEIGHT}px`}></div>{/if}
      {#each shown as l (l.line)}
        <div class="block" role="none" data-line={l.line}>
          {#each l.rows as r (r)}
            {@const row = raw.rows[r]}
            {#if row}
              {@const folds = foldRows[r]}
              {@const payloadLen = row.payload.end - row.payload.start}
              <!-- Keys are handled by the tree's keydown handler (roving focus). -->
              <!-- svelte-ignore a11y_click_events_have_key_events -->
              <span
                class="row"
                class:brk={row.kind === 'break'}
                role="treeitem"
                data-row={r}
                data-node-id={row.node_id}
                aria-level={row.depth + 1}
                aria-selected={selectedRows !== null &&
                  r >= selectedRows.start &&
                  r < selectedRows.end}
                aria-expanded={folds !== undefined ? !tab.collapsed.has(folds) : undefined}
                tabindex={rowStop === r ? 0 : -1}
                onclick={() => {
                  focusedRow = r;
                  select(row.node_id);
                }}
              >
                {#if folds !== undefined}
                  {@const folded = tab.collapsed.has(folds)}
                  <button
                    type="button"
                    class="fold"
                    tabindex="-1"
                    aria-label={folded ? 'Expand' : 'Collapse'}
                    onclick={(e) => {
                      e.stopPropagation();
                      workspace.toggleCollapsed(tabId, folds);
                    }}>{folded ? '▸' : '▾'}</button
                  >
                {/if}<span class="head">{hex(bytes, row.head.start, row.head.end)}</span
                >{#if payloadLen > 0}<span class="payload"
                    >{hex(
                      bytes,
                      row.payload.start,
                      row.payload.start + Math.min(payloadLen, MAX_PAYLOAD),
                    )}{payloadLen > MAX_PAYLOAD ? '…' : ''}</span
                  >{/if}
                <span class="desc">{row.description}</span>{#if row.comment}<span class="comment"
                    >/ {row.comment} /</span
                  >{/if}
              </span>
            {/if}
          {/each}
        </div>
      {/each}
      {#if slice}<div style:height={`${(visible.length - slice.end) * LINE_HEIGHT}px`}></div>{/if}
    </div>
  {:else if doc.raw.type === 'segments'}
    <div
      bind:this={treeEl}
      class="segments mono"
      role="tree"
      aria-label="Raw pane"
      tabindex="-1"
      onkeydown={onSegKey}
    >
      {#each doc.raw.segments as s, i (s.node_id)}
        {@const hl = highlight && highlight.segment === i ? highlight : null}
        {@const a = hl ? Math.max(0, hl.start - s.range.start) : 0}
        {@const b = hl ? Math.max(a, hl.end - s.range.start) : 0}
        {@const canFold = foldable(s.node_id)}
        {@const folded = canFold && tab.collapsed.has(s.node_id)}
        <!-- Keys are handled by the tree's keydown handler (roving focus). -->
        <!-- svelte-ignore a11y_click_events_have_key_events -->
        <div
          class="segment"
          class:folded
          role="treeitem"
          data-node-id={s.node_id}
          data-index={i}
          aria-level="1"
          aria-selected={hl !== null}
          aria-expanded={canFold ? !folded : undefined}
          tabindex={focusedSeg === i ? 0 : -1}
          onclick={() => {
            focusedSeg = i;
            select(s.node_id);
          }}
        >
          <div class="seg-head">
            {#if canFold}
              <button
                type="button"
                class="fold"
                tabindex="-1"
                aria-label={folded ? 'Expand' : 'Collapse'}
                onclick={(e) => {
                  e.stopPropagation();
                  workspace.toggleCollapsed(tabId, s.node_id);
                }}>{folded ? '▸' : '▾'}</button
              >
            {/if}
            <span class="label">{s.label}</span>
          </div>
          <div class="seg-text">
            {#if hl}{s.text.slice(0, a)}<mark>{s.text.slice(a, b)}</mark>{s.text.slice(
                b,
              )}{:else}{s.text}{/if}{#if s.separator}<span class="sep">{s.separator}</span>{/if}
          </div>
        </div>
      {/each}
    </div>
  {/if}
{/if}

<style>
  .hex {
    font-size: 0.8rem;
    min-width: max-content;
    padding: 0.25rem 0;
  }
  .block {
    height: var(--line-h);
    line-height: var(--line-h);
    white-space: pre;
  }
  .row {
    margin-right: 1.5em;
    padding: 0 0.2em;
    border-radius: 3px;
    cursor: default;
  }
  .row[aria-selected='true'] {
    background: var(--sel);
  }
  .row:focus-visible,
  .segment:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
  }
  .head {
    color: var(--accent);
  }
  .payload {
    margin-left: 0.4em;
  }
  .desc,
  .comment {
    margin-left: 0.6em;
    color: var(--muted);
    font-family: system-ui, sans-serif;
    font-size: 0.9em;
  }
  .fold {
    width: 1.2rem;
    padding: 0;
    border: 0;
    background: none;
    color: var(--muted);
    font: inherit;
    cursor: pointer;
  }
  .segments {
    font-size: 0.8rem;
    padding: 0.25rem;
  }
  .segment {
    padding: 0.25rem 0.4rem;
    border-radius: 4px;
    margin-bottom: 0.25rem;
  }
  .segment[aria-selected='true'] {
    background: var(--sel-soft);
  }
  .seg-head {
    display: flex;
    align-items: center;
  }
  .label {
    font-family: system-ui, sans-serif;
    font-weight: 600;
    color: var(--muted);
  }
  .seg-text {
    word-break: break-all;
    white-space: pre-wrap;
  }
  .folded .seg-text {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    word-break: normal;
  }
  mark {
    background: var(--mark);
    color: inherit;
  }
  .sep {
    color: var(--muted);
  }
</style>
