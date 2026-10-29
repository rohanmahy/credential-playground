<script lang="ts">
  // Main pane: read-only line tree (role=tree) over Document.main.text with
  // folding, annotations, and time hints; CodeMirror in live edit.
  import { tick } from 'svelte';
  import type { NodeId } from '../engine/types';
  import { getAppContext } from '../context';
  import { hiddenLines, lineInfos, type LineInfo } from '../logic/lines';
  import { nodeIndex } from '../logic/tree';
  import { hoverText, timeHintText } from '../logic/hover';
  import { kindFamily } from '../logic/kinds';
  import { LINE_HEIGHT, type Slice } from '../logic/viewport';
  import type { MenuItem } from '../ui';
  import CodeEditor from './CodeEditor.svelte';
  import Menu from './Menu.svelte';

  let {
    tabId,
    slice = null,
    onScrollTo,
  }: {
    tabId: string;
    /** Rendered window of the visible lines (null renders all). */
    slice?: Slice | null;
    /** Asks the scroll container to bring visible line `index` into view. */
    onScrollTo?: (index: number) => void;
  } = $props();

  const { workspace, platform } = getAppContext();
  const tab = $derived(workspace.tab(tabId));
  const doc = $derived(tab?.doc);
  const texts = $derived(doc ? doc.main.text.split('\n') : []);
  const offsets = $derived.by(() => {
    const out: number[] = [];
    let at = 0;
    for (const t of texts) {
      out.push(at);
      at += t.length + 1;
    }
    return out;
  });
  const index = $derived(doc ? nodeIndex(doc.tree) : new Map());
  const infos = $derived(doc ? lineInfos(doc) : []);
  const hidden = $derived(doc && tab ? hiddenLines(doc, tab.collapsed) : new Set<number>());
  const visible = $derived(infos.filter((l) => !hidden.has(l.line)));
  const shown = $derived(slice ? visible.slice(slice.start, slice.end) : visible);
  const items = $derived(visible.filter((l) => l.nodeId !== null));

  const selectedRange = $derived.by(() => {
    const id = tab?.selected;
    if (id === null || id === undefined) return null;
    return index.get(id)?.node.main ?? null;
  });

  let focused = $state<NodeId | null>(null);
  const tabStop = $derived.by(() => {
    if (focused !== null && items.some((i) => i.nodeId === focused)) return focused;
    const sel = selectedRange
      ? items.find((i) => i.line === selectedRange.line_start)?.nodeId
      : undefined;
    return sel ?? items[0]?.nodeId ?? null;
  });

  let treeEl: HTMLDivElement | undefined = $state();
  let menu = $state<{ x: number; y: number; id: NodeId } | null>(null);
  let editTimer: ReturnType<typeof setTimeout> | undefined;

  function isCollapsed(id: NodeId): boolean {
    return tab?.collapsed.has(id) ?? false;
  }

  function toggle(id: NodeId) {
    workspace.toggleCollapsed(tabId, id);
  }

  function select(id: NodeId) {
    focused = id;
    workspace.select(tabId, id);
  }

  async function focusItem(i: number) {
    const target = items[Math.max(0, Math.min(items.length - 1, i))];
    if (!target || target.nodeId === null) return;
    const id = target.nodeId;
    focused = id;
    const at = visible.indexOf(target);
    if (slice && (at < slice.start || at >= slice.end)) onScrollTo?.(at);
    await tick();
    treeEl
      ?.querySelector<HTMLElement>(`[role="treeitem"][data-node-id="${CSS.escape(id)}"]`)
      ?.focus();
  }

  function onkeydown(e: KeyboardEvent) {
    const el = (e.target as HTMLElement).closest<HTMLElement>('[role="treeitem"]');
    const id = el?.dataset['nodeId'];
    if (id === undefined) return;
    const at = items.findIndex((i) => i.nodeId === id);
    const info = items[at];
    if (!info) return;
    switch (e.key) {
      case 'ArrowDown':
        void focusItem(at + 1);
        break;
      case 'ArrowUp':
        void focusItem(at - 1);
        break;
      case 'Home':
        void focusItem(0);
        break;
      case 'End':
        void focusItem(items.length - 1);
        break;
      case 'ArrowLeft':
        if (info.foldable && !isCollapsed(id)) toggle(id);
        else {
          const parent = items.slice(0, at).findLastIndex((i) => i.depth < info.depth);
          if (parent >= 0) void focusItem(parent);
        }
        break;
      case 'ArrowRight':
        if (info.foldable && isCollapsed(id)) toggle(id);
        else if (info.foldable) void focusItem(at + 1);
        break;
      case 'Enter':
      case ' ':
        select(id);
        break;
      case 'ContextMenu':
        openMenu(el, id);
        break;
      case 'F10':
        if (!e.shiftKey) return;
        openMenu(el, id);
        break;
      default:
        return;
    }
    e.preventDefault();
  }

  function openMenu(el: HTMLElement | null, id: NodeId, x?: number, y?: number) {
    const rect = el?.getBoundingClientRect();
    menu = { x: x ?? rect?.left ?? 0, y: y ?? rect?.bottom ?? 0, id };
  }

  function menuItems(id: NodeId): MenuItem[] {
    if (!doc || !tab) return [];
    const node = index.get(id)?.node;
    const items: MenuItem[] = [{ label: 'Select', action: () => select(id) }];
    if (doc.kind.type === 'json_claims' && id !== '') {
      items.push({
        label: 'Selectively disclosable',
        role: 'menuitemcheckbox',
        checked: tab.sdMarks.has(id),
        action: () => workspace.toggleSdMark(tabId, id),
      });
    }
    if (node?.time || node?.kind === 'tag') {
      items.push({ label: 'Date/time…', action: () => workspace.openChit(tabId, id) });
    }
    const decodedId = id === '' ? '~e' : `${id}/~e`;
    if (index.has(decodedId) || tab.hideDecoded?.includes(id)) {
      const off = tab.hideDecoded?.includes(id) ?? false;
      items.push({
        label: off ? 'Show decoded view' : 'Hide decoded view',
        action: () => void workspace.toggleDecodedView(tabId, id),
      });
    } else if (node?.kind === 'bytes' && kindFamily(doc.kind) === 'cose') {
      items.push({
        label: 'Decode as CBOR',
        action: () => void workspace.decodeAsCbor(tabId, id),
      });
    }
    if (node?.main) {
      const text = doc.main.text.slice(node.main.start, node.main.end);
      items.push({ label: 'Copy text', action: () => void platform.writeClipboard(text) });
    }
    return items;
  }

  function onEdit(text: string) {
    clearTimeout(editTimer);
    editTimer = setTimeout(() => void workspace.applyEdit(tabId, text), 150);
  }

  /** The part of a line to carry the hover text: the member name / label
   *  before the value, or the whole value when there is no name. */
  function split(l: LineInfo): { indent: string; named: string; rest: string; title: string } {
    const text = texts[l.line] ?? '';
    const node = l.nodeId !== null ? index.get(l.nodeId)?.node : undefined;
    const annotation = node?.annotation ?? node?.key?.annotation ?? null;
    const indentLen = text.length - text.trimStart().length;
    const indent = text.slice(0, indentLen);
    if (!annotation || !node?.main)
      return { indent, named: '', rest: text.slice(indentLen), title: '' };
    const valueAt = node.main.start - (offsets[l.line] ?? 0);
    const end = valueAt > indentLen && valueAt <= text.length ? valueAt : text.length;
    return {
      indent,
      named: text.slice(indentLen, end),
      rest: text.slice(end),
      title: hoverText(annotation),
    };
  }
</script>

{#if tab && doc}
  {#if tab.liveEdit}
    <div class="live">
      <CodeEditor text={tab.editText} language={doc.main.language} onChange={onEdit} />
      {#if tab.editDiagnostics.length > 0}
        <div class="diagnostics" role="alert">
          {#each tab.editDiagnostics as d, i (i)}
            <p>
              {#if d.main}<span class="where">Line {d.main.line_start + 1}:</span>{/if}
              {d.message}
            </p>
          {/each}
        </div>
      {/if}
    </div>
  {:else}
    <div
      bind:this={treeEl}
      class="tree mono"
      role="tree"
      aria-label="Main pane"
      tabindex="-1"
      style:--line-h={`${LINE_HEIGHT}px`}
      {onkeydown}
    >
      {#if slice}<div style:height={`${slice.start * LINE_HEIGHT}px`}></div>{/if}
      {#each shown as l (l.line)}
        {@const parts = split(l)}
        {@const inSel =
          selectedRange !== null &&
          l.line >= selectedRange.line_start &&
          l.line < Math.max(selectedRange.line_end, selectedRange.line_start + 1)}
        {#if l.nodeId !== null}
          {@const id = l.nodeId}
          {@const node = index.get(id)?.node}
          {@const folded = l.foldable && isCollapsed(id)}
          <!-- Keys are handled by the tree's keydown handler (roving focus). -->
          <!-- svelte-ignore a11y_click_events_have_key_events -->
          <div
            class="line"
            class:in-sel={inSel}
            class:sd={tab.sdMarks.has(id)}
            role="treeitem"
            data-node-id={id}
            data-line={l.line}
            data-sd-mark={tab.sdMarks.has(id) ? 'true' : undefined}
            aria-level={l.depth + 1}
            aria-expanded={l.foldable ? !folded : undefined}
            aria-selected={selectedRange !== null && selectedRange.line_start === l.line}
            tabindex={tabStop === id ? 0 : -1}
            onclick={() => select(id)}
            oncontextmenu={(e) => {
              e.preventDefault();
              openMenu(e.currentTarget, id, e.clientX, e.clientY);
            }}
          >
            {#if l.foldable}
              <button
                type="button"
                class="fold"
                tabindex="-1"
                aria-label={folded ? 'Expand' : 'Collapse'}
                onclick={(e) => {
                  e.stopPropagation();
                  toggle(id);
                }}>{folded ? '▸' : '▾'}</button
              >
            {:else}<span class="fold" aria-hidden="true"></span>{/if}<span class="text"
              >{parts.indent}{#if parts.named}<span class="ann" title={parts.title}
                  >{parts.named}</span
                >{/if}{parts.rest}</span
            >{#if folded}<span class="ellipsis" aria-hidden="true">
                …</span
              >{/if}{#if node?.time}<span class="time" data-testid="time-hint"
                >{timeHintText(node.time)}</span
              >{/if}{#if tab.sdMarks.has(id)}<span class="sd-badge">SD</span>{/if}
          </div>
        {:else}
          <div class="line" class:in-sel={inSel} role="none" data-line={l.line}>
            <span class="fold" aria-hidden="true"></span><span class="text">{texts[l.line]}</span>
          </div>
        {/if}
      {/each}
      {#if slice}<div style:height={`${(visible.length - slice.end) * LINE_HEIGHT}px`}></div>{/if}
    </div>
  {/if}
  {#if menu}
    <Menu
      label="Node actions"
      items={menuItems(menu.id)}
      x={menu.x}
      y={menu.y}
      onClose={() => (menu = null)}
    />
  {/if}
{/if}

<style>
  .tree {
    font-size: 0.85rem;
    min-width: max-content;
    padding: 0.25rem 0;
  }
  .line {
    height: var(--line-h);
    line-height: var(--line-h);
    white-space: pre;
    cursor: default;
    padding-right: 1rem;
  }
  .line:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
  }
  .line.in-sel {
    background: var(--sel-soft);
  }
  .line[aria-selected='true'] {
    background: var(--sel);
  }
  .line.sd .text {
    text-decoration: underline dotted var(--accent);
  }
  .fold {
    display: inline-block;
    width: 1.2rem;
    padding: 0;
    border: 0;
    background: none;
    color: var(--muted);
    font: inherit;
    line-height: inherit;
    cursor: pointer;
  }
  .ann {
    text-decoration: underline dotted var(--muted);
    cursor: help;
  }
  .time,
  .sd-badge {
    margin-left: 1em;
    color: var(--muted);
    font-family: system-ui, sans-serif;
    font-size: 0.8em;
  }
  .sd-badge {
    color: var(--accent);
    font-weight: 600;
  }
  .ellipsis {
    color: var(--muted);
  }
  .live {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 12rem;
  }
  .diagnostics {
    border-top: 1px solid var(--border);
    color: var(--fail);
    padding: 0.25rem 0.5rem;
    font-size: 0.85rem;
  }
  .diagnostics p {
    margin: 0.2rem 0;
  }
  .where {
    font-weight: 600;
  }
</style>
