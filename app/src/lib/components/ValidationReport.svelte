<script lang="ts">
  // The checklist (SPEC §6) grouped by category, with links to NodeIds and
  // user-confirmed fetch offers.
  import type {
    Category,
    CheckItem,
    FetchHint,
    KeySelection,
    NodeId,
    ValidationReport,
  } from '../engine/types';

  let {
    report,
    onSelectNode,
    onFetch,
  }: {
    report: ValidationReport;
    onSelectNode: (id: NodeId) => void;
    onFetch?: (hint: FetchHint) => void;
  } = $props();

  const CATEGORIES: { id: Category; label: string }[] = [
    { id: 'signature', label: 'Signature' },
    { id: 'time', label: 'Time' },
    { id: 'sd', label: 'Selective disclosure' },
    { id: 'key_binding', label: 'Key binding' },
    { id: 'lint', label: 'Lint' },
  ];

  const SELECTION: Record<KeySelection, string> = {
    panel_kid: 'panel key matched by kid',
    panel_thumbprint: 'panel key matched by thumbprint',
    panel_unmatched: 'panel key that fits the alg (no kid match)',
    embedded_x5c: 'untrusted embedded key (x5c/x5chain leaf)',
    embedded_cnf: 'untrusted embedded key (cnf)',
    none: 'no key selected',
  };

  const LABELS = Object.fromEntries(CATEGORIES.map((c) => [c.id, c.label])) as Record<
    Category,
    string
  >;

  /** Items in report order, with a heading wherever the category changes. */
  const groups = $derived(
    report.items.reduce<{ id: Category; label: string; items: CheckItem[] }[]>((out, item) => {
      const last = out[out.length - 1];
      if (last && last.id === item.category) last.items.push(item);
      else out.push({ id: item.category, label: LABELS[item.category], items: [item] });
      return out;
    }, []),
  );

  function nodeLabel(id: NodeId): string {
    return id === '' ? '(root)' : id;
  }

  function signature(item: CheckItem): string | null {
    const d = item.detail;
    if (d?.type !== 'signature') return null;
    const key = d.key_label ?? (d.key_index !== null ? `key ${d.key_index + 1}` : null);
    const parts = [key ? `Key: ${key}` : null, `selected as ${SELECTION[d.selection]}`];
    if (d.untrusted) parts.push('untrusted');
    if (d.alg) parts.push(`alg ${d.alg}`);
    return parts.filter(Boolean).join(' · ');
  }
</script>

<section class="report" aria-label="Validation">
  <p class="overall" data-testid="report-overall" data-status={report.overall}>
    Overall: <strong>{report.overall}</strong>
  </p>
  <div role="list" aria-label="Validation report">
    {#each groups as g, gi (`${g.id}-${gi}`)}
      <h4>{g.label}</h4>
      {#each g.items as item, i (`${item.id}-${i}`)}
        {@const sig = signature(item)}
        <div class="item" role="listitem" data-status={item.status} data-id={item.id}>
          <span class="status">{item.status}</span>
          <span class="message">{item.message}</span>
          {#if sig}<span class="detail">{sig}</span>{/if}
          {#if item.detail?.type === 'encoding'}
            <span class="detail">Preferred: <code>{item.detail.preferred_hex}</code></span>
          {/if}
          {#if item.node_ids.length > 0}
            <span class="nodes">
              {#each item.node_ids as id (id)}
                <button type="button" class="link mono" onclick={() => onSelectNode(id)}
                  >{nodeLabel(id)}</button
                >
              {/each}
            </span>
          {/if}
        </div>
      {/each}
    {/each}
  </div>
  {#if report.fetchable.length > 0}
    <div class="fetch">
      {#each report.fetchable as hint (hint.url)}
        <p>
          <button type="button" onclick={() => onFetch?.(hint)}>Fetch key from {hint.url}</button>
          <span class="muted">{hint.reason}. Nothing is fetched until you confirm.</span>
        </p>
      {/each}
    </div>
  {/if}
</section>

<style>
  .report {
    padding: 0.5rem 0.75rem;
    border-top: 1px solid var(--border);
    font-size: 0.85rem;
  }
  .overall {
    margin: 0 0 0.3rem;
  }
  h4 {
    margin: 0.5rem 0 0.2rem;
    font-size: 0.85rem;
  }
  .item {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    align-items: baseline;
    padding: 0.15rem 0;
  }
  .status {
    min-width: 3rem;
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.75rem;
  }
  [data-status='pass'] > .status,
  .overall[data-status='pass'] strong {
    color: var(--pass);
  }
  [data-status='fail'] > .status,
  .overall[data-status='fail'] strong {
    color: var(--fail);
  }
  [data-status='warn'] > .status,
  .overall[data-status='warn'] strong {
    color: var(--warn);
  }
  [data-status='skip'] > .status,
  [data-status='info'] > .status {
    color: var(--muted);
  }
  .detail {
    color: var(--muted);
  }
  .nodes {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 0.3rem;
  }
  .fetch p {
    margin: 0.3rem 0;
  }
</style>
