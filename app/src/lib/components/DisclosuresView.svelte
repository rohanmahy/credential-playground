<script lang="ts">
  // SD view: disclosures with digest, salt, claim, value, status, and a link
  // to the slot they fill; undisclosed digests (decoys / withheld).
  import type { DisclosureStatus } from '../engine/types';
  import { getAppContext } from '../context';

  let { tabId }: { tabId: string } = $props();

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
</script>

{#if tab && (tab.doc.disclosures.length > 0 || tab.doc.undisclosed.length > 0)}
  <section class="sd" aria-labelledby={`${tabId}-sd`}>
    <h3 id={`${tabId}-sd`}>Selective disclosure</h3>
    {#if tab.doc.disclosures.length > 0}
      <div class="scroll">
        <table aria-label="Disclosures">
          <thead>
            <tr>
              <th scope="col">Claim</th>
              <th scope="col">Value</th>
              <th scope="col">Salt</th>
              <th scope="col">Digest</th>
              <th scope="col">Status</th>
              <th scope="col">Slot</th>
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
                <td class="mono">{d.value}</td>
                <td class="mono">{d.salt}</td>
                <td class="mono digest">{d.digest}</td>
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
      </div>
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
            <span class="muted">decoy or withheld{u.array_element ? ' (array element)' : ''}</span>
          </li>
        {/each}
      </ul>
    {/if}
  </section>
{/if}

<style>
  .sd {
    padding: 0.5rem 0.75rem;
    border-top: 1px solid var(--border);
  }
  h3 {
    font-size: 0.95rem;
    margin: 0 0 0.4rem;
  }
  h4 {
    font-size: 0.85rem;
    margin: 0.6rem 0 0.2rem;
  }
  .scroll {
    overflow-x: auto;
  }
  table {
    border-collapse: collapse;
    font-size: 0.85rem;
  }
  th,
  td {
    text-align: left;
    padding: 0.2rem 0.5rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }
  .digest {
    word-break: break-all;
    max-width: 18rem;
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
