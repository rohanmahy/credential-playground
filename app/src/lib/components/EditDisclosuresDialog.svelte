<script lang="ts">
  // Edit disclosures: remove, duplicate, reorder, change a value, forge a
  // new one, or remove a digest. Each edit opens a derived tab.
  import type { DisclosureOp } from '../engine/types';
  import { getAppContext } from '../context';
  import { kindFamily } from '../logic/kinds';
  import { errorMessage } from '../ui';
  import Dialog from './Dialog.svelte';

  let { tabId, onClose }: { tabId: string; onClose: () => void } = $props();

  const { workspace } = getAppContext();
  const tab = $derived(workspace.tab(tabId));
  const doc = $derived(tab?.doc);
  const jose = $derived(doc ? kindFamily(doc.kind) === 'jose' : true);

  let claim = $state('');
  let value = $state('');
  let salt = $state('');
  let error = $state<string | null>(null);

  async function apply(op: DisclosureOp) {
    error = null;
    try {
      await workspace.runAction(tabId, { action: 'edit_disclosures', ops: [op] });
      onClose();
    } catch (err) {
      error = errorMessage(err);
    }
  }
</script>

<Dialog title="Edit disclosures" {onClose} wide>
  {#if doc}
    <table>
      <caption class="sr-only">Disclosures to edit</caption>
      <thead><tr><th>#</th><th>Claim</th><th>Value</th><th>Edit</th></tr></thead>
      <tbody>
        {#each doc.disclosures as d, i (d.index)}
          <tr>
            <td>{d.index + 1}</td>
            <td class="mono">{d.claim ?? '(array element)'}</td>
            <td class="mono">{d.value}</td>
            <td class="buttons">
              <button type="button" onclick={() => apply({ type: 'remove', index: d.index })}
                >Remove</button
              >
              <button type="button" onclick={() => apply({ type: 'duplicate', index: d.index })}
                >Duplicate</button
              >
              <button
                type="button"
                disabled={i === 0}
                onclick={() => apply({ type: 'move', from: d.index, to: d.index - 1 })}
                >Move up</button
              >
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if jose && doc.undisclosed.length > 0}
      <h3>Digests without a disclosure</h3>
      <ul>
        {#each doc.undisclosed as u (u.node_id)}
          <li>
            <code>{u.digest}</code>
            <button type="button" onclick={() => apply({ type: 'remove_digest', digest: u.digest })}
              >Remove digest</button
            >
          </li>
        {/each}
      </ul>
    {/if}
    <form
      onsubmit={(e) => {
        e.preventDefault();
        void apply({
          type: 'forge',
          salt: salt || null,
          claim: claim || null,
          value: value || null,
        });
      }}
    >
      <h3>Forge a disclosure</h3>
      <label class="field"><span>Claim name</span><input type="text" bind:value={claim} /></label>
      <label class="field"
        ><span>Value ({jose ? 'JSON' : 'EDN'})</span><input type="text" bind:value /></label
      >
      <label class="field"
        ><span>Salt (optional)</span><input type="text" bind:value={salt} /></label
      >
      <div class="buttons"><button type="submit">Forge</button></div>
    </form>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
  {/if}
</Dialog>
