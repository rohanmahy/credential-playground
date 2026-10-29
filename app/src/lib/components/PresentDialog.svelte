<script lang="ts">
  // Disclose and Present: choose disclosures (all kept by default); Present
  // adds the holder key, audience, and nonce (iat comes from the clock).
  import { getAppContext } from '../context';
  import { ACTION_LABELS, canHoldWith } from '../logic/actions';
  import { errorMessage } from '../ui';
  import Dialog from './Dialog.svelte';

  let {
    tabId,
    action,
    onClose,
  }: { tabId: string; action: 'present' | 'disclose'; onClose: () => void } = $props();

  const { workspace, keys, settings } = getAppContext();
  const tab = $derived(workspace.tab(tabId));
  const disclosures = $derived(tab?.doc.disclosures ?? []);
  const holders = $derived(keys.cards.filter((c) => c.info.private && canHoldWith(c)));

  // svelte-ignore state_referenced_locally
  let keep = $state<boolean[]>(disclosures.map(() => true));
  // svelte-ignore state_referenced_locally
  let holderId = $state((holders.find((c) => c.role === 'holder') ?? holders[0])?.id ?? '');
  let aud = $state(settings.expectedAud ?? '');
  let nonce = $state(settings.expectedNonce ?? '');
  let error = $state<string | null>(null);
  let busy = $state(false);

  function claimLabel(d: (typeof disclosures)[number]): string {
    const name = d.claim ?? `Array element ${d.index + 1}`;
    return d.decoy ? `${name} (decoy)` : `${name}: ${d.value}`;
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    const kept = disclosures.filter((_, i) => keep[i]).map((d) => d.index);
    busy = true;
    error = null;
    try {
      if (action === 'present') {
        if (!holderId) return;
        await workspace.runAction(tabId, {
          action: 'present',
          keep: kept,
          holderKeyId: holderId,
          aud: aud || null,
          nonce: nonce || null,
        });
      } else {
        await workspace.runAction(tabId, { action: 'disclose', keep: kept });
      }
      onClose();
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={ACTION_LABELS[action]} {onClose}>
  <form onsubmit={submit}>
    {#if disclosures.length > 0}
      <fieldset>
        <legend>Disclosures to keep</legend>
        {#each disclosures as d, i (d.index)}
          <label class="check">
            <input type="checkbox" bind:checked={keep[i]} />
            <span class="mono">{claimLabel(d)}</span>
          </label>
        {/each}
      </fieldset>
    {:else}
      <p class="muted">No disclosures: the credential is presented as is.</p>
    {/if}
    {#if action === 'present'}
      <label class="field">
        <span>Holder key</span>
        <select bind:value={holderId}>
          {#each holders as c (c.id)}<option value={c.id}>{c.label}</option>{/each}
        </select>
      </label>
      <label class="field">
        <span>Audience</span>
        <input type="text" bind:value={aud} placeholder="https://verifier.example" />
      </label>
      <label class="field">
        <span>Nonce</span>
        <input type="text" bind:value={nonce} />
      </label>
      <p class="muted">iat is the validation clock (Settings).</p>
    {/if}
    {#if error}<p class="error" role="alert">{error}</p>{/if}
    <div class="buttons">
      <button type="submit" class="primary" disabled={busy || (action === 'present' && !holderId)}
        >{ACTION_LABELS[action]}</button
      >
      <button type="button" onclick={onClose}>Cancel</button>
    </div>
  </form>
</Dialog>
