<script lang="ts">
  // Export a key: format, public (default) or private with an explicit
  // confirmation; Save to file or Copy (private copies are labelled).
  import type { Visibility } from '../engine/types';
  import { getAppContext } from '../context';
  import { EXPORT_FORMATS } from '../logic/keys';
  import { errorMessage } from '../ui';
  import Dialog from './Dialog.svelte';

  let { cardId, onClose }: { cardId: string; onClose?: () => void } = $props();

  const { keys } = getAppContext();
  const card = $derived(keys.get(cardId));

  let formatId = $state('jwk');
  let visibility = $state<Visibility>('public');
  let understood = $state(false);
  let status = $state('');
  let error = $state<string | null>(null);

  const format = $derived(
    EXPORT_FORMATS.find((f) => f.id === formatId)?.format ?? { type: 'jwk' as const },
  );
  const blocked = $derived(visibility === 'private' && !understood);

  async function copy() {
    if (blocked) return;
    error = null;
    try {
      status = await keys.copyToClipboard(cardId, format, visibility);
    } catch (e) {
      error = errorMessage(e);
    }
  }

  async function save() {
    if (blocked) return;
    error = null;
    try {
      const saved = await keys.saveToFile(cardId, format, visibility);
      status = saved ? `${visibility === 'private' ? 'Private' : 'Public'} key saved` : '';
    } catch (e) {
      error = errorMessage(e);
    }
  }
</script>

<Dialog title="Export key" onClose={() => onClose?.()}>
  {#if card}
    <p class="muted">{card.label}</p>
    <label class="field">
      <span>Format</span>
      <select bind:value={formatId}>
        {#each EXPORT_FORMATS as f (f.id)}<option value={f.id}>{f.label}</option>{/each}
      </select>
    </label>
    <fieldset>
      <legend>Key material</legend>
      <label class="check"
        ><input type="radio" name="visibility" value="public" bind:group={visibility} /> Public</label
      >
      <label class="check"
        ><input
          type="radio"
          name="visibility"
          value="private"
          bind:group={visibility}
          disabled={!card.info.private}
        /> Private</label
      >
      {#if visibility === 'private'}
        <label class="check warn">
          <input type="checkbox" bind:checked={understood} />
          I understand this exports the private key
        </label>
      {/if}
    </fieldset>
    <div class="buttons">
      <button type="button" class="primary" disabled={blocked} onclick={copy}
        >{visibility === 'private' ? 'Copy private key' : 'Copy public key'}</button
      >
      <button type="button" disabled={blocked} onclick={save}>Save…</button>
      <button type="button" onclick={() => onClose?.()}>Close</button>
    </div>
    <p role="status" class:warn={status.startsWith('Private')}>{status}</p>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
  {/if}
</Dialog>

<style>
  .warn {
    color: var(--warn);
  }
</style>
