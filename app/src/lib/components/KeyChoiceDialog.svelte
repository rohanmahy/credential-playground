<script lang="ts">
  // Pick one key (e.g. for Re-sign when several private keys exist).
  import type { KeyCard } from '../model';
  import Dialog from './Dialog.svelte';

  let {
    title,
    cards,
    submitLabel = title,
    onChoose,
    onClose,
  }: {
    title: string;
    cards: KeyCard[];
    submitLabel?: string;
    onChoose: (id: string) => void;
    onClose: () => void;
  } = $props();

  // svelte-ignore state_referenced_locally
  let chosen = $state(cards[0]?.id ?? '');
</script>

<Dialog {title} {onClose}>
  <form
    onsubmit={(e) => {
      e.preventDefault();
      if (chosen) onChoose(chosen);
    }}
  >
    <label class="field">
      <span>Key</span>
      <select bind:value={chosen}>
        {#each cards as c (c.id)}<option value={c.id}>{c.label}</option>{/each}
      </select>
    </label>
    <div class="buttons">
      <button type="submit" class="primary">{submitLabel}</button>
      <button type="button" onclick={onClose}>Cancel</button>
    </div>
  </form>
</Dialog>
