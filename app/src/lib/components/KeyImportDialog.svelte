<script lang="ts">
  // Import keys from a paste, a file, or the clipboard.
  import type { KeyCard } from '../model';
  import { getAppContext } from '../context';
  import { errorMessage } from '../ui';
  import Dialog from './Dialog.svelte';

  let { onClose }: { onClose?: () => void } = $props();

  const { keys } = getAppContext();
  let text = $state('');
  let error = $state<string | null>(null);
  let busy = $state(false);

  const close = () => onClose?.();

  async function run(task: () => Promise<KeyCard[]>) {
    busy = true;
    error = null;
    try {
      const cards = await task();
      if (cards.length > 0) close();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title="Import key" onClose={close}>
  <form
    onsubmit={(e) => {
      e.preventDefault();
      void run(() => keys.importText(text));
    }}
  >
    <label class="field">
      <span>Key</span>
      <textarea
        rows="7"
        class="mono"
        bind:value={text}
        placeholder="PEM, JWK, JWK Set, COSE_Key or COSE_KeySet (hex, base64, or EDN)"></textarea>
    </label>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
    <div class="buttons">
      <button type="submit" class="primary" disabled={busy || text.trim() === ''}>Import</button>
      <button type="button" disabled={busy} onclick={() => run(() => keys.importFromClipboard())}
        >From clipboard</button
      >
      <button type="button" disabled={busy} onclick={() => run(() => keys.importFromFile())}
        >From file…</button
      >
    </div>
  </form>
</Dialog>
