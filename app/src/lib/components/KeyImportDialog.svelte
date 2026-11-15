<script lang="ts">
  // Import a key into a key area from a paste, a file, or the clipboard.
  // Key detection runs on the input; a set goes through "Choose a key".
  import { getAppContext } from '../context';
  import { KEY_ROLE_LABELS, type KeyRole } from '../model';
  import { errorMessage } from '../ui';
  import Dialog from './Dialog.svelte';

  let { role, onClose }: { role: KeyRole; onClose?: () => void } = $props();

  const { keys } = getAppContext();
  let text = $state('');
  let error = $state<string | null>(null);
  let busy = $state(false);

  const close = () => onClose?.();

  /** `task` resolves false when the user cancelled (no file chosen). */
  async function run(task: () => Promise<unknown>) {
    busy = true;
    error = null;
    try {
      if ((await task()) !== false) close();
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
      void run(() => keys.importText(role, text));
    }}
  >
    <p class="muted small">Fills the {KEY_ROLE_LABELS[role]} area.</p>
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
      <button
        type="button"
        disabled={busy}
        onclick={() => run(() => keys.importFromClipboard(role))}>From clipboard</button
      >
      <button type="button" disabled={busy} onclick={() => run(() => keys.importFromFile(role))}
        >From file…</button
      >
    </div>
  </form>
</Dialog>

<style>
  .small {
    font-size: 0.8rem;
  }
</style>
