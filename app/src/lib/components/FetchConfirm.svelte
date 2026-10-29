<script lang="ts">
  // Confirmation before any network request (role=alertdialog), with the URL
  // and the privacy note.
  import { FETCH_PRIVACY_NOTE } from '../logic/fetch';
  import Dialog from './Dialog.svelte';

  let { url, onConfirm, onCancel }: { url: string; onConfirm: () => void; onCancel: () => void } =
    $props();
</script>

<Dialog title="Fetch this URL?" role="alertdialog" onClose={onCancel}>
  <p class="url mono">{url}</p>
  <p>{FETCH_PRIVACY_NOTE} Nothing else is sent.</p>
  <div class="buttons">
    <button type="button" class="primary" onclick={onConfirm}>Fetch</button>
    <button type="button" onclick={onCancel}>Cancel</button>
  </div>
</Dialog>

<style>
  .url {
    word-break: break-all;
  }
</style>
