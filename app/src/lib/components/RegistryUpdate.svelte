<script lang="ts">
  // "Update registries": a confirmed fetch of the four IANA registries,
  // merged by the engine and cached for the next start.
  import { getAppContext } from '../context';
  import { FETCH_PRIVACY_NOTE } from '../logic/fetch';
  import { IANA_REGISTRIES, updateRegistries } from '../logic/registry';
  import { errorMessage } from '../ui';
  import Dialog from './Dialog.svelte';

  const { engine, platform } = getAppContext();

  let asking = $state<((ok: boolean) => void) | null>(null);
  let status = $state('');
  let busy = $state(false);

  async function update() {
    busy = true;
    status = '';
    try {
      const result = await updateRegistries(
        engine,
        platform,
        () => new Promise<boolean>((resolve) => (asking = resolve)),
      );
      if (result.type === 'updated') {
        const added = result.stats.reduce((n, s) => n + s.stats.added + s.stats.updated, 0);
        status = `Registries updated (${added} entries added or changed). Reload the app to use them.`;
      } else if (result.type === 'error') status = result.explanation;
    } catch (e) {
      status = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function clear() {
    await platform.registryCache.clear();
    status = 'Cached registries removed. Reload the app to use the bundled snapshot.';
  }

  function answer(ok: boolean) {
    asking?.(ok);
    asking = null;
  }
</script>

<div class="buttons">
  <button type="button" disabled={busy} onclick={update}>Update registries</button>
  <button type="button" disabled={busy} onclick={clear}>Use the bundled registries</button>
</div>
{#if status}<p class="muted" aria-live="polite">{status}</p>{/if}
{#if asking}
  <Dialog title="Fetch the IANA registries?" role="alertdialog" onClose={() => answer(false)}>
    <ul class="mono">
      {#each IANA_REGISTRIES as r (r.which)}<li>{r.url}</li>{/each}
    </ul>
    <p>{FETCH_PRIVACY_NOTE} The merged registries are the only data the app stores.</p>
    <div class="buttons">
      <button type="button" class="primary" onclick={() => answer(true)}>Fetch</button>
      <button type="button" onclick={() => answer(false)}>Cancel</button>
    </div>
  </Dialog>
{/if}
