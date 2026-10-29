<script lang="ts">
  // Key panel (SPEC §4.2): key cards with role, kid, thumbprints, provenance;
  // Create, Import (paste/file/clipboard), Fetch from URL (confirmed).
  import { getAppContext } from '../context';
  import KeyCard from './KeyCard.svelte';
  import KeyCreateDialog from './KeyCreateDialog.svelte';
  import KeyImportDialog from './KeyImportDialog.svelte';
  import UrlFetch from './UrlFetch.svelte';

  const { keys } = getAppContext();

  let dialog = $state<'create' | 'import' | null>(null);
  let fetchOpen = $state(false);
  let url = $state('');
  let fetching = $state<string | null>(null);
  let urlInput: HTMLInputElement | undefined = $state();

  function submitUrl(e: SubmitEvent) {
    e.preventDefault();
    const u = url.trim();
    if (u) fetching = u;
  }

  $effect(() => {
    if (fetchOpen) urlInput?.focus();
  });
</script>

<aside class="keys" aria-label="Keys">
  <header>
    <h2>Keys</h2>
    <div class="buttons">
      <button type="button" onclick={() => (dialog = 'create')}>Create key</button>
      <button type="button" onclick={() => (dialog = 'import')}>Import key</button>
      <button type="button" aria-expanded={fetchOpen} onclick={() => (fetchOpen = !fetchOpen)}
        >Fetch from URL</button
      >
    </div>
    {#if fetchOpen}
      <form class="fetch" onsubmit={submitUrl}>
        <label class="field">
          <span>URL</span>
          <input
            bind:this={urlInput}
            type="url"
            bind:value={url}
            placeholder="https://issuer.example/.well-known/jwks.json"
          />
        </label>
        <button type="submit" disabled={url.trim() === ''}>Fetch</button>
      </form>
      <p class="muted small">
        JWK Set, COSE_KeySet, or /.well-known/jwt-vc-issuer metadata. You confirm before anything is
        fetched.
      </p>
    {/if}
    {#if fetching}
      <UrlFetch
        url={fetching}
        onImported={() => {
          fetching = null;
          fetchOpen = false;
          url = '';
        }}
        onClose={() => (fetching = null)}
      />
    {/if}
  </header>
  {#if keys.cards.length === 0}
    <p class="muted empty">No keys yet. Create one, import one, or paste one into the input.</p>
  {/if}
  <div class="cards">
    {#each keys.cards as card (card.id)}
      <KeyCard cardId={card.id} />
    {/each}
  </div>
</aside>

{#if dialog === 'create'}
  <KeyCreateDialog onClose={() => (dialog = null)} />
{:else if dialog === 'import'}
  <KeyImportDialog onClose={() => (dialog = null)} />
{/if}

<style>
  .keys {
    display: flex;
    flex-direction: column;
    min-height: 0;
    overflow: auto;
    border-right: 1px solid var(--border);
    padding: 0.5rem 0.75rem;
  }
  h2 {
    font-size: 1rem;
    margin: 0 0 0.4rem;
  }
  .fetch {
    display: flex;
    align-items: end;
    gap: 0.4rem;
    margin-top: 0.5rem;
  }
  .fetch .field {
    flex: 1;
  }
  .small {
    font-size: 0.8rem;
  }
  .cards {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
    margin-top: 0.6rem;
  }
  .empty {
    font-size: 0.85rem;
  }
</style>
