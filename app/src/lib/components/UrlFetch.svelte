<script lang="ts">
  // A user-confirmed key fetch: confirm, fetch, import. On a CORS failure on
  // the web, explains why and offers pasting the content instead.
  import type { KeyCard } from '../model';
  import { getAppContext } from '../context';
  import { errorMessage } from '../ui';
  import FetchConfirm from './FetchConfirm.svelte';

  let {
    url,
    onImported,
    onClose,
  }: { url: string; onImported: (cards: KeyCard[]) => void; onClose: () => void } = $props();

  const { keys } = getAppContext();

  let asking = $state<{ url: string; resolve: (ok: boolean) => void } | null>(null);
  let phase = $state<'confirm' | 'fetching' | 'error' | 'paste'>('confirm');
  let explanation = $state('');
  let pasteFallback = $state(false);
  let pasted = $state('');

  // The first URL was confirmed in the dialog below; any further URL (a
  // jwks_uri in issuer metadata) is confirmed again.
  function confirmNext(next: string): Promise<boolean> {
    return new Promise((resolve) => (asking = { url: next, resolve }));
  }

  async function start() {
    phase = 'fetching';
    let first = true;
    const confirm = (u: string) => {
      if (first) {
        first = false;
        return Promise.resolve(true);
      }
      return confirmNext(u);
    };
    try {
      const { outcome, cards } = await keys.fetchFromUrl(url, confirm);
      if (outcome.type === 'error') {
        explanation = outcome.explanation;
        pasteFallback = outcome.pasteFallback;
        phase = 'error';
      } else if (outcome.type === 'cancelled') onClose();
      else onImported(cards);
    } catch (e) {
      explanation = errorMessage(e);
      pasteFallback = true;
      phase = 'error';
    }
  }

  async function importPasted(e: SubmitEvent) {
    e.preventDefault();
    try {
      onImported(await keys.importText(pasted));
    } catch (err) {
      explanation = errorMessage(err);
      phase = 'error';
    }
  }
</script>

{#if phase === 'confirm'}
  <FetchConfirm {url} onConfirm={start} onCancel={onClose} />
{:else if phase === 'fetching'}
  <p class="muted">Fetching {url}…</p>
{:else if phase === 'error'}
  <div class="error-box" role="alert">
    <p>{explanation}</p>
    <div class="buttons">
      {#if pasteFallback}
        <button type="button" onclick={() => (phase = 'paste')}>Paste instead</button>
      {/if}
      <button type="button" onclick={onClose}>Dismiss</button>
    </div>
  </div>
{:else}
  <form class="paste" onsubmit={importPasted}>
    <label class="field">
      <span>Paste the content of {url}</span>
      <textarea rows="5" bind:value={pasted}></textarea>
    </label>
    <div class="buttons">
      <button type="submit" class="primary" disabled={pasted.trim() === ''}>Import</button>
      <button type="button" onclick={onClose}>Cancel</button>
    </div>
  </form>
{/if}
{#if asking}
  {@const a = asking}
  <FetchConfirm
    url={a.url}
    onConfirm={() => {
      asking = null;
      a.resolve(true);
    }}
    onCancel={() => {
      asking = null;
      a.resolve(false);
    }}
  />
{/if}

<style>
  .error-box {
    border: 1px solid var(--fail);
    border-radius: 6px;
    padding: 0.5rem;
    margin: 0.5rem 0;
  }
  .error-box p {
    margin: 0 0 0.4rem;
  }
</style>
