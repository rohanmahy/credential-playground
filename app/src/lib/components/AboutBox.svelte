<script lang="ts">
  // About box with the security and privacy notes (SPEC §9) and the engine
  // versions (SD-CWT draft revision, registry dates) from engine.info().
  import { onMount } from 'svelte';
  import type { EngineInfo } from '../engine/types';
  import { getAppContext } from '../context';
  import { errorMessage } from '../ui';
  import Dialog from './Dialog.svelte';

  let { onClose }: { onClose?: () => void } = $props();

  const { engine } = getAppContext();
  let info = $state<EngineInfo | null>(null);
  let error = $state<string | null>(null);

  onMount(() => {
    engine.info().then(
      (i) => (info = i),
      (e: unknown) => (error = errorMessage(e)),
    );
  });
</script>

<Dialog title="About" onClose={() => onClose?.()}>
  <h3>The Tokenator</h3>
  <p>A local-only playground for JWT, SD-JWT, CWT, and SD-CWT credentials and their keys.</p>
  <h3>Security and privacy</h3>
  <ul>
    <li>Keys are held in page or process memory, unprotected. Use test keys only.</li>
    <li>
      RSA uses the pure-Rust <code>rsa</code> crate, which has a known timing side channel (RUSTSEC-2023-0071,
      "Marvin"). That's acceptable for a local playground, but not for production signing.
    </li>
    <li>A URL fetch reveals your IP address and the URL to that host.</li>
    <li>
      The web build sets a strict CSP. Script is loaded only from its own origin, and
      <code>connect-src</code> is limited to what user-initiated fetches need.
    </li>
    <li>Nothing is stored except refreshed IANA registry data, which is public.</li>
  </ul>
  <h3>Versions</h3>
  {#if info}
    <dl>
      <dt>Engine</dt>
      <dd>{info.version}</dd>
      <dt>SD-CWT draft</dt>
      <dd>{info.sd_cwt_revision}</dd>
      {#each Object.entries(info.registry_updated) as [name, date] (name)}
        <dt>{name.toUpperCase()} registry</dt>
        <dd>{date}</dd>
      {/each}
    </dl>
  {:else if error}
    <p class="muted">Engine information unavailable: {error}</p>
  {:else}
    <p class="muted">Loading…</p>
  {/if}
  <div class="buttons"><button type="button" onclick={() => onClose?.()}>Close</button></div>
</Dialog>

<style>
  h3 {
    font-size: 0.95rem;
    margin: 0.75rem 0 0.25rem;
  }
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.2rem 1rem;
    margin: 0;
  }
  dd {
    margin: 0;
  }
</style>
