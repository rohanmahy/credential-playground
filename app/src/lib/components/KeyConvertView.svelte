<script lang="ts">
  // JWK and CWK (EDN + hex) side by side, public or private.
  import { getAppContext } from '../context';
  import { fromB64u } from '../engine/bytes';
  import { errorMessage, hex } from '../ui';
  import Dialog from './Dialog.svelte';

  let { cardId, onClose }: { cardId: string; onClose?: () => void } = $props();

  const { keys } = getAppContext();
  const card = $derived(keys.get(cardId));

  let showPrivate = $state(false);
  let jwk = $state('');
  let edn = $state('');
  let cwkHex = $state('');
  let error = $state<string | null>(null);

  $effect(() => {
    const visibility = showPrivate ? 'private' : 'public';
    error = null;
    Promise.all([keys.toJwk(cardId, visibility), keys.toCwk(cardId, visibility)]).then(
      ([j, c]) => {
        jwk = j;
        edn = c.main.text;
        cwkHex = c.raw.type === 'hex' ? hex(fromB64u(c.raw.bytes)) : hex(fromB64u(c.bytes));
      },
      (e: unknown) => (error = errorMessage(e)),
    );
  });
</script>

<Dialog title="Convert key" wide onClose={() => onClose?.()}>
  {#if card}
    <p class="muted">{card.label}</p>
    <button
      type="button"
      role="switch"
      aria-checked={showPrivate}
      disabled={!card.info.private}
      onclick={() => (showPrivate = !showPrivate)}
      >{showPrivate ? 'Private (shown)' : 'Private'}</button
    >
    {#if showPrivate}<p class="warn">Showing private key material.</p>{/if}
    <div class="side">
      <section aria-label="JWK">
        <h3>JWK</h3>
        <pre class="mono">{jwk}</pre>
      </section>
      <section aria-label="COSE_Key">
        <h3>COSE_Key</h3>
        <pre class="mono">{edn}</pre>
        <h4>Hex</h4>
        <pre class="mono hex">{cwkHex}</pre>
      </section>
    </div>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
  {/if}
</Dialog>

<style>
  .side {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    gap: 1rem;
  }
  pre {
    white-space: pre-wrap;
    word-break: break-all;
    font-size: 0.8rem;
    margin: 0;
  }
  h3,
  h4 {
    font-size: 0.9rem;
    margin: 0.5rem 0 0.25rem;
  }
  .warn {
    color: var(--warn);
  }
</style>
