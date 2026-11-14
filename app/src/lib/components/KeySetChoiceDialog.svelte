<script lang="ts">
  // "Choose a key": a JWK Set or COSE_KeySet went into a key area, which
  // holds one key. One button per key (kid, alg, kty); the pick fills it.
  import type { KeyInfo } from '../engine/types';
  import { kidText } from '../logic/keys';
  import Dialog from './Dialog.svelte';

  let {
    infos,
    onChoose,
    onClose,
  }: {
    infos: KeyInfo[];
    onChoose: (index: number) => void;
    onClose: () => void;
  } = $props();
</script>

<Dialog title="Choose a key" {onClose}>
  <p class="muted">The input holds {infos.length} keys. The area takes one.</p>
  <ul class="keys">
    {#each infos as info, i (i)}
      <li>
        <button type="button" onclick={() => onChoose(i)}>
          <span class="mono">kid {kidText(info.kid) || '(none)'}</span>
          <span>· alg {info.alg ?? '(none)'}</span>
          <span>· kty {info.kty}</span>
          <span class="muted">· {info.description}{info.private ? ', private' : ''}</span>
        </button>
      </li>
    {/each}
  </ul>
  <div class="buttons">
    <button type="button" onclick={onClose}>Cancel</button>
  </div>
</Dialog>

<style>
  .keys {
    list-style: none;
    margin: 0 0 0.5rem;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
  }
  .keys button {
    width: 100%;
    text-align: left;
  }
</style>
