<script lang="ts">
  // Create a key into a key area: algorithm (KEY_SPECS), randomness
  // (random, well-known test seed, or a user seed), auto kid. The area is
  // the role.
  import type { KidSource } from '../engine/types';
  import { KEY_ROLE_LABELS, type KeyRole } from '../model';
  import { getAppContext } from '../context';
  import { KEY_SPECS } from '../logic/keys';
  import type { SeedChoice } from '../stores/keys.svelte';
  import { errorMessage } from '../ui';
  import Dialog from './Dialog.svelte';

  let { role, onClose }: { role: KeyRole; onClose?: () => void } = $props();

  const { keys } = getAppContext();

  let specIndex = $state(0);
  let seedType = $state<SeedChoice['type']>('random');
  let seed = $state('');
  let kid = $state<'none' | 'jwk' | 'cose'>('none');
  let busy = $state(false);
  let error = $state<string | null>(null);

  const close = () => onClose?.();

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    const spec = KEY_SPECS[specIndex]?.spec;
    if (!spec) return;
    const seedChoice: SeedChoice =
      seedType === 'text' ? { type: 'text', seed } : { type: seedType };
    const kidSource: KidSource | null =
      kid === 'jwk'
        ? { type: 'jwk_thumbprint', hash: 'sha256' }
        : kid === 'cose'
          ? { type: 'cose_thumbprint', hash: 'sha256' }
          : null;
    busy = true;
    error = null;
    try {
      await keys.generate(role, spec, { seed: seedChoice, kid: kidSource });
      close();
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title="Create key" onClose={close}>
  <p class="muted small">Fills the {KEY_ROLE_LABELS[role]} area.</p>
  <form onsubmit={submit}>
    <label class="field">
      <span>Algorithm</span>
      <select bind:value={specIndex}>
        {#each KEY_SPECS as k, i (k.label)}<option value={i}>{k.label}</option>{/each}
      </select>
    </label>
    <fieldset>
      <legend>Randomness</legend>
      <label class="check"
        ><input type="radio" name="seed" value="random" bind:group={seedType} /> Random</label
      >
      <label class="check"
        ><input type="radio" name="seed" value="well_known" bind:group={seedType} /> Well-known test seed</label
      >
      <label class="check"
        ><input type="radio" name="seed" value="text" bind:group={seedType} /> From a seed</label
      >
      <label class="field">
        <span>Seed</span>
        <input type="text" bind:value={seed} disabled={seedType !== 'text'} />
      </label>
      {#if seedType !== 'random'}
        <p class="muted small">
          Deterministic: the same seed always gives the same key. Test use only.
        </p>
      {/if}
    </fieldset>
    <label class="field">
      <span>kid</span>
      <select bind:value={kid}>
        <option value="none">None</option>
        <option value="jwk">JWK thumbprint</option>
        <option value="cose">COSE thumbprint</option>
      </select>
    </label>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
    <div class="buttons">
      <button type="submit" class="primary" disabled={busy}>Create</button>
      <button type="button" onclick={close}>Cancel</button>
    </div>
  </form>
</Dialog>

<style>
  .small {
    font-size: 0.8rem;
  }
</style>
