<script lang="ts">
  // Issue / Redact with the Issuer area's key: alg, serialization (JOSE) or
  // CBOR tags (COSE), header options, and optionally the Holder area's key
  // as `cnf`.
  import type { HeaderOptions, JoseSerialization } from '../engine/types';
  import { getAppContext } from '../context';
  import { ACTION_LABELS } from '../logic/actions';
  import { kindFamily } from '../logic/kinds';
  import { errorMessage } from '../ui';
  import Dialog from './Dialog.svelte';

  let {
    tabId,
    action,
    onClose,
  }: { tabId: string; action: 'issue' | 'redact'; onClose: () => void } = $props();

  const { workspace, keys } = getAppContext();
  const tab = $derived(workspace.tab(tabId));
  const cose = $derived(tab ? kindFamily(tab.doc.kind) === 'cose' : false);
  const issuer = $derived(keys.issuer);

  const TAGS: Record<string, number[] | null> = {
    '18': [18],
    '61,18': [61, 18],
    none: [],
  };

  let alg = $state('');
  let serialization = $state<JoseSerialization>('compact');
  let tags = $state('18');
  let cnf = $state(false);
  let typ = $state<'auto' | 'omit'>('auto');
  let kid = $state<'from_key' | 'none'>('from_key');
  let error = $state<string | null>(null);
  let busy = $state(false);

  const algs = $derived(issuer?.info.algs ?? []);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!issuer) return;
    const header: HeaderOptions = {
      typ: { type: typ },
      kid: { type: kid },
    };
    busy = true;
    error = null;
    try {
      await workspace.runAction(tabId, {
        action,
        cnf: cnf && keys.holder !== null,
        alg: alg || null,
        header,
        jose: serialization,
        coseTags: cose ? (TAGS[tags] ?? null) : null,
      });
      onClose();
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={ACTION_LABELS[action]} {onClose}>
  <form onsubmit={submit}>
    <p class="muted">
      Signed with the Issuer key{issuer ? `: ${issuer.info.description}` : ' (none)'}.
    </p>
    <label class="field">
      <span>Algorithm</span>
      <select bind:value={alg}>
        <option value="">Default for the key</option>
        {#each algs as a (a)}<option value={a}>{a}</option>{/each}
      </select>
    </label>
    {#if cose}
      <label class="field">
        <span>CBOR tags</span>
        <select bind:value={tags}>
          <option value="18">18 (COSE_Sign1)</option>
          <option value="61,18">61, 18 (CWT)</option>
          <option value="none">Untagged</option>
        </select>
      </label>
    {:else}
      <label class="field">
        <span>Serialization</span>
        <select bind:value={serialization}>
          <option value="compact">Compact</option>
          <option value="json_flattened">JSON (flattened)</option>
          <option value="json_general">JSON (general)</option>
        </select>
      </label>
    {/if}
    <label class="check">
      <input type="checkbox" bind:checked={cnf} disabled={!keys.holder} />
      Holder key (cnf)
    </label>
    <label class="field">
      <span>typ</span>
      <select bind:value={typ}>
        <option value="auto">Automatic</option>
        <option value="omit">Omit</option>
      </select>
    </label>
    <label class="field">
      <span>kid header</span>
      <select bind:value={kid}>
        <option value="from_key">From the key</option>
        <option value="none">None</option>
      </select>
    </label>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
    <div class="buttons">
      <button type="submit" class="primary" disabled={busy || !issuer}
        >{ACTION_LABELS[action]}</button
      >
      <button type="button" onclick={onClose}>Cancel</button>
    </div>
  </form>
</Dialog>
