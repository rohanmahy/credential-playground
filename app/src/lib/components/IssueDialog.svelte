<script lang="ts">
  // Issue / Redact: issuer key, alg, serialization (JOSE) or CBOR tags
  // (COSE), header options, and an optional holder key for `cnf`.
  import type { HeaderOptions, JoseSerialization } from '../engine/types';
  import { getAppContext } from '../context';
  import { ACTION_LABELS, canIssueWith } from '../logic/actions';
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
  const issuers = $derived(keys.cards.filter((c) => c.info.private && canIssueWith(c)));

  const TAGS: Record<string, number[] | null> = {
    '18': [18],
    '61,18': [61, 18],
    none: [],
  };

  // svelte-ignore state_referenced_locally
  let issuerId = $state((issuers.find((c) => c.role === 'issuer') ?? issuers[0])?.id ?? '');
  let alg = $state('');
  let serialization = $state<JoseSerialization>('compact');
  let tags = $state('18');
  let holderId = $state('');
  let typ = $state<'auto' | 'omit'>('auto');
  let kid = $state<'from_key' | 'none'>('from_key');
  let error = $state<string | null>(null);
  let busy = $state(false);

  const algs = $derived(keys.get(issuerId)?.info.algs ?? []);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!issuerId) return;
    const header: HeaderOptions = {
      typ: { type: typ },
      kid: { type: kid },
    };
    busy = true;
    error = null;
    try {
      await workspace.runAction(tabId, {
        action,
        issuerKeyId: issuerId,
        holderKeyId: holderId || null,
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
    <label class="field">
      <span>Issuer key</span>
      <select bind:value={issuerId}>
        {#each issuers as c (c.id)}<option value={c.id}>{c.label}</option>{/each}
      </select>
    </label>
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
    <label class="field">
      <span>Holder key (cnf)</span>
      <select bind:value={holderId}>
        <option value="">None</option>
        {#each keys.cards as c (c.id)}<option value={c.id}>{c.label}</option>{/each}
      </select>
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
      <button type="submit" class="primary" disabled={busy || !issuerId}
        >{ACTION_LABELS[action]}</button
      >
      <button type="button" onclick={onClose}>Cancel</button>
    </div>
  </form>
</Dialog>
