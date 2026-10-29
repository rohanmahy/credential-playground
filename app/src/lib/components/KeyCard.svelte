<script lang="ts">
  // One key card: description, role picker, kid (Auto kid), public/private,
  // provenance, JWK and COSE thumbprints; Export, Convert, Derive public.
  import type { HashName, Role, Thumbprint } from '../engine/types';
  import { getAppContext } from '../context';
  import { kidText } from '../logic/keys';
  import { provenanceLabel } from '../logic/provenance';
  import { errorMessage, uid } from '../ui';
  import Menu from './Menu.svelte';
  import KeyExportDialog from './KeyExportDialog.svelte';
  import KeyConvertView from './KeyConvertView.svelte';

  let { cardId }: { cardId: string } = $props();

  const { keys } = getAppContext();
  const card = $derived(keys.get(cardId));

  let hash = $state<HashName>('sha256');
  let prints = $state<{ jwk: Thumbprint; cose: Thumbprint } | null>(null);
  let kidMenu = $state(false);
  let kidEditing = $state(false);
  let kidValue = $state('');
  let open = $state<'export' | 'convert' | null>(null);
  let error = $state<string | null>(null);
  const titleId = uid('key-title');

  const jwkPrint = $derived(
    prints && hash !== 'sha256' ? prints.jwk.base64url : card?.info.jwk_thumbprint,
  );
  const cosePrint = $derived(
    prints && hash !== 'sha256' ? prints.cose.hex : card?.info.cose_thumbprint,
  );

  async function changeHash(next: HashName) {
    hash = next;
    error = null;
    if (next === 'sha256') {
      prints = null;
      return;
    }
    try {
      const [jwk, cose] = await Promise.all([
        keys.thumbprint(cardId, 'jwk', next),
        keys.thumbprint(cardId, 'cose', next),
      ]);
      prints = { jwk, cose };
    } catch (e) {
      error = errorMessage(e);
    }
  }

  async function guard(task: () => Promise<unknown>) {
    error = null;
    try {
      await task();
    } catch (e) {
      error = errorMessage(e);
    }
  }

  function setRole(value: string) {
    keys.setRole(cardId, value === '' ? null : (value as Role));
  }
</script>

{#if card}
  <article class="card" aria-labelledby={titleId}>
    <header>
      <h3 id={titleId}>{card.label}</h3>
      <span class="badge" class:private={card.info.private}
        >{card.info.private ? 'Private' : 'Public'}</span
      >
    </header>
    <p class="desc">
      {card.info.description}
      {#if card.info.alg}<span class="muted">· alg {card.info.alg}</span>{/if}
    </p>
    <dl>
      <dt>kid</dt>
      <dd class="mono kid" data-testid="kid">{kidText(card.info.kid) || '(none)'}</dd>
      <dt>From</dt>
      <dd>{provenanceLabel(card.provenance, (id) => keys.get(id)?.label ?? id)}</dd>
      <dt title={prints?.jwk.uri ?? card.info.jwk_thumbprint_uri}>JWK thumbprint</dt>
      <dd class="mono print">{jwkPrint}</dd>
      <dt title={prints?.cose.uri ?? card.info.cose_thumbprint_uri}>COSE thumbprint</dt>
      <dd class="mono print">{cosePrint}</dd>
    </dl>
    <div class="controls">
      <label class="inline">
        <span>Role</span>
        <select value={card.role ?? ''} onchange={(e) => setRole(e.currentTarget.value)}>
          <option value="">none</option>
          <option value="issuer">issuer</option>
          <option value="holder">holder</option>
          <option value="verifier">verifier</option>
        </select>
      </label>
      <label class="inline">
        <span>Thumbprint hash</span>
        <select value={hash} onchange={(e) => void changeHash(e.currentTarget.value as HashName)}>
          <option value="sha256">SHA-256</option>
          <option value="sha384">SHA-384</option>
          <option value="sha512">SHA-512</option>
        </select>
      </label>
    </div>
    <div class="buttons">
      <button type="button" onclick={() => (open = 'export')}>Export</button>
      <button type="button" onclick={() => (open = 'convert')}>Convert</button>
      <span class="anchor">
        <button
          type="button"
          aria-haspopup="menu"
          aria-expanded={kidMenu}
          onclick={() => (kidMenu = !kidMenu)}>Set kid</button
        >
        {#if kidMenu}
          <Menu
            label="Set kid"
            items={[
              {
                label: 'JWK thumbprint',
                action: () =>
                  void guard(() => keys.assignKid(cardId, { type: 'jwk_thumbprint', hash })),
              },
              {
                label: 'COSE thumbprint',
                action: () =>
                  void guard(() => keys.assignKid(cardId, { type: 'cose_thumbprint', hash })),
              },
              {
                label: 'Text…',
                action: () => {
                  kidValue = kidText(card.info.kid);
                  kidEditing = true;
                },
              },
            ]}
            onClose={() => (kidMenu = false)}
          />
        {/if}
      </span>
      {#if card.info.private}
        <button type="button" onclick={() => void guard(() => keys.derivePublic(cardId))}
          >Derive public key</button
        >
      {/if}
      <button
        type="button"
        class="icon"
        aria-label={`Remove ${card.label}`}
        onclick={() => keys.remove(cardId)}>×</button
      >
    </div>
    {#if kidEditing}
      <form
        class="kid-form"
        onsubmit={(e) => {
          e.preventDefault();
          kidEditing = false;
          void guard(() => keys.assignKid(cardId, { type: 'text', value: kidValue }));
        }}
      >
        <label class="field"><span>kid text</span><input type="text" bind:value={kidValue} /></label
        >
        <button type="submit">Set</button>
        <button type="button" onclick={() => (kidEditing = false)}>Cancel</button>
      </form>
    {/if}
    {#if error}<p class="error" role="alert">{error}</p>{/if}
  </article>
  {#if open === 'export'}
    <KeyExportDialog {cardId} onClose={() => (open = null)} />
  {:else if open === 'convert'}
    <KeyConvertView {cardId} onClose={() => (open = null)} />
  {/if}
{/if}

<style>
  .card {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.5rem 0.6rem;
    font-size: 0.85rem;
  }
  header {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: 0.5rem;
  }
  h3 {
    font-size: 0.95rem;
    margin: 0;
  }
  .badge {
    font-size: 0.75rem;
    padding: 0 0.4rem;
    border-radius: 999px;
    border: 1px solid var(--border);
  }
  .badge.private {
    color: var(--warn);
    border-color: currentColor;
  }
  .desc {
    margin: 0.2rem 0;
  }
  dl {
    display: grid;
    grid-template-columns: max-content minmax(0, 1fr);
    gap: 0.1rem 0.5rem;
    margin: 0.3rem 0;
  }
  dt {
    color: var(--muted);
  }
  dd {
    margin: 0;
    overflow-wrap: anywhere;
  }
  .print {
    font-size: 0.75rem;
  }
  .controls {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin: 0.3rem 0;
  }
  .anchor {
    position: relative;
  }
  .kid-form {
    display: flex;
    align-items: end;
    gap: 0.4rem;
    margin-top: 0.4rem;
  }
  .error {
    color: var(--fail);
    margin: 0.3rem 0 0;
  }
</style>
