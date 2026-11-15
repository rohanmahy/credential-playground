<script lang="ts">
  // One key area, Issuer or Holder (SPEC §4.2): Create, Import, Fetch from
  // URL; the key's text with a JWK / COSE_Key (EDN) toggle; Clear; then
  // the key's details (alg/kty, kid, public/private, provenance, JWK and
  // COSE thumbprints) with Export, Make public, and Auto kid. A paste or
  // drop into the empty text area runs key detection; typing parses the
  // text in the toggle's format.
  import { untrack } from 'svelte';
  import type { HashName, Thumbprint } from '../engine/types';
  import { getAppContext } from '../context';
  import { fromB64u } from '../engine/bytes';
  import { kidText } from '../logic/keys';
  import { provenanceLabel } from '../logic/provenance';
  import { KEY_ROLE_LABELS, type KeyRole } from '../model';
  import type { KeyTextFormat } from '../stores/keys.svelte';
  import {
    acceptDrag,
    droppedInput,
    errorMessage,
    hex,
    pastedInput,
    refuseDrop,
    uid,
    type AreaInput,
  } from '../ui';
  import Menu from './Menu.svelte';
  import KeyCreateDialog from './KeyCreateDialog.svelte';
  import KeyImportDialog from './KeyImportDialog.svelte';
  import KeyExportDialog from './KeyExportDialog.svelte';
  import KeySetChoiceDialog from './KeySetChoiceDialog.svelte';
  import UrlFetch from './UrlFetch.svelte';

  let { role }: { role: KeyRole } = $props();

  const { keys } = getAppContext();
  const name = $derived(KEY_ROLE_LABELS[role]);
  const area = $derived(keys.area(role));
  const card = $derived(keys.forRole(role));
  const empty = $derived(area.text.trim() === '');

  let dialog = $state<'create' | 'import' | 'export' | null>(null);
  let fetchOpen = $state(false);
  let url = $state('');
  let fetching = $state<string | null>(null);
  let urlInput: HTMLInputElement | undefined = $state();
  let busy = $state(false);
  let hash = $state<HashName>('sha256');
  let prints = $state<{ jwk: Thumbprint; cose: Thumbprint } | null>(null);
  let kidMenu = $state(false);
  let kidEditing = $state(false);
  let kidValue = $state('');
  let error = $state<string | null>(null);
  let cwkHex = $state('');
  const formatName = uid('key-format');

  // The card can change underneath the text (a test seeding it, an action):
  // re-render whenever it isn't the key the text shows.
  $effect(() => {
    const bytes = card?.info.key.bytes ?? null;
    if (bytes === untrack(() => area.shown)) return;
    untrack(() => {
      keys.renderText(role).catch((e: unknown) => (error = errorMessage(e)));
    });
  });

  // Thumbprints under another hash follow the key.
  $effect(() => {
    const h = hash;
    const bytes = card?.info.key.bytes;
    prints = null;
    if (!bytes || h === 'sha256') return;
    Promise.all([keys.thumbprint(role, 'jwk', h), keys.thumbprint(role, 'cose', h)]).then(
      ([jwk, cose]) => {
        if (keys.forRole(role)?.info.key.bytes === bytes) prints = { jwk, cose };
      },
      (e: unknown) => (error = errorMessage(e)),
    );
  });

  // A COSE_Key is also shown as hex (SPEC §4.2 Convert).
  $effect(() => {
    const bytes = card?.info.key.bytes;
    const isPrivate = card?.info.private ?? false;
    cwkHex = '';
    if (!bytes || area.format !== 'cose_key') return;
    keys.toCwk(role, isPrivate ? 'private' : 'public').then(
      (doc) => {
        if (keys.forRole(role)?.info.key.bytes === bytes) {
          cwkHex = hex(fromB64u(doc.raw.type === 'hex' ? doc.raw.bytes : doc.bytes));
        }
      },
      () => undefined,
    );
  });

  const jwkPrint = $derived(prints ? prints.jwk.base64url : card?.info.jwk_thumbprint);
  const cosePrint = $derived(prints ? prints.cose.hex : card?.info.cose_thumbprint);

  async function guard(task: () => Promise<unknown>) {
    error = null;
    busy = true;
    try {
      await task();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  /** Key detection on what was pasted or dropped into the empty area. */
  function detect(input: AreaInput | null) {
    if (input) void guard(() => keys.drop(role, input.bytes, input.provenance));
  }

  function onpaste(e: ClipboardEvent) {
    // Into text that's already there, a paste is just an edit.
    if (!empty) return;
    e.preventDefault();
    detect(pastedInput(e));
  }

  function ondragover(e: DragEvent) {
    if (empty) acceptDrag(e);
    else refuseDrop(e);
  }

  async function ondrop(e: DragEvent) {
    if (!empty) {
      refuseDrop(e);
      return;
    }
    acceptDrag(e);
    detect(await droppedInput(e.dataTransfer));
  }

  function setFormat(format: KeyTextFormat) {
    void guard(() => keys.setFormat(role, format));
  }

  function submitUrl(e: SubmitEvent) {
    e.preventDefault();
    const u = url.trim();
    if (u) fetching = u;
  }

  $effect(() => {
    if (fetchOpen) urlInput?.focus();
  });
</script>

<section class="area" aria-label={name}>
  <header>
    <h2>{name}</h2>
    <div class="buttons">
      <button type="button" onclick={() => (dialog = 'create')}>Create</button>
      <button type="button" onclick={() => (dialog = 'import')}>Import</button>
      <button type="button" aria-expanded={fetchOpen} onclick={() => (fetchOpen = !fetchOpen)}
        >Fetch from URL</button
      >
    </div>
  </header>
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
      {role}
      url={fetching}
      onDone={() => {
        fetching = null;
        fetchOpen = false;
        url = '';
      }}
      onClose={() => (fetching = null)}
    />
  {/if}
  <textarea
    class="mono key-text"
    class:has-error={area.error !== null}
    aria-label={name}
    aria-invalid={area.error !== null}
    aria-busy={busy}
    spellcheck="false"
    placeholder="Paste or drop a key (PEM, JWK, JWK Set, COSE_Key or COSE_KeySet), or type one in the format below"
    value={area.text}
    oninput={(e) => keys.edit(role, e.currentTarget.value)}
    {onpaste}
    {ondragover}
    {ondrop}></textarea>
  <div class="row">
    <div class="formats" role="radiogroup" aria-label="Key format">
      <label class="check"
        ><input
          type="radio"
          name={formatName}
          value="jwk"
          checked={area.format === 'jwk'}
          onchange={() => setFormat('jwk')}
        /> JWK</label
      >
      <label class="check"
        ><input
          type="radio"
          name={formatName}
          value="cose_key"
          checked={area.format === 'cose_key'}
          onchange={() => setFormat('cose_key')}
        /> COSE_Key</label
      >
    </div>
    <button
      type="button"
      onclick={() => {
        error = null;
        prints = null;
        keys.clear(role);
      }}>Clear</button
    >
  </div>
  {#if area.error}<p class="error" role="alert">{area.error}</p>{/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  {#if card}
    <div class="details">
      <p class="desc">
        <strong>{card.info.description}</strong>
        {#if card.info.alg}<span class="muted">· alg {card.info.alg}</span>{/if}
        <span class="muted">· kty {card.info.kty}</span>
        <span class="badge" class:private={card.info.private}
          >{card.info.private ? 'Private' : 'Public'}</span
        >
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
        {#if cwkHex}
          <dt>COSE_Key hex</dt>
          <dd class="mono print">{cwkHex}</dd>
        {/if}
      </dl>
      <label class="inline">
        <span>Thumbprint hash</span>
        <select bind:value={hash}>
          <option value="sha256">SHA-256</option>
          <option value="sha384">SHA-384</option>
          <option value="sha512">SHA-512</option>
        </select>
      </label>
      <div class="buttons">
        <button type="button" onclick={() => (dialog = 'export')}>Export</button>
        <button
          type="button"
          disabled={!card.info.private || busy}
          title={card.info.private ? 'Replace the key with its public part' : 'Already public'}
          onclick={() => void guard(() => keys.makePublic(role))}>Make public</button
        >
        <span class="anchor">
          <button
            type="button"
            aria-haspopup="menu"
            aria-expanded={kidMenu}
            onclick={() => (kidMenu = !kidMenu)}>Auto kid</button
          >
          {#if kidMenu}
            <Menu
              label="Auto kid"
              items={[
                {
                  label: 'JWK thumbprint',
                  action: () =>
                    void guard(() => keys.assignKid(role, { type: 'jwk_thumbprint', hash })),
                },
                {
                  label: 'COSE thumbprint',
                  action: () =>
                    void guard(() => keys.assignKid(role, { type: 'cose_thumbprint', hash })),
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
      </div>
      {#if kidEditing}
        <form
          class="kid-form"
          onsubmit={(e) => {
            e.preventDefault();
            kidEditing = false;
            void guard(() => keys.assignKid(role, { type: 'text', value: kidValue }));
          }}
        >
          <label class="field"
            ><span>kid text</span><input type="text" bind:value={kidValue} /></label
          >
          <button type="submit">Set</button>
          <button type="button" onclick={() => (kidEditing = false)}>Cancel</button>
        </form>
      {/if}
    </div>
  {/if}
</section>

{#if dialog === 'create'}
  <KeyCreateDialog {role} onClose={() => (dialog = null)} />
{:else if dialog === 'import'}
  <KeyImportDialog {role} onClose={() => (dialog = null)} />
{:else if dialog === 'export' && card}
  <KeyExportDialog cardId={role} onClose={() => (dialog = null)} />
{/if}
{#if area.choices}
  <KeySetChoiceDialog
    infos={area.choices.infos}
    onChoose={(i) => void guard(() => keys.choose(role, i))}
    onClose={() => keys.cancelChoice(role)}
  />
{/if}

<style>
  .area {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    min-height: 0;
    overflow: auto;
    padding: 0.5rem 0.75rem;
    font-size: 0.85rem;
  }
  /* The area scrolls; its parts keep their height. */
  .area > * {
    flex-shrink: 0;
  }
  header {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    justify-content: space-between;
    gap: 0.4rem;
  }
  h2 {
    font-size: 1rem;
    margin: 0;
  }
  .key-text {
    flex: 0 0 auto;
    min-height: 7rem;
    resize: vertical;
    font-size: 0.78rem;
  }
  .key-text.has-error {
    border-color: var(--fail);
  }
  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
  }
  .formats {
    display: flex;
    gap: 0.75rem;
  }
  .fetch {
    display: flex;
    align-items: end;
    gap: 0.4rem;
  }
  .fetch .field {
    flex: 1;
  }
  .small {
    font-size: 0.8rem;
    margin: 0;
  }
  .desc {
    margin: 0.2rem 0;
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
  .buttons {
    margin-top: 0.3rem;
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
    margin: 0;
  }
</style>
