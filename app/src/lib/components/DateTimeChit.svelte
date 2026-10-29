<script lang="ts">
  // Date/time converter (SPEC §4.3). Opened from a time-valued node it
  // pre-fills; Insert writes the chosen form back in live edit.
  import { onMount } from 'svelte';
  import type { DateFormKind, DateTimeForms, DateTimeInput, NodeId } from '../engine/types';
  import { getAppContext } from '../context';
  import { findNode } from '../logic/tree';
  import { errorMessage } from '../ui';
  import Dialog from './Dialog.svelte';

  let {
    tabId = null,
    nodeId = null,
    onClose,
  }: { tabId?: string | null; nodeId?: NodeId | null; onClose?: () => void } = $props();

  const { engine, settings, platform, workspace } = getAppContext();
  const tab = $derived(tabId ? workspace.tab(tabId) : undefined);
  const node = $derived(tab && nodeId !== null ? findNode(tab.doc.tree, nodeId) : null);

  const FORM_LABELS: Record<DateFormKind, string> = {
    epoch: 'NumericDate',
    tag1: 'Tag 1 (epoch)',
    rfc3339: 'RFC 3339 text',
    tag0: 'Tag 0 (RFC 3339)',
    tag100: 'Tag 100 (days)',
    tag1004: 'Tag 1004 (date)',
    dt: "dt''",
    dt_tagged: "DT'' (tag 1)",
  };

  let forms = $state<DateTimeForms | null>(null);
  let error = $state<string | null>(null);
  let fields = $state({ epoch: '', millis: '', utc: '', local: '' });
  let chosen = $state<DateFormKind | null>(null);
  let message = $state<string | null>(null);

  const canInsert = $derived(!!tab && !!node?.main && tab.liveEdit && chosen !== null);

  async function convert(input: DateTimeInput) {
    error = null;
    try {
      const now = settings.now();
      const result = await engine.datetime({
        input,
        now,
        local_offset_minutes: platform.localOffsetMinutes(now),
      });
      forms = result;
      fields = {
        epoch: result.epoch,
        millis: String(result.millis),
        utc: result.rfc3339_utc,
        local: result.rfc3339_local,
      };
    } catch (e) {
      error = errorMessage(e);
    }
  }

  function initialInput(): DateTimeInput {
    if (tab && node) {
      if (node.time) return { type: 'epoch', text: String(node.time.epoch) };
      if (node.main) {
        const text = tab.doc.main.text.slice(node.main.start, node.main.end);
        if (/^-?\d+(\.\d+)?$/.test(text)) return { type: 'epoch', text };
        return { type: 'edn', text };
      }
    }
    return { type: 'epoch', text: String(settings.now()) };
  }

  onMount(() => {
    void convert(initialInput());
  });

  type Field = keyof typeof fields;

  function shown(field: Field): string {
    if (!forms) return '';
    return {
      epoch: forms.epoch,
      millis: String(forms.millis),
      utc: forms.rfc3339_utc,
      local: forms.rfc3339_local,
    }[field];
  }

  /** Enter always converts; a change (blur) only when the text differs. */
  function apply(field: Field, force = false) {
    const value = fields[field].trim();
    if (value === '' || (!force && value === shown(field))) return;
    switch (field) {
      case 'epoch':
        void convert({ type: 'epoch', text: value });
        break;
      case 'millis': {
        const millis = Number(value);
        if (Number.isFinite(millis)) void convert({ type: 'millis', millis });
        else error = 'Milliseconds must be a number';
        break;
      }
      case 'utc':
      case 'local':
        void convert({ type: 'rfc3339', text: value });
        break;
    }
  }

  function onkey(field: Field) {
    return (e: KeyboardEvent) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        apply(field, true);
      }
    };
  }

  async function insert() {
    if (!tab || !tabId || !node?.main || !forms || chosen === null) return;
    const form = forms.forms.find((f) => f.form === chosen);
    if (!form) return;
    const base = tab.doc.main.text;
    const text = base.slice(0, node.main.start) + form.edn + base.slice(node.main.end);
    const result = await workspace.applyEdit(tabId, text);
    message = result.ok ? `Inserted ${form.edn}` : 'The inserted form did not parse';
  }

  function useAsClock() {
    if (!forms) return;
    const epoch = Number(forms.epoch);
    if (Number.isFinite(epoch)) {
      settings.clockOverride = epoch;
      message = `Validation clock set to ${forms.rfc3339_utc}`;
    }
  }

  const FIELDS: { id: Field; label: string }[] = [
    { id: 'epoch', label: 'Epoch seconds' },
    { id: 'millis', label: 'Milliseconds' },
    { id: 'utc', label: 'RFC 3339 (UTC)' },
    { id: 'local', label: 'RFC 3339 (local)' },
  ];
</script>

<Dialog title="Date/time" modal={false} onClose={() => onClose?.()}>
  <div class="fields">
    {#each FIELDS as f (f.id)}
      <label class="field">
        <span>{f.label}</span>
        <input
          type="text"
          class="mono"
          bind:value={fields[f.id]}
          onkeydown={onkey(f.id)}
          onchange={() => apply(f.id)}
        />
      </label>
    {/each}
  </div>
  <p class="relative">
    Relative to the clock: <span data-testid="relative">{forms?.relative ?? '–'}</span>
  </p>
  {#if error}<p class="error">{error}</p>{/if}
  {#if forms}
    <fieldset>
      <legend>CBOR forms</legend>
      {#each forms.forms as f (f.form)}
        <label class="form">
          <input type="radio" name="dt-form" value={f.form} bind:group={chosen} />
          <code>{f.edn}</code>
          <span class="muted">{FORM_LABELS[f.form]}</span>
          <code class="hex">{f.cbor_hex}</code>
        </label>
      {/each}
    </fieldset>
  {/if}
  <div class="buttons">
    <button
      type="button"
      disabled={!canInsert}
      title={canInsert
        ? 'Write the chosen form into the node'
        : 'Open from a node in Live edit and choose a form'}
      onclick={insert}>Insert</button
    >
    <button type="button" disabled={!forms} onclick={useAsClock}>Use as clock</button>
  </div>
  {#if message}<p class="muted" aria-live="polite">{message}</p>{/if}
</Dialog>

<style>
  .fields {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.4rem 0.75rem;
  }
  .form {
    display: grid;
    grid-template-columns: auto minmax(10rem, max-content) 1fr auto;
    gap: 0.5rem;
    align-items: baseline;
    font-size: 0.85rem;
  }
  .hex {
    color: var(--muted);
  }
  .relative {
    margin: 0.5rem 0;
  }
</style>
