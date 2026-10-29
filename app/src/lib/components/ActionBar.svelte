<script lang="ts">
  // role=toolbar with every action; disabled ones stay focusable
  // (aria-disabled) and explain what is missing in their title.
  import type { TamperOp } from '../engine/types';
  import { ACTION_IDS, type ActionId } from '../model';
  import { getAppContext } from '../context';
  import { ACTION_LABELS, actionTooltip, reencodeChoices } from '../logic/actions';
  import { kindFamily } from '../logic/kinds';
  import { fromB64u } from '../engine/bytes';
  import type { ActionRequest } from '../stores/workspace.svelte';
  import { errorMessage, type MenuItem } from '../ui';
  import Menu from './Menu.svelte';
  import IssueDialog from './IssueDialog.svelte';
  import PresentDialog from './PresentDialog.svelte';
  import EditDisclosuresDialog from './EditDisclosuresDialog.svelte';
  import KeyChoiceDialog from './KeyChoiceDialog.svelte';

  let { tabId }: { tabId: string } = $props();

  const { workspace, keys } = getAppContext();
  const tab = $derived(workspace.tab(tabId));
  const availability = $derived(tab ? workspace.availability(tabId) : null);

  let open = $state<ActionId | null>(null);
  let menu = $state<'reencode' | 'tamper' | null>(null);
  let error = $state<string | null>(null);
  let busy = $state(false);
  let focusIndex = $state(0);
  let toolbar: HTMLDivElement | undefined = $state();

  const privateKeys = $derived(keys.cards.filter((c) => c.info.private));

  async function run(req: ActionRequest) {
    error = null;
    busy = true;
    try {
      await workspace.runAction(tabId, req);
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function validate() {
    error = null;
    try {
      await workspace.validate(tabId);
    } catch (e) {
      error = errorMessage(e);
    }
  }

  function click(id: ActionId) {
    if (!availability?.[id].enabled) return;
    switch (id) {
      case 'validate':
        void validate();
        break;
      case 'resign':
        if (privateKeys.length === 1 && privateKeys[0]) {
          void run({ action: 'resign', keyId: privateKeys[0].id });
        } else open = 'resign';
        break;
      case 'reencode':
      case 'tamper':
        menu = menu === id ? null : id;
        break;
      default:
        open = id;
    }
  }

  function onkeydown(e: KeyboardEvent) {
    const buttons = toolbar
      ? [...toolbar.querySelectorAll<HTMLElement>(':scope > .slot > button')]
      : [];
    const at = buttons.indexOf(document.activeElement as HTMLElement);
    if (at < 0) return;
    let next: number;
    if (e.key === 'ArrowRight') next = (at + 1) % buttons.length;
    else if (e.key === 'ArrowLeft') next = (at - 1 + buttons.length) % buttons.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = buttons.length - 1;
    else return;
    e.preventDefault();
    focusIndex = next;
    buttons[next]?.focus();
  }

  function tamperItems(): MenuItem[] {
    if (!tab) return [];
    const doc = tab.doc;
    const cose = kindFamily(doc.kind) === 'cose';
    const op = (o: TamperOp) => () => void run({ action: 'tamper', op: o });
    const len = fromB64u(doc.bytes).length;
    const items: MenuItem[] = [
      {
        label: 'Flip a signature bit',
        action: op({ type: 'flip_bit', part: { type: 'signature' }, bit: 0 }),
      },
      {
        label: 'Flip a payload bit',
        action: op({ type: 'flip_bit', part: { type: 'payload' }, bit: 7 }),
      },
      {
        label: 'Flip a protected header bit',
        action: op({ type: 'flip_bit', part: { type: 'protected' }, bit: 7 }),
      },
      cose
        ? { label: 'Set alg to ES384 (-35)', action: op({ type: 'set_alg', alg: -35 }) }
        : { label: 'Set alg to none', action: op({ type: 'set_alg', alg: 'none' }) },
      cose
        ? { label: 'Remove alg', action: op({ type: 'remove_alg' }) }
        : { label: 'Set alg to HS256', action: op({ type: 'set_alg', alg: 'HS256' }) },
      { label: 'Strip the signature', action: op({ type: 'strip_signature' }) },
      {
        label: 'Change kid',
        action: op({ type: 'set_kid', kid: { type: 'text', value: 'tampered' } }),
      },
      { label: 'Remove kid', action: op({ type: 'set_kid', kid: null }) },
      {
        label: 'Truncate (drop the last byte)',
        disabled: len < 2,
        action: op({ type: 'truncate', len: Math.max(0, len - 1) }),
      },
    ];
    if (doc.disclosures.length > 0) {
      items.push({
        label: 'Duplicate the first disclosure',
        action: op({ type: 'duplicate_disclosure', index: 0 }),
      });
    }
    if (cose) {
      items.push(
        {
          label: 'Re-encode protected header (wide bstr head)',
          action: op({ type: 'reencode_protected', how: 'wide_bstr_head' }),
        },
        {
          label: 'Re-encode protected header (wide integers)',
          action: op({ type: 'reencode_protected', how: 'wide_integers' }),
        },
        {
          label: 'Re-encode protected header (indefinite map)',
          action: op({ type: 'reencode_protected', how: 'indefinite_map' }),
        },
        { label: 'Drop the CBOR tags', action: op({ type: 'set_tags', tags: [] }) },
        { label: 'Tag as CWT (61, 18)', action: op({ type: 'set_tags', tags: [61, 18] }) },
      );
    } else {
      items.push({
        label: 'Re-format the protected header',
        action: op({ type: 'reencode_protected', how: 'auto' }),
      });
    }
    return items;
  }

  function reencodeItems(): MenuItem[] {
    if (!tab) return [];
    return reencodeChoices(tab.doc).map((c) => ({
      label: c.label,
      action: () =>
        void run(
          c.cbor
            ? { action: 'reencode', cbor: c.cbor }
            : { action: 'reencode', jose: c.jose ?? null },
        ),
    }));
  }
</script>

{#if tab && availability}
  <div
    bind:this={toolbar}
    class="actions"
    role="toolbar"
    aria-label="Actions"
    aria-busy={busy}
    tabindex="-1"
    {onkeydown}
  >
    {#each ACTION_IDS as id, i (id)}
      {@const a = availability[id]}
      <span class="slot">
        <button
          type="button"
          aria-disabled={a.enabled ? 'false' : 'true'}
          aria-haspopup={id === 'reencode' || id === 'tamper' ? 'menu' : undefined}
          aria-expanded={id === 'reencode' || id === 'tamper' ? menu === id : undefined}
          title={actionTooltip(id, a)}
          tabindex={i === focusIndex ? 0 : -1}
          onclick={() => click(id)}>{ACTION_LABELS[id]}</button
        >
        {#if menu === id && (id === 'reencode' || id === 'tamper')}
          <Menu
            label={ACTION_LABELS[id]}
            items={id === 'reencode' ? reencodeItems() : tamperItems()}
            onClose={() => (menu = null)}
          />
        {/if}
      </span>
    {/each}
  </div>
  {#if error}<p class="error" role="alert">{error}</p>{/if}

  {#if open === 'issue' || open === 'redact'}
    <IssueDialog {tabId} action={open} onClose={() => (open = null)} />
  {:else if open === 'present' || open === 'disclose'}
    <PresentDialog {tabId} action={open} onClose={() => (open = null)} />
  {:else if open === 'edit_disclosures'}
    <EditDisclosuresDialog {tabId} onClose={() => (open = null)} />
  {:else if open === 'resign'}
    <KeyChoiceDialog
      title="Re-sign"
      cards={privateKeys}
      onChoose={(keyId) => {
        open = null;
        void run({ action: 'resign', keyId });
      }}
      onClose={() => (open = null)}
    />
  {/if}
{/if}

<style>
  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: 0.25rem;
  }
  .slot {
    position: relative;
  }
  button[aria-disabled='true'] {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .error {
    color: var(--fail);
    margin: 0.25rem 0;
  }
</style>
