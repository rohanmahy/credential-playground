<script lang="ts">
  // Validation clock, skew, key-binding expectations, view toggles, theme.
  // In memory only.
  import { getAppContext } from '../context';
  import type { Theme } from '../stores/settings.svelte';
  import Dialog from './Dialog.svelte';

  let { onClose }: { onClose: () => void } = $props();

  const { settings, workspace } = getAppContext();

  let clock = $state(settings.clockOverride === null ? '' : String(settings.clockOverride));

  function applyClock() {
    const t = clock.trim();
    const n = Number(t);
    settings.clockOverride = t === '' || !Number.isFinite(n) ? null : n;
  }

  function view(update: () => void) {
    update();
    void workspace.rerenderAll();
  }
</script>

<Dialog title="Settings" {onClose}>
  <fieldset>
    <legend>Validation</legend>
    <label class="field">
      <span>Clock (epoch seconds, empty for now)</span>
      <input type="text" class="mono" bind:value={clock} onchange={applyClock} />
    </label>
    <label class="field">
      <span>Allowed skew (seconds)</span>
      <input type="number" min="0" bind:value={settings.skew} />
    </label>
    <label class="field">
      <span>Expected audience</span>
      <input
        type="text"
        value={settings.expectedAud ?? ''}
        onchange={(e) => (settings.expectedAud = e.currentTarget.value || null)}
      />
    </label>
    <label class="field">
      <span>Expected nonce</span>
      <input
        type="text"
        value={settings.expectedNonce ?? ''}
        onchange={(e) => (settings.expectedNonce = e.currentTarget.value || null)}
      />
    </label>
  </fieldset>
  <fieldset>
    <legend>View</legend>
    <label class="check"
      ><input
        type="checkbox"
        checked={settings.decodedViews}
        onchange={(e) => view(() => (settings.decodedViews = e.currentTarget.checked))}
      /> Decoded views of embedded CBOR and JSON</label
    >
    <label class="check"
      ><input
        type="checkbox"
        checked={settings.annotations}
        onchange={(e) => view(() => (settings.annotations = e.currentTarget.checked))}
      /> Registry annotations</label
    >
    <label class="check"
      ><input
        type="checkbox"
        checked={settings.jsonPretty}
        onchange={(e) => view(() => (settings.jsonPretty = e.currentTarget.checked))}
      /> Re-indent decoded JSON</label
    >
    <label class="check"
      ><input type="checkbox" bind:checked={settings.showRaw} /> Show raw pane</label
    >
    <label class="field">
      <span>Theme</span>
      <select
        value={settings.theme}
        onchange={(e) => (settings.theme = e.currentTarget.value as Theme)}
      >
        <option value="system">Follow the system</option>
        <option value="light">Light</option>
        <option value="dark">Dark</option>
      </select>
    </label>
  </fieldset>
  <div class="buttons"><button type="button" onclick={onClose}>Close</button></div>
</Dialog>
