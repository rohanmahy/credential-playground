<script lang="ts">
  // About box with the security and privacy notes (SPEC §9) and the engine
  // versions (SD-CWT draft revision, registry dates) from engine.info().
  let { onClose }: { onClose?: () => void } = $props();
</script>

<div role="dialog" aria-label="About" aria-modal="true">
  <h2>The Tokenator</h2>
  <h3>Security and privacy</h3>
  <ul>
    <li>Keys are held in page or process memory, unprotected. Use test keys only.</li>
    <li>
      RSA uses the pure-Rust <code>rsa</code> crate, which has a known timing side channel (RUSTSEC-2023-0071,
      "Marvin"). That's acceptable for a local playground, but not for production signing.
    </li>
    <li>A URL fetch reveals your IP address and the URL to that host.</li>
    <li>
      The web build sets a strict CSP. Script is loaded only from its own origin, and
      <code>connect-src</code> is limited to what user-initiated fetches need.
    </li>
  </ul>
  <!-- Stub: versions from engine.info() go here. -->
  <button type="button" onclick={() => onClose?.()}>Close</button>
</div>
