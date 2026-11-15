<script lang="ts">
  // Key panel (SPEC §4.2): split vertically into the Issuer key area and
  // the Holder key area. The area a key sits in is its role.
  import { KEY_ROLES } from '../model';
  import KeyArea from './KeyArea.svelte';
</script>

<aside class="keys" aria-label="Keys">
  {#each KEY_ROLES as role (role)}
    <KeyArea {role} />
  {/each}
</aside>

<style>
  .keys {
    display: grid;
    grid-template-rows: minmax(0, 1fr) minmax(0, 1fr);
    min-height: 0;
    border-right: 1px solid var(--border);
  }
  .keys > :global(* + *) {
    border-top: 2px solid var(--border);
  }
</style>
