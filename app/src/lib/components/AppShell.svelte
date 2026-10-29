<script lang="ts">
  // Layout: key panel docked left, credential tabs right (SPEC §4).
  import KeyPanel from './KeyPanel.svelte';
  import TabArea from './TabArea.svelte';
</script>

<div class="shell">
  <KeyPanel />
  <TabArea />
</div>

<style>
  .shell {
    display: grid;
    grid-template-columns: minmax(16rem, 22rem) 1fr;
    height: 100%;
  }
</style>
