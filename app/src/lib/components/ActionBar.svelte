<script lang="ts">
  // role=toolbar with every action; disabled ones stay focusable
  // (aria-disabled) and explain what is missing in their title.
  let { tabId }: { tabId: string } = $props();
</script>

<div data-stub="ActionBar" data-tab-id={tabId}></div>
