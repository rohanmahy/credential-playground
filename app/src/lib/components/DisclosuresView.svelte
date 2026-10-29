<script lang="ts">
  // SD view: disclosures with digest, salt, claim, value, status, and a link
  // to the slot they fill; undisclosed digests (decoys / withheld).
  let { tabId }: { tabId: string } = $props();
</script>

<div data-stub="DisclosuresView" data-tab-id={tabId}></div>
