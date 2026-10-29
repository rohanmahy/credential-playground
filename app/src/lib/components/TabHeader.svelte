<script lang="ts">
  // Detected type, Detected as…, unwrapping breadcrumb, provenance
  // breadcrumb, validation badge, Read-only / Live edit switch, actions,
  // and the "modified – signature stale" banner.
  let { tabId }: { tabId: string } = $props();
</script>

<header data-stub="TabHeader" data-tab-id={tabId}></header>
