<script lang="ts">
  // Main pane: read-only line tree (role=tree) over Document.main.text with
  // folding, annotations, and time hints; CodeMirror in live edit.
  let { tabId }: { tabId: string } = $props();
</script>

<div data-stub="MainPane" data-tab-id={tabId}></div>
