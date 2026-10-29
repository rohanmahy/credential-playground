<script lang="ts">
  // Export a key: format, public (default) or private with an explicit
  // confirmation; Save to file or Copy (private copies are labelled).
  let { cardId, onClose: _onClose }: { cardId: string; onClose?: () => void } = $props();
</script>

<div data-stub="KeyExportDialog" data-card-id={cardId}></div>
