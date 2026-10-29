<script lang="ts">
  // JWK and CWK (EDN + hex) side by side, public or private.
  let { cardId }: { cardId: string } = $props();
</script>

<div data-stub="KeyConvertView" data-card-id={cardId}></div>
