<script lang="ts">
  // One key card: description, role picker, kid (Auto kid), public/private,
  // provenance, JWK and COSE thumbprints; Export, Convert, Derive public.
  let { cardId }: { cardId: string } = $props();
</script>

<article data-stub="KeyCard" data-card-id={cardId}></article>
