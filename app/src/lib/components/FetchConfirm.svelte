<script lang="ts">
  // Confirmation before any network request (role=alertdialog), with the URL
  // and the privacy note.
  let {
    url,
    onConfirm: _onConfirm,
    onCancel: _onCancel,
  }: { url: string; onConfirm: () => void; onCancel: () => void } = $props();
</script>

<div data-stub="FetchConfirm" data-url={url}></div>
