<script lang="ts">
  // Date/time converter (SPEC §4.3). Opened from a time-valued node it
  // pre-fills; Insert writes the chosen form back in live edit.
  import type { NodeId } from '../engine/types';

  let {
    tabId = null,
    nodeId = null,
    onClose: _onClose,
  }: { tabId?: string | null; nodeId?: NodeId | null; onClose?: () => void } = $props();
</script>

<div data-stub="DateTimeChit" data-tab-id={tabId} data-node-id={nodeId}></div>
