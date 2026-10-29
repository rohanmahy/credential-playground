<script lang="ts">
  // The checklist (SPEC §6) grouped by category, with links to NodeIds and
  // user-confirmed fetch offers.
  import type { FetchHint, NodeId, ValidationReport } from '../engine/types';

  let {
    report,
    onSelectNode: _onSelectNode,
    onFetch: _onFetch,
  }: {
    report: ValidationReport;
    onSelectNode: (id: NodeId) => void;
    onFetch?: (hint: FetchHint) => void;
  } = $props();
</script>

<div data-stub="ValidationReport" data-overall={report.overall}></div>
