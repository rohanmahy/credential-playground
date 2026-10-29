<script lang="ts">
  // CodeMirror 6 wrapper for live edit (lib/editor/setup.ts).
  import type { Language } from '../engine/types';

  let {
    text,
    language,
    onChange: _onChange,
  }: { text: string; language: Language; onChange: (text: string) => void } = $props();
</script>

<div data-stub="CodeEditor" data-language={language} data-length={text.length}></div>
