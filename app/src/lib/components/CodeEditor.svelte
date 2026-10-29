<script lang="ts">
  // CodeMirror 6 wrapper for live edit (lib/editor/setup.ts). `text` flows
  // in (e.g. a date/time Insert); the user's edits flow out via onChange.
  import { onMount } from 'svelte';
  import { EditorState } from '@codemirror/state';
  import { EditorView } from '@codemirror/view';
  import type { Language } from '../engine/types';
  import { editorExtensions, externalChange } from '../editor/setup';

  let {
    text,
    language,
    onChange,
  }: { text: string; language: Language; onChange: (text: string) => void } = $props();

  let host: HTMLDivElement | undefined = $state();
  let view: EditorView | undefined = $state();

  onMount(() => {
    if (!host) return;
    const v = new EditorView({
      parent: host,
      state: EditorState.create({
        doc: text,
        extensions: editorExtensions(language, (t) => onChange(t), false, 'Live edit text'),
      }),
    });
    view = v;
    return () => v.destroy();
  });

  $effect(() => {
    const next = text;
    if (view && view.state.doc.toString() !== next) {
      view.dispatch({
        changes: { from: 0, to: view.state.doc.length, insert: next },
        annotations: externalChange.of(true),
      });
    }
  });
</script>

<div bind:this={host} class="editor" data-testid="live-editor" data-language={language}></div>

<style>
  .editor {
    height: 100%;
    font-family: var(--mono);
    font-size: 0.85rem;
  }
  .editor :global(.cm-editor) {
    height: 100%;
  }
</style>
