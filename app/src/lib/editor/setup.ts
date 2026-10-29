// CodeMirror extensions for the live-edit main pane.
import { EditorState, type Extension } from '@codemirror/state';
import { EditorView, keymap, lineNumbers, highlightActiveLine } from '@codemirror/view';
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
import { foldGutter, syntaxHighlighting, defaultHighlightStyle } from '@codemirror/language';
import { json } from '@codemirror/lang-json';
import type { Language } from '../engine/types';
import { ednLanguage } from './edn';

export function editorExtensions(
  language: Language,
  onChange: (text: string) => void,
  readOnly = false,
): Extension[] {
  return [
    lineNumbers(),
    foldGutter(),
    history(),
    highlightActiveLine(),
    syntaxHighlighting(defaultHighlightStyle),
    keymap.of([...defaultKeymap, ...historyKeymap]),
    language === 'json' ? json() : ednLanguage(),
    EditorState.readOnly.of(readOnly),
    EditorView.updateListener.of((u) => {
      if (u.docChanged) onChange(u.state.doc.toString());
    }),
  ];
}
