// CodeMirror extensions for the live-edit main pane.
import { Annotation, EditorState, type Extension } from '@codemirror/state';
import { EditorView, keymap, lineNumbers, highlightActiveLine } from '@codemirror/view';
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
import { foldGutter, syntaxHighlighting, defaultHighlightStyle } from '@codemirror/language';
import { json } from '@codemirror/lang-json';
import type { Language } from '../engine/types';
import { ednLanguage } from './edn';

/** Marks changes the app makes itself (not reported through onChange). */
export const externalChange = Annotation.define<boolean>();

export function editorExtensions(
  language: Language,
  onChange: (text: string) => void,
  readOnly = false,
  label = 'Editor',
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
    EditorView.contentAttributes.of({ 'aria-label': label }),
    EditorView.updateListener.of((u) => {
      if (u.docChanged && !u.transactions.some((tr) => tr.annotation(externalChange))) {
        onChange(u.state.doc.toString());
      }
    }),
  ];
}
