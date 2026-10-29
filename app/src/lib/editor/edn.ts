// A minimal CodeMirror stream mode for CBOR EDN (draft-ietf-cbor-edn-literals).
// Stub: it highlights comments, strings, app-string literals (h'', b64'',
// dt'', …), numbers, simple values, and encoding indicators. Folding and
// autocomplete from the registry come later.
import { StreamLanguage, type StringStream } from '@codemirror/language';

interface EdnState {
  /** Inside a `/ … /` block comment. */
  inComment: boolean;
}

function token(stream: StringStream, state: EdnState): string | null {
  if (state.inComment) {
    if (stream.skipTo('/')) {
      stream.next();
      state.inComment = false;
    } else {
      stream.skipToEnd();
    }
    return 'comment';
  }
  if (stream.eatSpace()) return null;
  if (stream.match('#')) {
    stream.skipToEnd();
    return 'comment';
  }
  if (stream.eat('/')) {
    state.inComment = true;
    return token(stream, state) ?? 'comment';
  }
  if (stream.match(/^[a-zA-Z][a-zA-Z0-9]*'/)) {
    while (!stream.eol()) {
      const ch = stream.next();
      if (ch === '\\') stream.next();
      else if (ch === "'") break;
    }
    return 'string.special';
  }
  if (stream.eat('"') || stream.eat("'")) {
    const quote = stream.current();
    while (!stream.eol()) {
      const ch = stream.next();
      if (ch === '\\') stream.next();
      else if (ch === quote) break;
    }
    return 'string';
  }
  if (stream.match(/^_[0-3i]?/)) return 'meta';
  if (stream.match(/^-?(0x[0-9a-fA-F]+|0o[0-7]+|0b[01]+|\d+(\.\d+)?([eE][+-]?\d+)?)/)) {
    return 'number';
  }
  if (stream.match(/^(true|false|null|undefined|simple|NaN|-?Infinity)\b/)) return 'atom';
  stream.next();
  return 'punctuation';
}

export const ednStreamParser = {
  name: 'edn',
  startState: (): EdnState => ({ inComment: false }),
  token,
  copyState: (s: EdnState): EdnState => ({ ...s }),
};

export function ednLanguage(): StreamLanguage<EdnState> {
  return StreamLanguage.define(ednStreamParser);
}
