import { describe, expect, it } from 'vitest';
import { StringStream } from '@codemirror/language';
import { ednStreamParser } from '../../lib/editor/edn';

function tokens(line: string): [string, string | null][] {
  const state = ednStreamParser.startState();
  const stream = new StringStream(line, 2, 2);
  const out: [string, string | null][] = [];
  while (!stream.eol()) {
    const style = ednStreamParser.token(stream, state);
    const text = stream.current();
    if (text.trim()) out.push([text, style]);
    stream.start = stream.pos;
  }
  return out;
}

describe('EDN stream mode (stub)', () => {
  it('highlights comments, app-strings, numbers, and indicators', () => {
    const t = tokens(`/ kid / 4: h'4173', 1_1: -7.5`);
    expect(t).toContainEqual(['/ kid /', 'comment']);
    expect(t).toContainEqual(["h'4173'", 'string.special']);
    expect(t).toContainEqual(['-7.5', 'number']);
    expect(t).toContainEqual(['_1', 'meta']);
  });

  it('highlights strings and simple values', () => {
    const t = tokens(`"a\\"b": true, simple(59)`);
    expect(t).toContainEqual(['"a\\"b"', 'string']);
    expect(t).toContainEqual(['true', 'atom']);
    expect(t).toContainEqual(['simple', 'atom']);
  });
});
