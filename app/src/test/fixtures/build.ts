// Small builders that keep hand-written fixtures self-consistent: ranges are
// computed from the fixture text instead of typed in. Fixture texts are
// ASCII, so UTF-16 offsets equal byte offsets.
import type {
  Annotation,
  Node,
  NodeId,
  NodeKind,
  SdMark,
  TextRange,
  TimeHint,
} from '../../lib/engine/types';

export function lineOf(text: string, offset: number): number {
  let line = 0;
  for (let i = 0; i < offset && i < text.length; i++) if (text[i] === '\n') line++;
  return line;
}

/** A TextRange with its half-open line range. */
export function textRange(text: string, start: number, end: number): TextRange {
  const lineStart = lineOf(text, start);
  const lineEnd = end > start ? lineOf(text, end - 1) + 1 : lineStart;
  return { start, end, line_start: lineStart, line_end: lineEnd };
}

export function lineCount(text: string): number {
  return text.split('\n').length;
}

/** Offset of the start of line `n` (0-based). */
export function lineOffset(text: string, n: number): number {
  let offset = 0;
  for (let i = 0; i < n; i++) {
    const next = text.indexOf('\n', offset);
    if (next < 0) throw new Error(`no line ${n}`);
    offset = next + 1;
  }
  return offset;
}

/** The range of `needle` within line `line`. */
export function onLine(text: string, line: number, needle: string): [number, number] {
  const start = lineOffset(text, line);
  const end = text.indexOf('\n', start);
  const lineText = text.slice(start, end < 0 ? undefined : end);
  const at = lineText.indexOf(needle);
  if (at < 0) throw new Error(`"${needle}" not on line ${line}: ${lineText}`);
  return [start + at, start + at + needle.length];
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function asciiHex(text: string): string {
  return [...text].map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}

export interface NodeExtras {
  annotation?: Annotation;
  time?: TimeHint;
  sd?: SdMark;
}

export function bareNode(id: NodeId, kind: NodeKind, label: string): Node {
  return {
    id,
    kind,
    label,
    annotation: null,
    main: null,
    raw: null,
    key: null,
    time: null,
    sd: null,
    children: [],
  };
}

export function escapeSegment(name: string): string {
  return name.replace(/~/g, '~0').replace(/\//g, '~1');
}

export function childId(parent: NodeId, segment: string): NodeId {
  return parent === '' ? segment : `${parent}/${segment}`;
}

export const SPEC_LINK = (text: string, url: string) => ({ text, url });

export function annotation(
  name: string,
  description: string,
  spec: string,
  url: string,
  valueName: string | null = null,
): Annotation {
  return { name, description, value_name: valueName, spec: [{ text: spec, url }] };
}
