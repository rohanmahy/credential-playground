// Builds JOSE Documents (core TEST-PLAN §3–§5): the compact token, the JSON
// view object as the main pane text, the node tree with `~e` decoded levels,
// and segments with base64url ranges for nested nodes.
import type { Document, Kind, Node, NodeId, RawRange, Segment } from '../../lib/engine/types';
import { textToB64u } from '../../lib/engine/bytes';
import { bareNode, childId, escapeSegment, lineCount, textRange, type NodeExtras } from './build';

export interface JoseSpec {
  kind: Kind;
  header: string;
  payload: string;
  signature: string;
  disclosures?: string[];
  kb?: { header: string; payload: string; signature: string };
  extras?: Record<NodeId, NodeExtras>;
}

// --- a tiny JSON scanner that keeps positions -----------------------------

interface JValue {
  kind: 'map' | 'array' | 'text' | 'number' | 'bool' | 'null';
  start: number;
  end: number;
  entries: { name: string | null; keyStart: number; keyEnd: number; value: JValue }[];
}

function scan(text: string): JValue {
  let i = 0;
  const ws = () => {
    while (i < text.length && /\s/.test(text[i] ?? '')) i++;
  };
  const str = (): [number, number] => {
    const start = i;
    i++;
    while (text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
    i++;
    return [start, i];
  };
  const value = (): JValue => {
    ws();
    const start = i;
    const c = text[i];
    if (c === '{' || c === '[') {
      const close = c === '{' ? '}' : ']';
      const entries: JValue['entries'] = [];
      i++;
      ws();
      while (text[i] !== close) {
        let name: string | null = null;
        let keyStart = -1;
        let keyEnd = -1;
        if (c === '{') {
          [keyStart, keyEnd] = str();
          name = JSON.parse(text.slice(keyStart, keyEnd)) as string;
          ws();
          i++; // ':'
        }
        const v = value();
        entries.push({ name, keyStart, keyEnd, value: v });
        ws();
        if (text[i] === ',') i++;
        ws();
      }
      i++;
      return { kind: c === '{' ? 'map' : 'array', start, end: i, entries };
    }
    if (c === '"') {
      const [s, e] = str();
      return { kind: 'text', start: s, end: e, entries: [] };
    }
    const m = /^(true|false|null|-?\d+(\.\d+)?([eE][+-]?\d+)?)/.exec(text.slice(i));
    if (!m) throw new Error(`bad JSON at ${i}: ${text.slice(i, i + 10)}`);
    i += m[0].length;
    const kind = m[0] === 'null' ? 'null' : m[0] === 'true' || m[0] === 'false' ? 'bool' : 'number';
    return { kind, start, end: i, entries: [] };
  };
  return value();
}

// --- tree building ----------------------------------------------------------

interface Seg {
  index: number;
  /** Offset of the segment in the token. */
  at: number;
  len: number;
}

/** core TEST-PLAN §5: decoded bytes a..b of a segment → base64url chars. */
function segRaw(seg: Seg, a: number, b: number): RawRange {
  return {
    start: seg.at + 4 * Math.floor(a / 3),
    end: seg.at + Math.min(4 * Math.ceil(b / 3), seg.len),
    row_start: seg.index,
    row_end: seg.index + 1,
  };
}

function jsonNode(
  view: string,
  v: JValue,
  id: NodeId,
  label: string,
  base: number,
  seg: Seg | null,
  partStart: number,
  extras: Record<NodeId, NodeExtras>,
): Node {
  const node = bareNode(id, v.kind, label);
  node.main = textRange(view, v.start, v.end);
  if (seg) node.raw = segRaw(seg, v.start - partStart, v.end - partStart);
  Object.assign(node, extras[id] ?? {});
  v.entries.forEach((e, n) => {
    const seg2 = e.name === null ? String(n) : escapeSegment(e.name);
    const child = jsonNode(
      view,
      e.value,
      childId(id, seg2),
      e.name ?? String(n),
      base,
      seg,
      partStart,
      extras,
    );
    if (e.name !== null) {
      const key = bareNode(`${child.id}/~k`, 'text', e.name);
      key.main = textRange(view, e.keyStart, e.keyEnd);
      if (seg) key.raw = segRaw(seg, e.keyStart - partStart, e.keyEnd - partStart);
      child.key = key;
    }
    node.children.push(child);
  });
  return node;
}

export function buildJose(spec: JoseSpec): Document {
  const extras = spec.extras ?? {};
  // token and segments
  const segTexts: { id: NodeId; label: string; text: string; sep: string | null }[] = [];
  const sd = spec.disclosures !== undefined;
  segTexts.push({
    id: 'protected',
    label: 'Protected header',
    text: textToB64u(spec.header),
    sep: '.',
  });
  segTexts.push({ id: 'payload', label: 'Payload', text: textToB64u(spec.payload), sep: '.' });
  segTexts.push({
    id: 'signature',
    label: 'Signature',
    text: spec.signature,
    sep: sd ? '~' : null,
  });
  (spec.disclosures ?? []).forEach((d, n) =>
    segTexts.push({
      id: `disclosures/${n}`,
      label: `Disclosure ${n}`,
      text: textToB64u(d),
      sep: '~',
    }),
  );
  if (spec.kb) {
    segTexts.push({
      id: 'kb/protected',
      label: 'KB-JWT protected header',
      text: textToB64u(spec.kb.header),
      sep: '.',
    });
    segTexts.push({
      id: 'kb/payload',
      label: 'KB-JWT payload',
      text: textToB64u(spec.kb.payload),
      sep: '.',
    });
    segTexts.push({
      id: 'kb/signature',
      label: 'KB-JWT signature',
      text: spec.kb.signature,
      sep: null,
    });
  }
  let token = '';
  const segments: Segment[] = segTexts.map((s) => {
    const start = token.length;
    token += s.text + (s.sep ?? '');
    return {
      node_id: s.id,
      label: s.label,
      range: { start, end: start + s.text.length },
      text: s.text,
      separator: s.sep,
    };
  });
  const segOf = (id: NodeId): Seg => {
    const index = segments.findIndex((s) => s.node_id === id);
    const s = segments[index];
    if (!s) throw new Error(id);
    return { index, at: s.range.start, len: s.text.length };
  };

  // the view object text, recording where each part's value starts
  const parts: { id: NodeId; at: number; text: string; decoded: boolean }[] = [];
  let view = '{\n';
  const put = (
    indent: string,
    name: string | null,
    id: NodeId,
    text: string,
    decoded: boolean,
    last: boolean,
  ) => {
    view += indent + (name === null ? '' : `"${name}": `);
    parts.push({ id, at: view.length, text, decoded });
    view += text + (last ? '\n' : ',\n');
  };
  const sig = (s: string) => `"${s}"`;
  const hasMore = sd || !!spec.kb;
  put('  ', 'protected', 'protected', spec.header, true, false);
  put('  ', 'payload', 'payload', spec.payload, true, false);
  put('  ', 'signature', 'signature', sig(spec.signature), false, !hasMore);
  let disclosuresStart = -1;
  let disclosuresEnd = -1;
  if (sd) {
    view += '  "disclosures": ';
    disclosuresStart = view.length;
    view += '[\n';
    const ds = spec.disclosures ?? [];
    ds.forEach((d, n) => put('    ', null, `disclosures/${n}`, d, true, n === ds.length - 1));
    disclosuresEnd = view.length + 3;
    view += spec.kb ? '  ],\n' : '  ]\n';
  }
  let kbStart = -1;
  let kbEnd = -1;
  if (spec.kb) {
    view += '  "kb": ';
    kbStart = view.length;
    view += '{\n';
    put('    ', 'protected', 'kb/protected', spec.kb.header, true, false);
    put('    ', 'payload', 'kb/payload', spec.kb.payload, true, false);
    put('    ', 'signature', 'kb/signature', sig(spec.kb.signature), false, true);
    kbEnd = view.length + 3;
    view += '  }\n';
  }
  view += '}';

  const partNode = (p: (typeof parts)[number], label: string): Node => {
    const seg = segOf(p.id);
    const node = bareNode(p.id, 'part', label);
    node.main = textRange(view, p.at, p.at + p.text.length);
    node.raw = {
      start: seg.at,
      end: seg.at + seg.len,
      row_start: seg.index,
      row_end: seg.index + 1,
    };
    Object.assign(node, extras[p.id] ?? {});
    if (p.decoded) {
      const v = scan(p.text);
      const shift = (x: JValue): JValue => ({
        ...x,
        start: x.start + p.at,
        end: x.end + p.at,
        entries: x.entries.map((e) => ({
          ...e,
          keyStart: e.keyStart + p.at,
          keyEnd: e.keyEnd + p.at,
          value: shift(e.value),
        })),
      });
      const decoded = jsonNode(view, shift(v), `${p.id}/~e`, 'decoded', p.at, seg, p.at, extras);
      decoded.kind = 'decoded';
      node.children.push(decoded);
    }
    return node;
  };

  const root = bareNode('', 'document', '');
  root.main = textRange(view, 0, view.length);
  const byId = (id: NodeId) => {
    const p = parts.find((x) => x.id === id);
    if (!p) throw new Error(id);
    return p;
  };
  root.children.push(partNode(byId('protected'), 'protected'));
  root.children.push(partNode(byId('payload'), 'payload'));
  root.children.push(partNode(byId('signature'), 'signature'));
  if (sd) {
    const list = bareNode('disclosures', 'array', 'disclosures');
    list.main = textRange(view, disclosuresStart, disclosuresEnd);
    (spec.disclosures ?? []).forEach((_, n) =>
      list.children.push(partNode(byId(`disclosures/${n}`), String(n))),
    );
    root.children.push(list);
  }
  if (spec.kb) {
    const kb = bareNode('kb', 'part', 'kb');
    kb.main = textRange(view, kbStart, kbEnd);
    kb.children.push(partNode(byId('kb/protected'), 'protected'));
    kb.children.push(partNode(byId('kb/payload'), 'payload'));
    kb.children.push(partNode(byId('kb/signature'), 'signature'));
    root.children.push(kb);
  }

  return {
    kind: spec.kind,
    layers: [],
    bytes: textToB64u(token),
    signed: true,
    signature_stale: false,
    tree: root,
    main: { language: 'json', text: view, line_count: lineCount(view) },
    raw: { type: 'segments', segments },
    disclosures: [],
    undisclosed: [],
    diagnostics: [],
  };
}

/** A JSON claim set: the text as is, a tree of its members, no raw pane. */
export function buildJsonClaims(text: string, extras: Record<NodeId, NodeExtras> = {}): Document {
  const tree = jsonNode(text, scan(text), '', '', 0, null, 0, extras);
  return {
    kind: { type: 'json_claims' },
    layers: [],
    bytes: textToB64u(text),
    signed: false,
    signature_stale: false,
    tree,
    main: { language: 'json', text, line_count: lineCount(text) },
    raw: { type: 'none' },
    disclosures: [],
    undisclosed: [],
    diagnostics: [],
  };
}
