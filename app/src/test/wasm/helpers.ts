// Shared by the wasm tests: the parity corpus (testdata/parity, written by
// `pnpm parity:regen` from the native engine) and the built module.
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fromB64u } from '../../lib/engine/bytes';

export const REPO = join(import.meta.dirname, '../../../..');
export const PKG = join(REPO, 'crates/tokenator-wasm/pkg');
export const WASM_FILE = join(PKG, 'tokenator_wasm_bg.wasm');
export const PARITY = join(REPO, 'testdata/parity');

export function wasmBytes(): Uint8Array<ArrayBuffer> {
  return new Uint8Array(readFileSync(WASM_FILE));
}

/** Every Engine method by its core (= binding) name; tools/parity METHODS. */
export const METHODS = [
  'info',
  'detect',
  'open',
  'render',
  'parse_edit',
  'convert_claims',
  'issue',
  'redact',
  'disclose',
  'present',
  'validate',
  'lint',
  'resign',
  'tamper',
  'reencode',
  'edit_disclosures',
  'decode_embedded',
  'key_import',
  'key_export',
  'key_public',
  'key_generate',
  'key_thumbprint',
  'key_assign_kid',
  'key_to_jwk',
  'key_to_cwk',
  'datetime',
  'registry_lookup',
  'registry_merge',
] as const;

export type Method = (typeof METHODS)[number];

/** `parse_edit` → `parseEdit` (the TS Engine method). */
export function camel(method: string): string {
  return method.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
}

export type Arg = { bytes: string } | { json: unknown };

export interface Case {
  method: Method;
  source: string;
  stack?: boolean;
  args: Arg[];
}

export type Golden = { text: string } | { sha256: string; len: number };

export interface CorpusEntry {
  id: string;
  case: Case;
  golden: Golden;
}

export function readCorpus(): CorpusEntry[] {
  const cases = readdirSync(join(PARITY, 'cases'))
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.slice(0, -'.json'.length))
    .sort();
  return cases.map((id) => {
    const c = JSON.parse(readFileSync(join(PARITY, 'cases', `${id}.json`), 'utf8')) as Case;
    let golden: Golden;
    try {
      golden = { text: readFileSync(join(PARITY, 'expected', `${id}.json`), 'utf8') };
    } catch {
      const [sha256 = '', len = '0'] = readFileSync(
        join(PARITY, 'expected', `${id}.sha256`),
        'utf8',
      )
        .trim()
        .split(/\s+/);
      golden = { sha256, len: Number(len) };
    }
    return { id, case: c, golden };
  });
}

/** The arguments a binding gets: Uint8Array for raw input, JSON text else. */
export function bindingArgs(c: Case): (Uint8Array | string)[] {
  return c.args.map((a) => ('bytes' in a ? fromB64u(a.bytes) : JSON.stringify(a.json)));
}

/** The arguments a WasmEngine method gets: Uint8Array or the DTO object. */
export function engineArgs(c: Case): unknown[] {
  return c.args.map((a) => ('bytes' in a ? fromB64u(a.bytes) : a.json));
}

export function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/** Why `out` is not byte-identical to `golden`, or null when it is. */
export function mismatch(out: string, golden: Golden): string | null {
  if ('sha256' in golden) {
    const len = Buffer.byteLength(out, 'utf8');
    if (len === golden.len && sha256(out) === golden.sha256) return null;
    return `digest differs (got ${len} bytes, expected ${golden.len}): ${out.slice(0, 200)}`;
  }
  if (out === golden.text) return null;
  let i = 0;
  while (i < out.length && out[i] === golden.text[i]) i++;
  const from = Math.max(0, i - 80);
  return (
    `differs at character ${i}\n  got:      …${out.slice(from, i + 80)}\n` +
    `  expected: …${golden.text.slice(from, i + 80)}`
  );
}

/** The parsed envelope of a text golden. */
export function envelope(golden: { text: string }): { ok: unknown } | { err: unknown } {
  return JSON.parse(golden.text) as { ok: unknown } | { err: unknown };
}
