// TauriEngine over a mocked IPC (app/src-tauri/TEST-PLAN.md): every Engine
// method invokes `engine_<snake_name>` with the core parameter names, raw
// input crosses as base64url, `engine_init` runs once first, and failures
// reject with EngineFailure.
import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { type Engine, EngineFailure } from '../../lib/engine/Engine';
import { TauriEngine } from '../../lib/engine/TauriEngine';
import { toB64u } from '../../lib/engine/bytes';
import { defaultViewOptions } from '../../lib/engine/defaults';
import type { Candidate, EngineError } from '../../lib/engine/types';
import * as fx from '../fixtures';
import { hexToBytes } from '../fixtures/build';

interface Call {
  cmd: string;
  args: unknown;
}

let calls: Call[] = [];
/** Per-command responses; a function may throw to reject. */
let respond: Record<string, (args: unknown) => unknown> = {};

beforeEach(() => {
  calls = [];
  respond = {};
  mockIPC((cmd, args) => {
    calls.push({ cmd, args });
    const handler = respond[cmd];
    if (handler) return handler(args);
    return cmd === 'engine_init' ? null : { from: cmd };
  });
});

afterEach(() => clearMocks());

/** The calls after `engine_init`. */
const engineCalls = () => calls.filter((c) => c.cmd !== 'engine_init');

const bytes = Uint8Array.of(0xd2, 0x84, 0xfb, 0xff);
const view = defaultViewOptions();
const candidate = fx.jwtCandidates[0] as Candidate;
const docRef = { kind: fx.jwt.kind, bytes: fx.jwt.bytes };
const keyRef = fx.issuerInfo.key;

// Request DTOs are passed through untouched, so any object stands in.
const req = (name: string) => ({ marker: name }) as never;

type Case = { call: (e: Engine) => Promise<unknown>; cmd: string; args: unknown };

// A Record over keyof Engine: adding an Engine method without a case fails
// typechecking.
const CASES: Record<keyof Engine, Case> = {
  info: { call: (e) => e.info(), cmd: 'engine_info', args: {} },
  detect: { call: (e) => e.detect(bytes), cmd: 'engine_detect', args: { input: '0oT7_w' } },
  open: {
    call: (e) => e.open(bytes, candidate, view),
    cmd: 'engine_open',
    args: { input: '0oT7_w', candidate, view },
  },
  render: {
    call: (e) => e.render({ doc: docRef }),
    cmd: 'engine_render',
    args: { req: { doc: docRef } },
  },
  parseEdit: {
    call: (e) => e.parseEdit(req('pe')),
    cmd: 'engine_parse_edit',
    args: { req: req('pe') },
  },
  issue: { call: (e) => e.issue(req('is')), cmd: 'engine_issue', args: { req: req('is') } },
  redact: { call: (e) => e.redact(req('rd')), cmd: 'engine_redact', args: { req: req('rd') } },
  disclose: {
    call: (e) => e.disclose(req('dc')),
    cmd: 'engine_disclose',
    args: { req: req('dc') },
  },
  present: { call: (e) => e.present(req('pr')), cmd: 'engine_present', args: { req: req('pr') } },
  validate: {
    call: (e) => e.validate(req('va')),
    cmd: 'engine_validate',
    args: { req: req('va') },
  },
  lint: { call: (e) => e.lint(req('li')), cmd: 'engine_lint', args: { req: req('li') } },
  resign: { call: (e) => e.resign(req('rs')), cmd: 'engine_resign', args: { req: req('rs') } },
  tamper: { call: (e) => e.tamper(req('ta')), cmd: 'engine_tamper', args: { req: req('ta') } },
  reencode: {
    call: (e) => e.reencode(req('re')),
    cmd: 'engine_reencode',
    args: { req: req('re') },
  },
  editDisclosures: {
    call: (e) => e.editDisclosures(req('ed')),
    cmd: 'engine_edit_disclosures',
    args: { req: req('ed') },
  },
  decodeEmbedded: {
    call: (e) => e.decodeEmbedded(req('de')),
    cmd: 'engine_decode_embedded',
    args: { req: req('de') },
  },
  keyImport: {
    call: (e) => e.keyImport(req('ki')),
    cmd: 'engine_key_import',
    args: { req: req('ki') },
  },
  keyExport: {
    call: (e) => e.keyExport(req('ke')),
    cmd: 'engine_key_export',
    args: { req: req('ke') },
  },
  keyPublic: { call: (e) => e.keyPublic(keyRef), cmd: 'engine_key_public', args: { key: keyRef } },
  keyGenerate: {
    call: (e) => e.keyGenerate(req('kg')),
    cmd: 'engine_key_generate',
    args: { req: req('kg') },
  },
  keyThumbprint: {
    call: (e) => e.keyThumbprint(req('kt')),
    cmd: 'engine_key_thumbprint',
    args: { req: req('kt') },
  },
  keyAssignKid: {
    call: (e) => e.keyAssignKid(req('ka')),
    cmd: 'engine_key_assign_kid',
    args: { req: req('ka') },
  },
  keyToJwk: {
    call: (e) => e.keyToJwk(req('kj')),
    cmd: 'engine_key_to_jwk',
    args: { req: req('kj') },
  },
  keyToCwk: {
    call: (e) => e.keyToCwk(req('kc')),
    cmd: 'engine_key_to_cwk',
    args: { req: req('kc') },
  },
  datetime: {
    call: (e) => e.datetime(req('dt')),
    cmd: 'engine_datetime',
    args: { req: req('dt') },
  },
  registryLookup: {
    call: (e) => e.registryLookup({ kind: 'cwt_claim', prefix: 'c' }),
    cmd: 'engine_registry_lookup',
    args: { query: { kind: 'cwt_claim', prefix: 'c' } },
  },
  registryMerge: {
    call: (e) => e.registryMerge(req('rm')),
    cmd: 'engine_registry_merge',
    args: { req: req('rm') },
  },
};

describe('TauriEngine commands', () => {
  it('covers all 27 Engine methods', () => {
    expect(Object.keys(CASES)).toHaveLength(27);
  });

  it.each(Object.entries(CASES))('%s invokes its command', async (_name, c) => {
    respond[c.cmd] = () => ({ result: c.cmd });
    const result = await c.call(new TauriEngine());
    expect(engineCalls()).toEqual([{ cmd: c.cmd, args: c.args }]);
    expect(result).toEqual({ result: c.cmd });
  });
});

describe('raw input (#34 item 2)', () => {
  it('sends detect/open input as unpadded base64url', async () => {
    const e = new TauriEngine();
    await e.detect(new Uint8Array());
    await e.detect(Uint8Array.of(0xfb, 0xff));
    await e.open(hexToBytes('d28443a10126a0'), candidate, view);
    expect(engineCalls().map((c) => (c.args as { input: string }).input)).toEqual([
      '',
      '-_8',
      toB64u(hexToBytes('d28443a10126a0')),
    ]);
  });

  it('accepts a subarray view (only its bytes are sent)', async () => {
    const backing = Uint8Array.of(1, 2, 0xd2, 0x84, 3);
    await new TauriEngine().detect(backing.subarray(2, 4));
    expect(engineCalls()[0]?.args).toEqual({ input: '0oQ' });
  });
});

describe('engine_init (registry snapshot)', () => {
  it('runs once, first, with null when there is no snapshot', async () => {
    const e = new TauriEngine();
    expect(calls).toEqual([]); // not in the constructor
    await e.info();
    await e.detect(bytes);
    expect(calls.map((c) => c.cmd)).toEqual(['engine_init', 'engine_info', 'engine_detect']);
    expect(calls[0]?.args).toEqual({ snapshot: null });
  });

  it('sends the snapshot as base64url', async () => {
    const snapshot = Uint8Array.of(0x7b, 0x7d, 0xff);
    await new TauriEngine(snapshot).info();
    expect(calls[0]).toEqual({ cmd: 'engine_init', args: { snapshot: toB64u(snapshot) } });
  });

  it('runs once even for concurrent first calls', async () => {
    const e = new TauriEngine();
    await Promise.all([e.info(), e.detect(bytes), e.lint(req('x'))]);
    expect(calls.filter((c) => c.cmd === 'engine_init')).toHaveLength(1);
    expect(calls[0]?.cmd).toBe('engine_init');
  });

  it('a new TauriEngine re-inits (Update registries swaps the shell engine)', async () => {
    await new TauriEngine().info();
    await new TauriEngine(Uint8Array.of(1)).info();
    expect(calls.filter((c) => c.cmd === 'engine_init').map((c) => c.args)).toEqual([
      { snapshot: null },
      { snapshot: 'AQ' },
    ]);
  });

  it('an init failure rejects calls with EngineFailure and sends nothing else', async () => {
    const error: EngineError = { code: 'registry', message: 'bad snapshot', node_id: null };
    respond['engine_init'] = () => {
      throw error;
    };
    const e = new TauriEngine(Uint8Array.of(1));
    const failure = await e.info().catch((x: unknown) => x);
    expect(failure).toBeInstanceOf(EngineFailure);
    expect((failure as EngineFailure).error).toEqual(error);
    await expect(e.detect(bytes)).rejects.toBeInstanceOf(EngineFailure);
    expect(engineCalls()).toEqual([]);
  });
});

describe('errors', () => {
  it('wraps a core EngineError in EngineFailure, keeping code, message, node_id', async () => {
    const error: EngineError = {
      code: 'no_private_key',
      message: 'the key has no private part',
      node_id: 'payload/~e/cnf',
    };
    respond['engine_resign'] = () => {
      throw error;
    };
    const failure = await new TauriEngine().resign(req('r')).catch((x: unknown) => x);
    expect(failure).toBeInstanceOf(EngineFailure);
    expect((failure as EngineFailure).error).toEqual(error);
    expect((failure as EngineFailure).message).toBe('the key has no private part');
  });

  it('wraps a Tauri string rejection (bad args, missing command) as invalid_input', async () => {
    respond['engine_issue'] = () => {
      throw 'invalid args `req` for command `engine_issue`: missing field `claims`';
    };
    const failure = await new TauriEngine().issue(req('i')).catch((x: unknown) => x);
    expect(failure).toBeInstanceOf(EngineFailure);
    expect((failure as EngineFailure).error).toEqual({
      code: 'invalid_input',
      message: 'invalid args `req` for command `engine_issue`: missing field `claims`',
      node_id: null,
    });
  });

  it('wraps anything else as invalid_input with its text', async () => {
    respond['engine_info'] = () => {
      throw new Error('IPC down');
    };
    const failure = await new TauriEngine().info().catch((x: unknown) => x);
    expect(failure).toBeInstanceOf(EngineFailure);
    expect((failure as EngineFailure).error.code).toBe('invalid_input');
    expect((failure as EngineFailure).error.message).toContain('IPC down');
  });

  it('never rejects with a NotImplemented or raw value', async () => {
    respond['engine_lint'] = () => {
      throw { code: 'parse', message: 'x', node_id: null };
    };
    await expect(new TauriEngine().lint(req('l'))).rejects.toBeInstanceOf(EngineFailure);
  });
});
